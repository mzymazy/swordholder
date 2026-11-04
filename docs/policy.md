# 判定策略层（Policy Layer）

> 一句话：**内核不含领域知识，判定规则写在 YAML 里。**

0.4.0 及之前，"什么结论算合法、判误报需要什么凭据"这些规则是硬编码在 `agent_loop.py:guardrail()` 里的。
这在单一场景下能跑，但有两个问题：

1. 换个场景（比如对外发信审批）就得改内核代码，改的是被判定的那个程序本身；
2. 规则散落在 Python 分支里，安全评审只能读代码猜意图，没法逐条对照、没法版本化。

0.5.0 把这些规则抽成声明式策略包，内核退化成"按文件执行校验"的执行器。

## 1. 结构

一份策略包是一个 YAML 文件，`schema: swordholder/policy/v1`，六个必需段：

| 段 | 作用 |
| --- | --- |
| `schema` / `id` / `version` | 身份与版本，会写进每份凭证的 `agent.policy` 字段 |
| `verdicts` / `severities` | 判定枚举白名单。取值不在这里面 → 拒收 |
| `limits` | 结构性阈值：最少取证步数、处置动作条数与长度上下限、结论长度上限 |
| `invariants` | 不变量：某个判定取值下的附加前置条件，命中即拒收 |

可选段：`confidence_text_map`（模型把 confidence 写成文字时的换算口径）、`title`、`description`。

内置两份：

- `default-soc-triage.yaml` —— SOC 告警分诊，等价于 0.4.0 的硬编码规则（回归测试保证等价）；
- `email-outbound-approval.yaml` —— 对外发信审批，证明**换场景不改内核**。

## 2. 不变量怎么写

不变量是策略层唯一的"闸门"，长这样：

```yaml
invariants:
  - id: I1
    title: 判误报必须给出经工具核实的授权单号
    when:
      verdict: false_positive       # 命中这个判定取值时生效
    require: tool_verified_ref      # 要满足什么
    field: authorization_ref        # 拿哪个字段去满足
    source: tickets                 # 去哪查
    mismatch_field: ticket_id
    messages:
      missing: "false_positive 必须给出 {field}"
```

内核只认 `require` 的类型，不认业务含义。目前支持两种：

| require | 语义 |
| --- | --- |
| `tool_verified_ref` | 字段值必须出现在某工具的真实返回里（`facts[source]` 中 `mismatch_field` 命中） |
| `window_covers_alert` | 该字段指向的记录，其 `window` 必须覆盖告警发生时刻 |

写别的类型 → 加载期直接报错。这是刻意的：**策略包是可被外部编辑的输入，不能让它在运行时决定执行什么代码**。

## 3. 加载与失败处理

```
--policy 参数  >  $SWORDHOLDER_POLICY  >  swordholder/policy/default-soc-triage.yaml
```

任何一步失败都 **fail-closed**：

- 文件不存在、YAML 语法错、schema 不匹配、缺必需字段、`require` 类型不支持 → `PolicyError`；
- `guardrail()` 拿不到策略 → 一律拒收（理由里写明"策略包不可用"）；
- `run_agent()` 拿不到策略 → 不调用模型、不产出判定，`fallback_reason` 记 `policy-error:*`，落到规则层。

**读不到策略就放行**是这类系统最典型的事故形态，所以这里不给自己留例外。

## 4. 命令行

```bash
swordholder policy list                    # 内置策略包 + 当前生效项
swordholder policy show                    # 判定枚举 / 阈值 / 不变量
swordholder policy show --json             # 给程序读
swordholder policy check my-policy.yaml    # 改完先本地校验
swordholder agent alert.json --policy my-policy.yaml
```

`policy show` 的输出就是安全评审要看的全部内容——不需要读 Python。

## 5. 改策略的流程

规则外置之后，改 YAML 等于改系统行为，所以它不能是"随手改"：

1. 改 `swordholder/policy/*.yaml`；
2. `swordholder policy check` 过语法；
3. **`python scripts/regress_policy.py`** 跑判据案例库（见 `cases/README.md`）——该放行的放行、该拒收的拒收，一条不对就不许合入；
4. 如果某条案例的期望本来就该变，先改 `why` 说清为什么，再改 `expect`，然后 `--update-manifest` 重新固化；
5. 策略变更和判据变更一起提交，让 review 同时看到两件事。

第 3 步已接进 CI（`tests/test_regress_gate.py`），本地 `pytest` 一跑门禁就生效。

## 6. 追溯

每份凭证的 `agent` 段会记：

```json
"policy": {"id": "soc-alert-triage", "version": 1},
"guardrail_invariants": ["I1:判误报必须给出经工具核实的授权单号", "I2:..."]
```

配合 ed25519 签名，事后能回答"这条结论当时是按哪一版规则判的"。
这是策略外置真正的意义：**规则可改，但改了什么、什么时候改的、影响哪些结论，都留得住。**

## 7. 边界（诚实说明）

- 策略层管的是**结论的合法性**，不管取证质量——模型可以合法地取两步无信息量的证。
  取证有效性属于评测与案例库要盯的事，不在本层解决。
- 不变量目前只支持两种 `require`，复杂条件（如"授权单必须由特定审批人签"）要新增类型并改内核。
  这是有意保守：宁可加类型走代码评审，也不做成可执行表达式。
- `confidence` 的数值是否合理（0.99 是否吹牛）不在本层校验，属于校准问题。

---

相关：`docs/architecture.md`（整体架构）、`cases/README.md`（判据案例库）、`swordholder/policy_loader.py`（加载器实现）。
