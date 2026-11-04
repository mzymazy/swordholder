# 判据案例库（cases/）

这里放的是**人工确认过的判定基线**：什么样的结论该放行、什么样的结论必须拒收、拒收时该说哪句话。

它存在的理由很简单——判定规则已经从代码挪进了 `swordholder/policy/*.yaml`（见 `docs/policy.md`）。
规则外置之后，改一份 YAML 就等于改系统行为，所以必须有一批"人签字认过的案例"来当门禁：
改完策略跑一遍，该过的过、该拒的拒，一条不对就不许合入。

## 一条案例长什么样

```yaml
id: C-002
title: 判误报但拿不出授权单：必须拒收
why: 模型最常见的偷懒——一句"看着像演练"就想结案。没有可核实的授权单就不许下误报结论。
policy: default-soc-triage.yaml     # 该案例预期的策略包
signed_by: 马梓尧                    # 人工确认人
signed_at: '2026-11-04'
input:
  decision: { ... }                 # 模型提交的原始结论
  executed_steps: 2                 # 之前成功取证了几步
  facts: { ... }                    # 工具侧事实（授权单等）
  alert_ts: '2026-10-20T10:00:00Z'  # 告警发生时刻
expect:
  ok: false                         # 期望：拒收
  reason_contains: authorization_ref # 拒收理由里必须出现这个词
```

`why` 不是装饰——它写的是"为什么这条边界值得守"。没有它，后面的人只会看到一堆 YAML 字段，不知道删掉会发生什么。

## 当前 6 条基线

| 案例 | 守的是什么 |
| --- | --- |
| C-001 | 授权单可核实、时间窗覆盖 → 误报**应当放行**（防止策略越改越严，最后什么都拒） |
| C-002 | 判误报但拿不出授权单 → **拒收** |
| C-003 | 授权单存在但时间窗不覆盖告警时刻 → **拒收** |
| C-004 | 取证步数低于 `limits.min_ok_steps` → **拒收** |
| C-005 | 把自家处置动作当证据引用 → **拒收** |
| C-006 | 判定取值不在策略白名单 → **拒收** |

C-001 是这批案例里最容易被忽略、却最重要的一条：**只守拒收不守放行，策略会一路收紧到不可用**。

## 怎么跑

```bash
python scripts/regress_policy.py                                   # 用当前生效策略
python scripts/regress_policy.py --policy swordholder/policy/email-outbound-approval.yaml
```

退出码：`0` 全过；`1` 有案例不符合期望（策略不能合入）；`2` 案例库被改动或用法错误。

## 改了策略怎么办

1. 先本地跑 `python scripts/regress_policy.py` 看影响面；
2. 如果某条案例的期望**本来就该变**（例如业务上允许了新的处置形态），改 `expect` 之前先把 `why` 改成能说服人的理由；
3. 跑 `python scripts/regress_policy.py --update-manifest` 重新固化 digest；
4. 和策略 YAML 一起提交，让 review 同时看到"规则变了"和"判据变了"。

## 完整性

`manifest.json` 存了每条案例的 sha256。案例被改动而 manifest 没更新，门禁直接红灯（退出码 2），
避免"顺手把不听话的案例改掉"这种事悄悄发生。

这条链路由 `tests/test_regress_gate.py` 接进 CI：`pytest` 一跑，门禁就自动生效。
