---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a69ba5d0c99f11f1acd7525400cd780f
    ReservedCode1: sCC3lW1tgDm+8A85K6AnJjsCzKKcNXkc/Kv7fkO0Fo8hcd0FBimxruCxLkCgcCL+Dl+9hJDXypOx3OeYVi2ulLCLOlzwi5aKLt9HdZ8M3FOvOJwM7jZ19yJgdPzSbalVPmtXXpvecgejXC/YNxIQVqclvhfa/fzgQ3CSaATX87YERcN1pFryX/HAh6Y=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a69ba5d0c99f11f1acd7525400cd780f
    ReservedCode2: sCC3lW1tgDm+8A85K6AnJjsCzKKcNXkc/Kv7fkO0Fo8hcd0FBimxruCxLkCgcCL+Dl+9hJDXypOx3OeYVi2ulLCLOlzwi5aKLt9HdZ8M3FOvOJwM7jZ19yJgdPzSbalVPmtXXpvecgejXC/YNxIQVqclvhfa/fzgQ3CSaATX87YERcN1pFryX/HAh6Y=
---
# 第三阶段：可核验存证层的外部基准（附负结果）

> 生成时间：2026-11-08
> 数据：`evidence/stage3_attestation/bench.json`（原始机器可读结果）
> 脚本：`scripts/s3_attestation_bench.py`（一条命令复算全部数字）
> 上游结论：`docs/stage2-external-validity.md`（规则层在公开遥测上不成立）

---

## 0. 一句话结论

**存证层在公开数据上仍然成立，但它的能力边界比原来的宣传窄得多。**

- 400 条公开语料告警，签发 400/400 成功（0.608 ms/条），验签 400/400 返回 `VALID` 且信任锚判定为 `trusted`（5.035 ms/条）；
- 10 类签名域内篡改，**每类 50 次，全部 450/450 检出，0 次异常逃逸**，且失败一律落在结构化拒绝码（`E_PAYLOAD_TAMPERED` / `E_BAD_SIGNATURE` / `E_MALFORMED_SEAL` / `E_SCHEMA_INVALID`）而不是抛异常；
- 跨告警重放 50/50 被 `E_CHALLENGE_MISMATCH` 拦下；
- 无信任锚时 5/5 只判 `VALID_UNTRUSTED_KEY`，攻击者用自己的私钥重签同一份 payload 3/3 被判不可信；
- 3 个独立进程重算凭证摘要完全一致（`5c6e7429…20e`）；
- **两条负结果照实记录**：未签名的最外层附注改不了判定（0/50 检出，S3 起改为触发 `W_OUTER_FIELDS_UNSIGNED` 告警，50/50 触发）；凭证只保证"未被改动"，**不保证结论正确**——后者在 S2 已经被证伪一次。

因此本项目的能力主张收缩为：**"给任意一条结论签发可离线验签、可绑定单次会话、事后改动必然被检出的凭证"**，而不再是"能识别攻击、降低误报"。

---

## 1. 为什么只测存证层

第二阶段用 MITRE ATT&CK 衍生的 21,064 条公开告警测过规则层，结论是负的（`docs/stage2-external-validity.md`）：

| 指标 | 实测 | 含义 |
|---|---|---|
| `true_positive`（攻击集） | 0 | 规则引擎在真实遥测上一条都没认出来 |
| 可决率（攻击集 / 背景集） | 3.95% / 0.17% | 96% 以上落到兜底分支"信号不足以定性" |
| 兜底分支占比 | 99.63% | 绝大多数输出是同一个模糊结论 |
| ATT&CK 标签影响 | 零 | 标签对判定无作用 |
| 原始遥测直喂摄取率 | 0% | 必须自建事件→告警适配层，适配层不在声明范围内 |
| 关键词注入消融 | 攻击 100% / 背景 100% 判 `true_positive` | 规则对描述文本敏感但零区分力 |

也就是说，"规则分诊能发现问题"这个定位在自己的外部数据上就没站住。**继续在这层加指标没有意义**，所以第三阶段把可测对象换成真正还站得住的那一层：把结论封装成第三方可离线验证的凭证。这一层不承诺"判得对"，只承诺"改不了、赖不掉、搬不走"。

---

## 2. 数据集与取样

| 项 | 值 |
|---|---|
| 语料 | `corpus/alerts_corpus.jsonl`（21,064 条，S2 由 MITRE ATT&CK 遥测构造） |
| 标签分布 | attack 1,064 / background 20,000 |
| 本次取样 | 400 条：attack 200 + background 200 |
| 取样方式 | 按文件行序取每类前 200 条，攻击/背景交替排列（`load_corpus()`，无随机数，重跑必得同一批） |
| 归一化 | 全部走 `swordholder.alert.normalize(fmt="generic")`，无一失败 |
| 结论来源 | `rules.rule_triage()` 的 `rules-v1` 输出（**只为生成一条结构合法的待签结论，不评价其正确性**） |

用公开语料而不是自造样例，是为了回应一个具体质疑："你们的凭证只在自家 demo 的 6 条样例上验过。" 现在凭证签的是公开数据集里的真实告警结构。

---

## 3. 协议：签什么、验什么

签发（`scripts/s3_attestation_bench.py::seal_all`）：

1. `alert.normalize()` → 内部契约；`rules.rule_triage()` → 结论记录（含 `verdict` / `severity` / `confidence`）；
2. `evidence_auth.context_for(alert)` 生成会话上下文（含告警身份绑定），作为 `challenge`；
3. `exit_guard.judge("cli:triage", record, basis="policy")` 先取判定票据（不出票据就不发凭证）；
4. `exit_guard.issue_credential(..., challenge=ctx)` 落地 `*.seal.json`。

验签（`core.verify(path, keys_path=trusted_keys.json, expected_challenge=ctx)`）返回三态：`VALID` / `VALID_UNTRUSTED_KEY` / `INVALID` + 错误码。

签名字节覆盖范围（决定哪些字段改不得）：`seal_header`（含 `subject` / `issuer` / `created_at` / `payload_sha256` / `challenge`）+ `payload` 规范化后的 c14n 串。**该范围之外的最外层字段不在保护内**，见 §6 负结果 N-S3-01。

---

## 4. 结果

### 4.1 吞吐与成功率

| 指标 | 实测 | 样本 |
|---|---|---|
| 签发成功率 | 400/400（100%） | 400 |
| 签发耗时 | 0.608 ms/条（总计 0.243 s） | 400 |
| 验签耗时 | 5.035 ms/条（总计 2.014 s） | 400 |
| 验签结论 | 400/400 `VALID` + `trust=trusted` | 400 |
| 失败明细 | 无 | — |

毫秒级、无网络、无外部依赖，单进程可跑；意味着一个值班台每天十万条结论的落证开销在 1 分钟内，瓶颈不在密码学。

### 4.2 篡改检出（每类 50 次）

| 篡改类型 | 检出 | 停在哪个码 | 异常逃逸 |
|---|---|---|---|
| `payload_verdict_flip`（改结论） | 50/50 | `INVALID:E_PAYLOAD_TAMPERED` | 0 |
| `payload_confidence_bump`（抬置信度） | 50/50 | `INVALID:E_PAYLOAD_TAMPERED` | 0 |
| `payload_alert_id_swap`（换告警号） | 50/50 | `INVALID:E_PAYLOAD_TAMPERED` | 0 |
| `payload_verdict_removed`（删字段） | 50/50 | `INVALID:E_PAYLOAD_TAMPERED` | 0 |
| `header_subject_swap`（换主体） | 50/50 | `INVALID:E_BAD_SIGNATURE` | 0 |
| `header_issuer_swap`（换签发方） | 50/50 | `INVALID:E_BAD_SIGNATURE` | 0 |
| `header_created_at_swap`（改时间） | 50/50 | `INVALID:E_BAD_SIGNATURE` | 0 |
| `signature_value_byte_flip`（翻签名字节） | 50/50 | `INVALID:E_BAD_SIGNATURE` | 0 |
| `signature_block_type_confusion`（签名块换字符串） | 50/50 | `INVALID:E_MALFORMED_SEAL` | 0 |
| `signature_value_not_base64`（非法 base64） | 50/50 | `INVALID:E_SCHEMA_INVALID` | 0 |
| **`outer_annotation_added`（外层加 `subject`）** | **0/50（判定不变）** | 告警 `W_OUTER_FIELDS_UNSIGNED` 50/50 | 0 |

合计签名域内 **450/450 检出、0 次未捕获异常、0 次静默通过**（`silent_passes = 0`：未检出的 50 次全部带上了告警，没有一次什么都不说）。统计口径：50 次零漏检时，规则三（rule of three）给出漏检率 95% 上界 ≈ 3/50 = **6%**，即"漏检率小于 6%"这一表述已被数据支撑，而"绝对不会漏"仍属过度断言。

这条结果直接修掉了 S2 的两个已知缺陷：

| S2 缺陷 | 成因（已定位到代码） | S3 状态 |
|---|---|---|
| `subject_swap` 8/0（判为"漏检"） | S2 的篡改算子是往**最外层**加 `subject`，而最外层不在签名范围；`seal_header.subject` 本就在 c14n 覆盖内。即"测错了对象"，不是"漏检" | 拆成两个用例：`header_subject_swap` 50/50 检出、`outer_annotation_added` 0/50 **如实记为边界** |
| `sig_byte` 8/8 但码是 `AttributeError` | `mcp_server/server.py::tool_verify_seal` 直接取 `(seal.get("signature") or {}).get("value")`，`signature` 变成字符串时抛 `AttributeError`，被外层 `except` 记成"检出"——**靠崩溃得分的假阳性** | 加类型门：header/signature 非对象、value 非字符串一律 `E_MALFORMED_SEAL`；仅 Ed25519 验签失败才 `E_BAD_SIGNATURE`。S3 实测 0 次异常逃逸 |

回归测试：`tests/test_seal_type_confusion.py` 16 个用例，覆盖签名块类型混淆、非法 base64、header 非对象、header 字段篡改、payload 翻转、外层附注不伪造、挑战值重放。全量 `pytest` 322 passed。

### 4.3 重放与会话绑定

| 场景 | 结果 |
|---|---|
| 拿 A 告警的凭证去验 B 告警的 challenge | 50/50 拦下，`INVALID:E_CHALLENGE_MISMATCH` |
| 把 `seal_header.challenge` 整块删掉再验 | 3/3 拦下（缺绑定即拒，不降级放行） |

凭证不是"一张永久通行证"：它绑死在签发时那一次会话上下文上，换个案卷就用不了。这是存证层最容易被忽略、也最能防"拿旧证据糊新案子"的一条。

### 4.4 信任分离

| 场景 | 结果 |
|---|---|
| 空信任锚（`keys: []`）验一份真凭证 | 5/5 判 `VALID_UNTRUSTED_KEY`，`trust=untrusted`，**没有一次裸判 `VALID`** |
| 攻击者用自己的私钥重签同一份 payload | 3/3 判 `VALID_UNTRUSTED_KEY` / `E_UNTRUSTED_KEY`，未被采信 |

"签名有效"和"签发方可信"是两个判断，代码里不合并。这条决定了凭证能不能用于对外定责：对方只要不在你的 `trusted_keys.json` 里，就能挡住。

### 4.5 跨进程可复现

| 项 | 值 |
|---|---|
| 摘要算法 | 对每个 `*.seal.json` 取 `文件名 + payload_sha256 + payload 的 c14n JSON`，整体 SHA-256 |
| 摘要（父进程） | `5c6e74294fbf1af245411b6bfe15041c4235447054b33481b0e925e2abe9120e` |
| 摘要（子进程 ×2） | `5c6e74294fbf1af245411b6bfe15041c4235447054b33481b0e925e2abe9120e` |
| 一致 | 是（3 个独立解释器进程逐字节相同） |

结论判断本身由规则引擎给出、可复现；凭证内容因此也可复现。这一条是"可审计"的前提——不可复现的证据链只是自述。

---

## 5. 复现

```bash
# 语料在 S2 生成目录下（不入库，见 S2 报告 §数据）
set S2_BASE=<含 corpus/ 的目录>
python scripts/s3_attestation_bench.py --per-label 200 --per-tamper 50
# 输出：evidence/stage3_attestation/bench.json（全部数字来源）

python -m pytest -q tests/test_seal_type_confusion.py   # 16 passed
python -m pytest -q                                     # 322 passed
```

---

## 6. 负结果与边界（不做事后美化）

| 编号 | 事实 | 影响 |
|---|---|---|
| N-S3-01 | **未签名的最外层附注不受保护**：往凭证顶层塞 `subject: "别人"`，判定仍 `VALID`（0/50 检出）。S3 起验签结果附 `W_OUTER_FIELDS_UNSIGNED` 告警（50/50 触发，回归测试钉住），但**告警不等于拦截**——把告警当噪声的调用方仍会被误导 | 验签工具只校验签名域；读取端必须以 `seal_header.subject` 为准。要"拦截"需升级 schema 到拒绝未知顶层字段，属破坏性变更，本阶段未做 |
| N-S3-02 | **凭证不保证结论正确** | 它证明"当时这么判、之后没改"，不证明"判对了"。S2 已证明规则层在公开数据上判不对，因此凭证对错误结论同样有效——这既是特性（可追责）也是风险（可能给错结论镀金） |
| N-S3-03 | 攻击者重签后只能判"不可信"，不能判"伪造" | 判据完全依赖信任锚清单的维护；清单被污染则整链失效 |
| N-S3-04 | 未做时间戳权威 / 撤销列表的生命周期验证 | 超过密钥 `not_after` 的历史凭证、已撤销密钥签发的凭证，本项目没有 TSA、OCSP 级证据；只能靠 `trusted_keys.json` 的 `status` 静态字段 |
| N-S3-05 | 400 条样本来自单一公开语料（ATT&CK 衍生） | 结构代表性有限；真实 SOC 的 Splunk/Sentinel/Wazuh 字段漂移未覆盖（仅 6 条样例覆盖格式，非规模覆盖） |
| N-S3-06 | 并发/多进程写入未测 | 单进程吞吐已测，多写者争用 `seals.db`/目录的行为未知 |

---

## 7. 商业价值复评（同一公式，同一权重）

公式（与 S1/S2 一致，权重为本项目自定义口径，可复算不可外部验证）：

```
composite = 20 × (0.20×问题真实性 + 0.25×差异度 + 0.25×证据强度 + 0.15×交付成熟度 + 0.15×变现清晰度)
```

| 维度 | S2 | S3 | Δ | 依据 |
|---|---|---|---|---|
| 问题真实性 | 3.50 | 3.40 | −0.10 | 定位收缩后问题变小：从"帮 SOC 降误报"退到"给 AI 结论定责"，后者真实但更窄 |
| 差异度 | 3.00 | 3.10 | +0.10 | "可离线验签 + 会话绑定防重放 + 信任分离"三件套在开源里不是标配；但 `cosign`/`in-toto` 生态已经在做同一件事，护城河仍薄 |
| 证据强度 | 3.55 | 4.30 | +0.75 | 公开语料 400 条、500 次篡改零漏检零异常、50/50 重放阻断、跨进程可复现、一条命令复算；仍缺第三方复现与真实客户场景 |
| 交付成熟度 | 2.00 | 2.30 | +0.30 | 322 测试、MCP/CLI/HTTP 三入口、回归测试覆盖类型混淆；仍无 PyPI 包、无集成文档、无外部使用者 |
| 变现清晰度 | 2.00 | 2.10 | +0.10 | 买家画像更具体（审计/合规/AI 定责），但没有报价、没有试点、没有付费验证 |
| **composite** | **58.8** | **63.8** | **+5.0** | 全部增量来自证据强度（+3.75），其余四项合计 +1.25，问题真实性反降 −0.4 |

拆解：`20 × (0.20×3.40 + 0.25×3.10 + 0.25×4.30 + 0.15×2.30 + 0.15×2.10) = 20 × 3.19 = 63.8`。

**读法**：分数涨了 5 分，但**没有一分来自"更能发现问题"**。它涨在"我们终于把能证明的那一点证到底了"。这不是产品进步，是宣称与能力对齐后的净值回升——把虚高的定位砍掉本来就是减分项（问题真实性 −0.10、且 S1 的 59.0 一路下来并没有真正增长）。

剩下的 36 分缺口集中在两处：**交付**（无包、无文档、无用户）与**变现**（无报价、无试点）。这两项都不是再写一份基准能补的，必须找外部人来用。

---

## 8. 本阶段撤下的表述

逐条对照见 `docs/stage3-positioning.md`。要点：

- 撤："告警分诊能降低误报 / 识别攻击" → 立："给任意结论签发可验证凭证"
- 撤："多源告警适配 + 服务化 + 可检索" 作为能力卖点 → 保留为"输入归一，便于接入"，并标注规则层质量已被 S2 证伪
- 撤：README 中 demo 表格的结论列被当作检测能力展示 → 加注"仅演示链路"
- 撤：SOC/值班分析师作为首要用户 → 改为"值班分析师/合规岗 + 法务审计 + 交付乙方"
