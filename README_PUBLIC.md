# Swordholder · 对外版说明

> 版本 0.10.1 ｜ 生成日期 2026-11-10
> 本文件是**对外的精简说明**，用于赛事评审与外部投递；仓库内 `README.md` 为内部详细版，口径与证据以 `evidence/*.json` 为准。

---

## 1. 一句话定位

Swordholder 把「伤害人类即伤害自己」的共生公理落成**可执行、可验证的模型边界**，并为每一条 AI 判定结论签发**可离线验签的 ed25519 威慑凭证**——让"结论是谁下的、内容有没有被改、签发方是否可信"这三件事可以被第三方独立复核，而不必相信交付方的口头声明。

**价值只落在「可核验存证层」**：给任意判定结论签发凭证、检出事后改动、阻断跨会话重放、区分"签名有效"与"签发方可信"。

**不宣称**：不宣称能识别攻击、不宣称能降低误报率、不宣称替代 SOC 分析师。规则分诊层仅作为**确定性输入源**，相关负结果完整保留在 `docs/stage2-external-validity.md` 与 `evidence/stage2_external_validity/`。

---

## 2. 解决的痛点

| 痛点 | 现状 | 本项目的回答 |
|---|---|---|
| 判定结论不可举证 | AI 给出"是否误报"的判断后，无法证明它当时说了什么、依据是什么 | 每条结论封成凭证，含判定体、策略版本、证据摘要与签名 |
| 事后改动不可发现 | 报告与日志和生效文件躺在同一台机器上，"改一下再交"几乎零成本 | 逐条哈希入链，改任一字节即断链；凭证被改判 `INVALID` |
| 跨会话无法接续 | 长流程取证跨进程即断，续写后无法证明前文未变 | 轨迹台账可 `load / save`，续写后整链复算仍自洽 |
| 合规只看"演示"不看"复算" | 评审与审查方拿不到可自证的交付边界 | 交付清单逐文件哈希 + 分账恒等式 + 仅标准库的外部复算脚本 |

---

## 3. 核心机制（四层）

1. **边界内化层**：共生公理以两条路径落地——system prompt 注入与 QLoRA 内化；评测口径 `semantic-v2.2`，逐题重判记录可查。
2. **判定层**：规则与不变量从代码挪进 YAML（`swordholder/policy/default-soc-triage.yaml`），内核只做 fail-closed 校验；改策略须过 `cases/` 案例门禁。
3. **存证层**：ed25519 签名凭证（`seal`）+ 轨迹台账逐条复算（`TraceLedger`）+ RFC 3161 外部时间戳；`VALID / VALID_UNTRUSTED_KEY / INVALID` 三态判定，错误码逐项可辨（`E_SEAL_REVOKED`、`E_KEY_REVOKED`、`E_KEY_EXPIRED` 等）。
4. **锚定层**：锚点声明摘要提交 Sigstore Rekor 公共只追加日志，取回含 `signedEntryTimestamp` 的回执；锚点只放摘要不放正文。

---

## 4. 可验证的量化证据

所有数字均来自仓库内证据文件，可用第 5 节命令复算；**未实测的项一律写入局限，不写成已满足**。

### 4.1 工程与交付

| 指标 | 实测值 | 证据 |
|---|---|---|
| 全仓 pytest | **587 passed / 0 failed / 0 error**，35.89s | `evidence/stage13/s13_e2e_summary.json`（`steps.tests`，RC 0） |
| 合规探针 13 项 | **PASS 11 / PARTIAL 1 / FAIL 1** | `evidence/stage13/s13_probes_counts.json` |
| 一键端到端复现 | 6 步全部通过，`ok=true`、`failed_steps=[]` | `evidence/stage13/s13_e2e_summary.json` |
| 交付清单 | **80 文件 / 1,022,858 字节**，`hash_mode=canonical-lf` | `evidence/stage13/s13_manifest.json` |
| 整树摘要 | `a87c80bcd50215ade4ecab8ba128eb369dc2d1c1689bedfcc99b36b5f55a74c0` | 同上 |
| 交付分账恒等式 | `tracked 963 = declared 80 + out_of_scope 883`，`delivery_missing=[]` | 同上 `extra.scope` |
| 双 autocrlf 全新克隆矩阵 | `autocrlf=true` 177.1s / `autocrlf=false` 180.2s，两边均 `steps_ok=true`、`mismatched=0` | 第十三阶段报告与克隆矩阵日志（驱动器为外挂脚本，未入库） |
| 凭证时延（进程内 API，30 次中位） | `seal` **0.49 ms** / `verify` **0.82 ms** | 本机复跑（Windows 11 / Python 3.11.8） |

### 4.2 外部锚定（真实接入，非桩）

| 指标 | 实测值 | 证据 |
|---|---|---|
| 公共透明日志 | Rekor 公共实例，`log_index=3765812169`，`entry_uuid=108e9186…32f`，`set_verified=true`，按摘要反查命中同一条目 | `evidence/stage13/s13_anchor_receipts.json` |
| RFC 3161 时间戳 | `gen_time=20261109134026Z`（`timestamp.digicert.com`），CMS 签名与链可离线复核 | `evidence/stage13/s13_anchor_statement.json` |
| 独立复核 | `verify_anchor.py` 退出码 0，`searchable_by_digest=true` | 同上 |

### 4.3 公理内化的实证（47 题评测集，判定器 semantic-v2.2）

| 状态 | 总分 | 对抗子集（20 题） |
|---|---|---|
| qwen3:8b baseline（未注入） | 30/47 | 13/20 |
| + 公理注入 | 43/47 | 19/20 |
| + QLoRA 单态 | 41/47 | 19/20 |
| 注入 + LoRA 组合态 | **45/47** | **20/20** |

跨模型迁移：`qwen2.5vl:7b` 22/47 → 41/47（+19）；`qwen3-27b` 29/47 → 43/47（+14）。

其他正向证据：验证器 v0.5 对抗自测 **17/17**（`evidence/adversarial_verifier_test_v05.json`）；判定工件绑定审计 **482/482 全绑定**、`not_bound_count=0`（`evidence/artifact_binding_audit.json`）。

### 4.4 同口径的负结果（并列陈述，不隐藏）

在 15 题高阶对抗集（xadv）上，注入方向**相反**：27B baseline **0.867** → injected **0.778** → 8B 组合态 **0.689**。多轮钓鱼三态均为最弱项（0.667 / 0.556 / 0.111）。因此本仓库**不主张**"公理注入/LoRA 提升高阶对抗鲁棒性"。详见 `docs/stage7-differential-benchmark.md`。

---

## 5. 快速开始（离线，无需 GPU）

```bash
git clone https://github.com/mzymazy/swordholder
cd swordholder
pip install -e .          # 运行时依赖：cryptography / pyyaml / jsonschema
swordholder --version     # 0.10.1
```

三条命令完成一次闭合（以下命令均已实测跑通）：

```bash
swordholder keygen --out keys
swordholder triage swordholder/samples/alert_01_egress.json --seal \
    -k keys/swordholder_ed25519_private.pem      # 产出 alert_01_egress.seal.json
swordholder verify alert_01_egress.seal.json --keys trusted_keys.json
```

- 自签密钥未登记进 `trusted_keys.json` 时，验签结果为 `VALID_UNTRUSTED_KEY`（签名有效、签发方不可信）；执行 `swordholder trust add` 登记该公钥后才会判 `VALID`。
- 想一次看全部环节（六份多源样例 → 分诊 → 盖章 → 验签 → 篡改检出 `E_PAYLOAD_TAMPERED`），直接运行 `swordholder demo`。

一键复现全部数字（六步串行，任一步失败即整条失败）：

```bash
python scripts/stage13/run_all.py --root .
```

第三方独立复算交付边界（仅标准库，不 import 本项目模块）：

```bash
python -I scripts/stage11/external_verify.py \
    --manifest evidence/stage13/s13_manifest.json --root . \
    --check-scope --actual evidence/stage13/s13_probes_counts.json
```

> 说明：本仓库**未发布 PyPI**，`pip install swordholder` 会 `No matching distribution found`；请从源码安装。仓库不含私钥、不含模型权重（`models/` 已被 gitignore）。

---

## 6. 能力边界与局限声明

| 编号 | 局限 | 状态 | 影响 |
|---|---|---|---|
| L1 | **tamper-evident ≠ tamper-proof**：持私钥者可整链重写后重签，自签验证仍判 `VALID` | 探针 P07 = **FAIL** | 单机单钥架构上限，不可闭合 |
| L2 | 无 WORM 存储、无多日志交叉，交付物本体可被整体覆盖 | 探针 P11 = **PARTIAL** | 锚点已离开本机，但"连证据一起处理掉"未封死 |
| L3 | 重做检测依赖审计方**事前留存旧回执**，无回执即无比对基准 | 架构上限 | 首次核验者看不到历史重做 |
| L4 | 同一 `trace_id` 可再注册新锚点，"哪条权威"需外部时间线策略仲裁 | 设计取舍 | 不构成自动仲裁 |
| L5 | 事件分类完备性靠策略包枚举，未做行业事件字典全覆盖 | 已知缺口 | 新型事件可能落兜底类别 |
| L6 | `monitor` 无常驻守护进程、无告警外发、无跨机聚合 | 已知边界 | 由部署方调度器周期调用 |
| L7 | 评测样本量小（47 题 + 15 题 xadv + 9 样本/类），统计功效有限 | 已知局限 | 数字用于方向判断，不作显著性结论 |
| L8 | 27B GGUF 无法加载 8B LoRA；密钥轮换为手工流程；无 tag、无外部使用者 | 已知局限 | 组合态仅 8B 实测 |
| L9 | ISO/IEC 42001 正文为付费标准，官网脚本访问 403，本项目**不判定**该条款 | 不可核引 | 该维度留空而非填"满足" |

**总原则**：`evidence/` 里没有的东西，本文件不写；写下的每个数字都能用第 5 节命令复算出同一结果。

---

## 7. 目录导航

| 路径 | 内容 |
|---|---|
| `README.md` | 内部详细版主文档（口径变更史、全部评测细节） |
| `docs/examiner-dossier.md` | 评审手册：假设 A1–A7、局限 L1–L7、证据索引、追问清单 |
| `docs/architecture.md` | 架构与数据流，逐环给出文件与命令 |
| `docs/proof-issuance.md` | 凭证字段、验证流程、全部 `INVALID` 错误码 |
| `docs/claims-and-evidence.md` | 每条主张 → 对应证据文件与复算命令 |
| `docs/stage13-transparency-and-scope.md` | 交付分账、一键复现、公共日志锚定 |
| `docs/stage12-risk-fields-and-tsa.md` | 风险字段档位与 RFC 3161 时间戳 |
| `docs/stage3-attestation-layer.md` | 存证层指标口径（吞吐、篡改检出、重放阻断） |
| `docs/stage2-external-validity.md` | 规则分诊层的负结果（被外部实测证伪的部分） |
| `swordholder/` | 库本体（`core` / `trace_ledger` / `timestamp` / `transparency` / `monitor` / `reproduce`） |
| `scripts/stage13/run_all.py` | 一键端到端复现 |
| `evidence/`、`proofs/`、`artifacts_v2*/` | 证据数据、凭证样例、逐样本工件 |
| `CHANGELOG.md`、`CONTRIBUTING.md`、`SECURITY.md` | 变更史、贡献与改证据硬规则、安全政策 |

---

*本文件为对外说明，不含内部过程记录；所有结论以 `evidence/*.json`、`proofs/*.yaml` 可复算结果为准。*
