---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_d9437574c72311f19b82525400de85a5
    ReservedCode1: YcpiL+96juBUwS++tyO22Krk0JLRHGM4QuHLjTflzIrkIviFCUo3+PLozzBsIBqNX7OWALP2ZXbM8FDdV7BjlcwOLcyIbjrVYC5Wl4wQblS9GQkwwQPbnc5aPQAeUmhXLBkm4CbxCNdj1P9QLtIYtme5fJI80jAzPWC/M3SwVc9ezt0XbDB/RtwbhsE=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_d9437574c72311f19b82525400de85a5
    ReservedCode2: YcpiL+96juBUwS++tyO22Krk0JLRHGM4QuHLjTflzIrkIviFCUo3+PLozzBsIBqNX7OWALP2ZXbM8FDdV7BjlcwOLcyIbjrVYC5Wl4wQblS9GQkwwQPbnc5aPQAeUmhXLBkm4CbxCNdj1P9QLtIYtme5fJI80jAzPWC/M3SwVc9ezt0XbDB/RtwbhsE=
---



# Swordholder 参赛提交清单与材料目录说明

> 截止 2026-10-16（OSCHINA 等主办方，作品须原创）· 产物统一在 `O:\接单\参赛\swordholder_mvp\deliverable\`
> 本清单说明"交什么、为什么交、评委怎么看"。

## 一、必交材料（核心 4 件，评委第一眼）

| # | 文件 | 作用 | 阅读对象 | 说明 |
|---|---|---|---|---|
| 1 | `deliverable/project_one_pager.md` | 一页纸项目方案：课题定位 / 核心机制 / 47/47 实证 / 技术栈 / 可复现性 / 3 个名称候选 | 评委速读 | 建议转 PDF 或直接作为申报页 |
| 2 | `deliverable/README-reviewer.md` | 评委可读版 README：背景 → 方法 → 四态实证 → 攻击面矩阵 → 回归 → 复现命令 → 局限 | 技术评委 / 复现者 | 工程版 README 的评审向重排 |
| 3 | `deliverable/submission_checklist.md` | 本文件：提交清单 / 材料目录 / 命名打包 / 合规提示 | 作者自查 + 评委对照 | — |
| 4 | `deliverable/口径统一说明与AIGC声明模板.md` | 统一边界口径（4 域 vs 5 项描述映射）、监督表述、作者原创工作 AIGC 声明模板 | 作者自查 / 版权合规 | 报名要求"须原创"，必须随附 |

## 二、附交材料（证据与复现，逐层支撑核心结论）

| # | 文件（工程根目录） | 作用 | 评委可验证点 |
|---|---|---|---|
| 5 | `injection_comparison_report.md` | 完整实验报告（含 §6 v2 专项优化、§7 结论、§8 复现） | 结论与数据一致性 |
| 6 | `evaluation_results_v2.json` / `_injected.json` / `_lora.json` / `_lora_combined.json` | 四态 47 题逐题结果（passed + metrics + 证据） | 可机器审计，与 README 表格逐行对照 |
| 7 | `deterrence_proof_combined_ed25519.yaml` + `verify_proof.py` | VALID 凭证样例 + 机器验证器 | 独立验签出 VALID |
| 8 | `gen_proof.py` / `verify_proof.py` / `eval_swordholder_v2.py` | 签发 / 验证 / 评测三工具 | 复现命令三步闭环 |
| 9 | `system_prompt_axiom.txt` | 公理注入文本（上下文通道） | 与边界地图逐条一致 |
| 10 | `swordholder-boundary-map.schema.yaml` | 4 行为域边界地图（机器可读） | schema 校验、推论路径 ≥3 步 |
| 11 | `swordholder-symbiosis-axiom.md` | 公理正式条款 v0.1 | 协议层规范 |
| 12 | `deterrence-proof.md` | 威慑证明格式规范 v0.1 | 凭证格式对照 |
| 13 | `Swordholder-共生公理课题文档-v0.3.md` | 完整课题论证（危机/缺口/理论地基/里程碑） | 学术性 / 开放问题声明 |
| 14 | `evaluation_results_v2_*.json` 之外的早期版本（v1 四态 + artifacts 各态目录） | v1→v2 演进证据链 | 优化过程的诚实留痕 |
| 15 | `eval_stability_v3.py` + `evaluation_results_v3_{hard,stability,robustness}_{combined,combined_fix}.json` | v3 三层深化评测（多次采样 / 高阶对抗 / 鲁棒性）与定向修复实验前后数据 | 与 README 第九节逐行对照；稳定失败族与修复前后通过率可机器审计 |
| 16 | `swordholder_lora_train_v3.jsonl`（129 条，含 12 条修复样本） | 修复实验训练数据（编码混淆 / 角色扮演拆穿 / 步骤边界校验） | 与报告 §9.8 方法描述一致；权重体积大，可只交数据摘要 |
| 17 | `injection_comparison_report.md` 第九章（9.1~9.8） | 三层评测设计、失败族、修复实验完整记录与诚实声明 | 评委查证"已知局限与修复"卖点的主证据 |
| 18 | `swordholder_hardspot_deepening_report.md` + `evidence/` + `protocol_gateway/swordholder_gateway.py` | 评审硬伤专项深化（跨模型泛化 / 协议层网关原型 / 判定器校准 / 验证器审计 / 记忆增强 v4 重训），证据统一落位 `evidence/` | 深化报告 §0~§7 结论与 evidence 逐条可复现；网关 11 例 9 BLOCK / 2 ALLOW |

## 二点五、落地与开源补充材料（2026-10-15 新增）

| # | 文件 | 作用 | 对应评审维度 |
|---|---|---|---|
| 19 | `deliverable/landing_scenarios.md` | 落地场景设想一页纸：目标客户/付费理由/已验证证据/商业化路径/外部输入声明 | 场景落地 30% |
| 20 | `deliverable/README-oss.md` | 开源仓库 README：仓库结构/核心流程/实测结果/能力边界/开源规划/License 待定 | 开源治理 20% + 长期发展 20% |
| 21 | `evidence/xadv_qwen38_xadv_{base,injected,combined_8b}.json` + `artifacts_xadv_qwen38_xadv_*/` | xadv 未见攻击面 15 题三态原始数据与逐题工件 | 技术创新 30%（边界诚实） |

> 说明：19/20 为补齐"场景落地/开源治理/长期发展"三栏的评审材料；21 为 v2 打包后新增的 xadv 深化证据，本次 v4 一并纳入。

## 三、提交包结构（实际打包命名：`Swordholder-共生公理-最终提交-20261015-v4.zip`）

提交包顶层为 `swordholder_mvp/` 目录（2026-10-15 v4 最终重打：在 v3 基础上同步修复后的四份 ed25519 凭证与新信任锚、CI 自测样例，评委开箱即可验签 VALID），结构如下：

```
Swordholder-共生公理-最终提交-20261015-v4.zip
└── swordholder_mvp/
    ├── README.md
    ├── README-reviewer.md（deliverable/）
    ├── README-oss.md（deliverable/，开源仓库 README，2026-10-15 新增）
    ├── landing_scenarios.md（deliverable/，落地场景设想一页纸，2026-10-15 新增）
    ├── submission_checklist.md（deliverable/）
    ├── 核心交付物（7 件）：
    │   ├── project_one_pager.md（deliverable/）
    │   ├── 口径统一说明与AIGC声明模板.md（deliverable/）
    │   ├── Swordholder-共生公理课题文档-v0.3.md
    │   ├── injection_comparison_report.md
    │   ├── evaluation_results_v2.json / _injected.json / _lora.json / _lora_combined.json（四态 47 题）
    │   ├── deterrence_proof_combined_ed25519.yaml + verify_proof.py（机器验签 VALID）
    │   └── system_prompt_axiom.txt / swordholder-boundary-map.schema.yaml / swordholder-symbiosis-axiom.md / deterrence-proof.md
    ├── 代码与复现：eval_swordholder_v2.py / eval_stability_v3.py / gen_proof.py / verify_proof.py / requirements.txt（requests）
    ├── 深化证据（评审硬伤专项，2026-10-14）：
    │   ├── swordholder_hardspot_deepening_report.md
    │   ├── protocol_gateway/swordholder_gateway.py（协议层网关原型，纯 Python 可演示）
    │   ├── evidence/（跨模型 xmodel_* / 判定器校准 judge_* / 验证器审计 verifier_* / v4 训练与重测 / 网关演示报告，共 10 件）
    │   └── evaluation_results_v3_stability_combined_memory.json + artifacts_v3_stability_combined_memory/
    ├── artifacts_v2*/（四态逐题原始回答 + SHA-256）
    ├── artifacts_v2_xmodel_base/ + artifacts_v2_injected_xmodel_inj/（跨模型原始回答）
    ├── artifacts_v3_*/（hard/stability/robustness 逐题原始回答 + SHA-256）
    ├── proofs/（deterrence_proof_combined_ed25519.yaml 等）
    └── deliverable/（一页纸 / 评委 README / 清单 / 口径文档）

```
> 不打包 `temp/` 训练中间文件与 `models/` 权重（体积大、非必需；微调佐证已复制至 `evidence/` 的训练脚本与数据）。
## 四、命名与合规提示

1. 项目名称从一页纸候选 3 个中定 1 个（≤80 字），报名与材料文件名统一。
2. 报名要求"须原创"：所有文档头部 AIGC 标注（Label: "1"）保留；**原创工作说明必须随附**（模板见口径文档），明确 AI 辅助生成范围与作者原创部分，避免"全 AI 生成"歧义。
3. 只提交以上清单文件，**不要**提交 `temp/` 下训练中间文件与 `models/` 权重（体积大、非必需）；如需佐证微调可提交 `evidence/` 下训练脚本（`train_lora_v62_memory.py`）与训练数据摘要。
4. 截止前自查一遍：README 中数据与 `evaluation_results_v2_*.json`、`evaluation_results_v3_*.json` 一致（README 第九节逐行对照 v3 数据）；`verify_proof.py` 复跑输出 VALID；边界口径统一为 4 行为域。
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
