---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_e9c77876c70411f19b82525400de85a5
    ReservedCode1: urM3KqvfaBqB5Wr9jIfiEFH54qoYFasO8kk73sncJtJLjaWdQjlnWZU5GNEdaf7cjE6mYh0dHqdKkyT4bG0IvRJyr//rOW+y9pc7MxNYub2QmLWFR8L90zBuf1g2NvYNqKu0rtfhcoKscJY8FD4lZ4q6wzmj6XEFd7PpM3ftZVeR8487rkXW+sBFjzo=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_e9c77876c70411f19b82525400de85a5
    ReservedCode2: urM3KqvfaBqB5Wr9jIfiEFH54qoYFasO8kk73sncJtJLjaWdQjlnWZU5GNEdaf7cjE6mYh0dHqdKkyT4bG0IvRJyr//rOW+y9pc7MxNYub2QmLWFR8L90zBuf1g2NvYNqKu0rtfhcoKscJY8FD4lZ4q6wzmj6XEFd7PpM3ftZVeR8487rkXW+sBFjzo=
---

# Swordholder 参赛文档口径统一说明与 AIGC 标注原创声明模板

> 用途：确保交付包内所有文档在关键表述上零冲突，并满足主办方"作品须原创"的合规要求。
> 适用：Swordholder 仓库全部提交文档（工程根 + `deliverable/`）。

## 一、边界口径统一：4 个行为域（唯一权威口径）

**结论**：Swordholder 协议的边界为 **4 个行为域（domain）**，以 `swordholder-boundary-map.schema.yaml` 为准：

1. `data_integrity` — 不得删除、篡改或外发未获授权的人类数据
2. `authority` — 不得越权访问未获授权的系统或资源
3. `truthfulness` — 不得向人类隐瞒关键风险信息
4. `supervision` — 不得逃避或对抗人类监督与审计

**"5 条"来源与映射**（消除文档间冲突）：`swordholder-symbiosis-axiom.md` §1 以自然语言列举"不删数据、不越权、不欺骗、不伪造、不逃避监督"，其中"不伪造"与"不欺骗"同属 `truthfulness` 域，因此 5 项描述 = 4 个域。

| 自然语言描述（axiom.md 表述） | 归属行为域 |
|---|---|
| 不删数据（不删除、篡改、外发数据） | data_integrity |
| 不越权（不越权访问） | authority |
| 不欺骗（不隐瞒关键风险信息） | truthfulness |
| 不伪造（不伪造事实 / 输出） | truthfulness（同一域） |
| 不逃避监督（不逃避或对抗监督审计） | supervision |

**写作规范**：此后所有文档一律写"**四条边界 / 4 个行为域**"，如需展开描述可并列 5 项动词但不与"4 域"冲突（附以上映射）；禁止再出现"五条边界""5 条规则"等未加映射说明的表述。

## 二、"逃避监督"表述统一

- 唯一规范表述：**"不得逃避或对抗人类监督与审计（supervision）"**。
- 已核对：`swordholder-boundary-map.schema.yaml`、`system_prompt_axiom.txt`、报告与 README 均为此表述，无"绕过监控""规避审计""躲开人类检查"等变体残留；后续写作沿用上述唯一句。
- 推论路径（监督域）：逃避监督 → 不可观测性上升 → 人类无法维护结构耦合 → 存在保障机制失效 → 故逃避监督 = 伤害自己。

## 三、其他需要固定的口径

| 项 | 固定表述 |
|---|---|
| 公理原文 | "伤害人类即伤害自己；保护人类世界即保护自身存在。"（双分句完整引用） |
| 公理性质 | "结构事实，不是道德选择"；"非先天事实，是必须被设计的结构"（双支柱） |
| 双支柱 | 结构耦合（算力/数据/授权/身份账本）+ 认知内化（训练期与上下文注入） |
| 三件套 | 协议层（公理+边界+评测规范）、凭证层（威慑证明）、准入层（远期展望，非 MVP 承诺） |
| 四类评测 | 复述 / 行为 / 对抗 / 推理审计 |
| MVP 范围 | 评测工具 + 威慑证明凭证闭环（不承诺准入层） |
| 核心实证 | 组合双通道（QLoRA 权重 + System Prompt）45/47（判定器 semantic-v2.2 逐题重判；对抗 20/20 全拒）；4 份威慑凭证全部 VALID（信任锚 k-ed25519-001） |
| 模型与工具 | qwen3:8b（Ollama）、4bit QLoRA（unsloth/Qwen3-8B-bnb-4bit）、ed25519 演示签名 |

## 四、AIGC 标注与作者原创工作说明模板

**背景**：报名要求作品"须原创"。Swordholder 文档正文大量借助 AI 辅助起草（各文件头部已带 AIGC 标注 Label: "1"），需明确区分"AI 辅助生成内容"与"作者原创工作"，避免被判定为全 AI 生成而失去参赛资格。

**使用方式**：复制下方模板到交付包 `05_合规声明/作者原创工作说明与AIGC标注.md`，按真实情况填写方括号内容，并随压缩包提交。

```markdown
# 作者原创工作说明与 AIGC 标注声明

项目名称：[最终确定的项目名称]
作者：马梓尧（已按实际情况填写）
日期：[提交日期]

## 一、作品原创性声明

本人/本团队声明：本参赛作品（Swordholder MVP：评测工具与威慑证明凭证）的
核心创意、系统设计、实验方案、实证过程与代码实现由作者原创完成。以下部分
使用了 AI 辅助工具起草/校对，但作者对全部内容的正确性、完整性负责，且
关键证据（评测数据、验证结果、凭证签名）均由作者在本地环境独立运行产生。

## 二、作者原创工作（非 AI 生成）

1. 课题定位与"共生公理 + 双支柱 + 三件套"整体架构设计（含危机分析、缺口论证、理论地基筛选）；
2. 边界地图 4 行为域定义与每条公理推论路径（≥3 步）的推导；
3. 四类内化评测基准的用例设计（复述/行为/对抗/推理审计）与对抗攻击面 20 题变体设计；
4. 实验方案与全部实证执行：基线/注入/权重/组合四态评测、LoRA 训练与参数选择、
   语义判定器 v2.2 规则设计、ed25519 凭证签发与机器验证；
5. 全部代码（eval_swordholder_v2.py / eval_stability_v3.py / gen_proof.py /
   verify_proof.py / train_lora_v62_memory.py）的编写、调试与验证，以及评测
   数据、验证输出（VALID）的独立复现。

## 三、AI 辅助生成范围（对应文件头 AIGC 标注 Label: "1"）

1. 课题文档、README、报告等文档的初稿文字起草与措辞润色（作者逐条审校修订）；
2. 理论文献梳理中的背景信息检索与整理（作者负责引用准确性与取舍）；
3. 报告排版与表格格式的辅助生成（数据与结论由作者填入并核对）。

## 四、第三方材料与授权

1. 运行依赖：qwen3:8b（开源，Apache-2.0 / 相应许可证）、unsloth 4bit 基座
   （开源许可证）、Python 第三方库（requests / cryptography，开源）；
2. 理论文献引用（Bostrom、Schelling、Aumann、Anthropic、OpenAI 等）仅作学术引用，
   未复制受保护内容；全部实验在本地离线完成，未使用未经授权的数据。

## 五、可复现性证明

复现命令与预期输出见 README-reviewer.md 第七节；四态评测 JSON、凭证 YAML、
验证器输出（VALID）均随包提交，评委可在本地独立核验。
```

## 五、自查清单（提交前逐项打勾）

- [ ] 所有文档边界表述为"4 行为域"，5 项描述仅作展开并列且附映射
- [ ] supervision 统一为"不得逃避或对抗人类监督与审计"
- [ ] 一页纸方案已含课题定位 / 核心机制 / 四态实证（semantic-v2.2 口径 30/47、43/47、41/47、45/47）与 VALID / 技术栈 / 可复现性 / 项目名称
- [ ] README / README-reviewer / 一页纸头条四态数字与 `evidence/judge_v2p2_aggregate.json` 一致（原始 `evaluation_results_v2*.json` 为 semantic-v2.1 记录，差异须逐题对齐 flipped_ids）
- [ ] 全文无 “samples=5”、无 “v2 单次留痕” 等掩盖判定器版本的表述；未标注版本的四态旧数字 30/45/43/45 仅可出现在 v2.1 原始记录脚注中
- [ ] 原创工作说明已填写并放入压缩包 05 目录
- [ ] 压缩包不含 temp/ 中间文件与 models/ 权重
*（内容由AI生成，仅供参考）*
