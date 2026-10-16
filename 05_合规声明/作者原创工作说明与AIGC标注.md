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

# 作者原创工作说明与 AIGC 标注声明

项目名称：Swordholder 共生公理（参赛用名，已定名，见 `deliverable/project_one_pager.md` 第 5 节）
作者：马梓尧
日期：2026-10-16

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

复现命令与预期输出见 README-reviewer.md 第七节（含 `--max-age-days 365`）；
四态评测 JSON（判定器 semantic-v2.2 逐题重判：baseline 30/47、injected 43/47、
lora 41/47、combined 45/47）、凭证 YAML（v9 整改版重新签发）、验证器 v0.5
输出（VALID）均随包提交，评委可在本地独立核验。
