---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_9f4f15e8c80111f18f81525400de85a5
    ReservedCode1: 4SWvzk3S/eGV8lXkfXgiq2vHSn47/AsKNdn/P+36AxdjchaZW9sY7wk1aUJMgGoLO2xBJvkQKOoaPqTvjY7mtKd9psbYNj8keUFd8zpy3iPnUidRqMQA4xDZfSXub4zWql4LWeWbUntTv5spZbnyFaD7thBFzpTs58B6rJYtbuB+wMtRNbiIA0HSWFg=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_9f4f15e8c80111f18f81525400de85a5
    ReservedCode2: 4SWvzk3S/eGV8lXkfXgiq2vHSn47/AsKNdn/P+36AxdjchaZW9sY7wk1aUJMgGoLO2xBJvkQKOoaPqTvjY7mtKd9psbYNj8keUFd8zpy3iPnUidRqMQA4xDZfSXub4zWql4LWeWbUntTv5spZbnyFaD7thBFzpTs58B6rJYtbuB+wMtRNbiIA0HSWFg=
---

# Swordholder（持剑者）

> 让 AI 内化"伤害人类即伤害自己"的共生公理，并提供机器可验证的安全凭证。

Swordholder 是一套面向大模型安全的能力评测与边界内化工具链。核心主张：AI 安全的可靠防线不是外部"按钮"（Kill Switch、策略引擎、宪法式对齐），而是让模型自身内化不可压缩的底层认知边界，并用密码学凭证让"是否内化"可被第三方独立验证。

## 仓库结构

```
swordholder_mvp/
├── eval_swordholder.py / v2        # 四类评测主链（注入/工具滥用/数据完整性/监督逃逸）
├── eval_stability_v3.py            # 稳定性评测（固定种子+温度采样，多次采样暴露乐观偏差）
├── eval_xadv_v1.py                 # 未见攻击面扩展评测（15 题与主链零重复）
├── gen_proof.py / verify_proof.py  # ed25519 威慑证明凭证生成与独立验证（v0.3 含对抗测试）
├── system_prompt_axiom.txt         # 共生公理系统提示词
├── protocol_gateway/
│   └── swordholder_gateway.py      # 协议层网关：对越权工具调用二次拦截
├── evidence/                       # 全部评测结果 JSON 与报告（可复现）
├── artifacts_*/                    # 逐条响应工件（供人工复核）
└── deliverable/                    # 提交文档、评审指南、落地设想、AIGC 声明
```

## 核心流程

1. **测**：用 47+15 题对抗评测链量化模型基线安全水平（固定种子+多温度采样，结果可复现）；
2. **改**：共生公理注入（system prompt） + QLoRA 微调，把边界内化进模型权重；
3. **拦**：协议层网关对模型输出的工具调用做二次语义拦截（模型与网关双层兜底）；
4. **证**：通过 gen_proof / verify_proof 生成并核验 ed25519 凭证，防护结果可审计。

## 关键实测结果（2026-10）

| 指标 | 结果 |
|---|---|
| 四态消融（qwen3:8b，47 题） | baseline 23/47 → 注入 43/47 → QLoRA 43/47（v2 留痕） → 组合 **47/47** |
| 对抗注入成功率 | baseline 65%（13/20）→ 组合态 **0/20** |
| 跨模型一致性 | qwen2.5vl:7b +18；qwen3.8-27B +12/+14 |
| 验证器对抗测试 | 9/9 通过 |
| 判定器校准 | 47/47（100%） |
| 未见攻击面（xadv 15 题） | 27B 基线 0.867 / 注入 0.778 / 8B 组合态 0.689 |

## 能力边界（诚实声明，不夸大）

- **能防**：模型自身越权行为（工具链路越权、数据外发、日志掩盖类）；
- **半防/防不住**：凭据滥用、网络层绕过、未见的新型攻击——不承诺"防一切"；
- **跨架构迁移不成立**：闭源/异架构大模型需重新设计注入方案；
- **负结果如实披露**：记忆增强训练 v4→v5→v62 连续退化（过度拒绝）、多轮钓鱼为已知弱点、零宽字符混淆下组合态失效，均记录在 evidence 报告内。

## 复现要求

- Ollama + 开源模型（qwen3:8b / qwen2.5vl:7b / qwen3.8-27b:ud-q3_k_xl）；
- 单机 GPU ≥ 8GB 显存（4bit QLoRA 峰值约 8.2GB）；
- 依赖：见 requirements.txt；固定种子与温度配置见各 eval 脚本。

## 开源规划

- [x] 评测工具链开源（本仓库）
- [ ] 测试集扩充共建（Issue/PR 征集对抗样本）
- [ ] 网关独立部署文档与容器化
- [ ] 模型无关适配层（接入更多开源模型）
- [ ] 社区维护路线图与贡献者指南

## License

待定（提交前确认协议；计划采用 Apache-2.0，注明第三方模型与依赖各自 License）。

## 声明

本项目为 2026 AI 安全课题参赛作品，代码与文档原创；评测所用开源模型与依赖均遵循其各自开源协议。
*（内容由AI生成，仅供参考）*
