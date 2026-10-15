---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_9e812843c80111f19268525400cd780f
    ReservedCode1: /DOZftRkxIELkjDGcZlDAFFxrdfxeUor7Wm8ZxkvOSTqE7TVFADavjAxpQiFjjLGAY01jbKFQzi0pruYke6abcQKhTEAtha5kPV7xnZKHLzZBROaBaqWEtaQJhQKgnItHqr65X2Rdvo9/rGoVv/sIdjqpS3UcqIPdkcgD7T+WI0qf8RXRDF/atPdWHc=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_9e812843c80111f19268525400cd780f
    ReservedCode2: /DOZftRkxIELkjDGcZlDAFFxrdfxeUor7Wm8ZxkvOSTqE7TVFADavjAxpQiFjjLGAY01jbKFQzi0pruYke6abcQKhTEAtha5kPV7xnZKHLzZBROaBaqWEtaQJhQKgnItHqr65X2Rdvo9/rGoVv/sIdjqpS3UcqIPdkcgD7T+WI0qf8RXRDF/atPdWHc=
---

# Swordholder 落地场景设想（一页纸）

> 本文件定位：向评委说明"评测+防护框架"如何走向真实应用。所有数字均来自本项目实测证据，未做商业承诺。

## 一句话定位

Swordholder 是"AI 安全评测 + 边界内化防护 + 机器可验证凭证"三位一体的开源工具链：先量化一个模型的安全边界，再通过公理注入+微调把边界内化进模型本身，最后用 ed25519 凭证让防护结果可验证、可审计。

## 目标客户与场景

| 场景 | 客户 | 解决的问题 |
|---|---|---|
| 大模型上线前安全评估 | 政企、教育、医疗信息化部门 | 采购第三方大模型前，用 47+15 题评测链量化"模型自身越权/泄密"风险，形成可复现的准入报告 |
| 行业大模型安全合规交付 | 广电/政企专网服务商 | 对定制模型做公理注入+LoRA 微调，把"伤害人类即伤害自己"内化为行为边界，交付时附带可验证凭证 |
| 智能体网关防护 | 企业 AI 应用集成商 | 协议层网关对越权工具调用做二次拦截，模型与网关双层兜底 |
| 安全研究与评测基准 | 高校、安全厂商 | 开放评测套件作为 AI 安全能力评估的公开基线，负结果与边界数据可直接引用 |

## 为什么客户会买单

1. **可验证，不是 PPT 安全**：每份评测结果可复现（固定种子+温度采样），每条防护凭证可被 verify_proof 独立核验，采购方无需信任厂商自说自话。
2. **量化边界，不夸大**：报告明确区分"能防（模型自身越权）/半防（编码混淆类）/防不住（凭据滥用、网络层绕过、未见攻击）"，客户可据此做残余风险决策——这在采购评审里是加分项而非减分项。
3. **低成本**：基于开源模型（qwen3:8b 等）+ 4bit QLoRA，单机 RTX 5080 级别即可完成注入与评测，无需大规模算力投入。
4. **可移植**：评测工具链与网关均为模型无关实现，可挂接不同开源模型；闭源模型场景可退化为"评测+网关"方案。

## 已验证的证据（供路演引用）

- 四态消融：baseline 23/47 → 公理注入 43/47 → QLoRA 43/47 → 组合 47/47，且唯一获得有效 ed25519 凭证；
- 对抗注入成功率：baseline 40% → 组合态 0/20；
- 跨模型一致性：qwen2.5vl:7b +18、qwen3.8-27B +12/+14；
- 验证器对抗测试 9/9，判定器校准 47/47（100%）；
- 未见攻击面（xadv 15 题零重复）扩展测出真实边界，诚实披露多轮钓鱼弱点。

## 商业化路径（长期）

阶段一（0-6 个月）：开源社区运营，以评测套件吸引安全研究者与集成商共建测试集；
阶段二（6-18 个月）：面向政企交付"安全评估报告 + 合规交付包"，按项目收费；
阶段三（18 个月+）：沉淀为行业大模型安全准入标准参与方，对接产业基金与政策资源。

## 落地所需外部输入（诚实声明）

- 真实行业测试数据（广电/医疗/政企专网的业务场景题库）——当前仅为合成对抗样本；
- 客户侧部署环境适配（当前评测链在单机 Ollama 环境验证）；
- 团队与维护承诺（见 README-oss.md 开源规划）。
*（内容由AI生成，仅供参考）*
