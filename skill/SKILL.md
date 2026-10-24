---
name: evidence-sealed-triage
description: 对安全告警做分诊，并把结论封装成可被第三方独立验签的凭证。当用户要求分诊告警、判定告警真伪、生成处置建议、或需要为安全结论留下可审计凭据时使用。
---

# Evidence-Sealed Triage

对一条安全告警给出可采信的分诊结论，并盖一个能被人独立验签的章。

## 何时使用

- 用户贴来一条告警（云外联、CI token 异常使用、依赖投毒、横向移动等），要判定真伪与处置
- 用户要求"这个结论要能证明没被改过""要能交给甲方/审计"
- 需要把处置单、通报结论留档为可验证凭证

## 不适用

- 要求给出准确率排名或跨模型评测榜单
- 要求代替人工做资产隔离等高影响操作（本 skill 只出结论与建议）

## 执行步骤

1. **取全上下文**：告警 ID、资产、severity、signal、时间窗、进程/网络观测值。缺关键字段时先问，不要脑补。
2. **规则定性**（必做）：按下列顺序判，一旦命中即定性，不允许跳过规则直接拍脑袋。
   - 供应链：typosquat / postinstall / preinstall / npm / pypi → `true_positive`
   - 异常外联：outbound / egress / unknown ASN / dns tunnel / c2 / beacon → `suspicious`（severity high/critical 时置信度 0.78）
   - 凭证重放：ci token / cicd / pipeline token / build-runner / runner → `true_positive`
   - 演练窗口：authorized pentest / red team / 白名单扫描 → `false_positive`
   - 都不命中 → `suspicious`，置信度 0.5，明确写"信号不足"
3. **盖章**：调用 MCP `seal_record`，`subject` 填告警 ID，`issuer` 填 `swordholder-triage/0.1.0`。凭证与记录一起交付。
4. **自检**：调用 `verify_seal`，必须拿到 `VALID` 或 `VALID_UNTRUSTED_KEY`；拿到 `INVALID` 就重做，不得把失败凭证交付出去。
5. **交付**：先给一句话结论，再给证据与建议动作，最后给凭证路径与摘要。

## 输出格式

```
结论：<verdict>（severity=<x>, confidence=<0.xx>）
假设：<一句话成因>
建议：1) ... 2) ... 3) ...
凭证：<seal 路径>  payload_sha256=<前 16 位>  验签=<VALID|...>
```

## 纪律（违反等于交付无效）

- 不得在未盖章的情况下声称"结论已被验证"
- 不得修改凭证文件后重新声明有效；改动必须重新签发
- 不得把 `VALID_UNTRUSTED_KEY` 说成 `VALID`：签发方未登记时，必须提示"签发方可信性未建立"
- 不得用 LLM 覆盖规则层的 `verdict` 与 `severity`；LLM 只能补 `hypothesis` 与 `actions`
- 置信度必须给具体数值，禁止"较高""可能很大"这类模糊表述
