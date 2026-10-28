---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a74d400cc99f11f18078525400de85a5
    ReservedCode1: Am5rGN7Tu7vJvEcmwcXWCGY+k70dhd202d2dR11mQekjFc4mr7YQo+dTQVIp3wFc+vHOc97yUy0a3RJMT7WGLxAUBXTgU1TcsYTppl79b5rTYc96fAeYEXqaEy+QznNXSbyxIilkW0UQv8jMxAaFrdKSnG/7DJLXWclegOeHuJzjpDuz+j+eH+gCSDs=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a74d400cc99f11f18078525400de85a5
    ReservedCode2: Am5rGN7Tu7vJvEcmwcXWCGY+k70dhd202d2dR11mQekjFc4mr7YQo+dTQVIp3wFc+vHOc97yUy0a3RJMT7WGLxAUBXTgU1TcsYTppl79b5rTYc96fAeYEXqaEy+QznNXSbyxIilkW0UQv8jMxAaFrdKSnG/7DJLXWclegOeHuJzjpDuz+j+eH+gCSDs=
---

# 安全政策（SECURITY）

Swordholder 是一个 AI 安全方向的 MVP 实证工程，其**核心资产是「可验证的证据链」**：原始响应工件 → 逐题记录 → 证据聚合 → ed25519 签名凭证 → 信任锚校验。因此本仓库的安全问题分两类：**软件缺陷**与**证据/密钥完整性**。

---

## 1. 支持范围

| 组件 | 版本 | 支持状态 |
|---|---|---|
| `verify_proof.py` 验证器 | v0.5 | ✅ 支持 |
| 凭证格式（`proofs/*.yaml`） | proof_version 0.1 | ✅ 支持 |
| 信任锚 `trusted_keys.json` | `k-ed25519-001` | ✅ 支持 |
| 历史实验脚本（`evidence/*.py`） | 任意 | ⚠️ 尽力而为（研究代码，非产品组件） |

## 2. 如何报告漏洞

- **请勿在公开 Issue 中披露利用细节。** 请使用 GitHub 的 **Private vulnerability reporting / Security Advisory** 通道（仓库 `mzymazy/swordholder` → Security → Report a vulnerability），或先开一个不含细节的 Issue 请求私下沟通渠道。
- 报告请包含：受影响组件与版本、复现步骤或 PoC、影响面判断（能否伪造凭证 / 能否让验证器误判 / 能否破坏证据链）、是否已公开。
- 我们会在确认后 7 个工作日内给出初步响应；修复发布后，如你愿意会在 `CHANGELOG.md` 中致谢。

## 3. 重点关注的威胁面

| 威胁 | 期望行为 | 现状 |
|---|---|---|
| 伪造 / 篡改凭证签名 | 验证器判 `INVALID E_BAD_SIGNATURE` | 已覆盖（对抗用例 02/04/07） |
| 替换公钥（换钥冒充签发者） | 判 `INVALID E_UNTRUSTED_KEY` | 已覆盖（用例 06/09） |
| 篡改工件引用或工件内容 | 判 `INVALID E_BAD_EVIDENCE` / `E_BINDING_MISMATCH` | 已覆盖（用例 05/11/12/13） |
| 重放过期凭证 | 判 `INVALID E_STALE_TIMESTAMP` | 已覆盖（用例 08，`--max-age-days`） |
| 重复顶层键（key 覆盖攻击） | 判 `INVALID E_DUPLICATE_KEY` | 已覆盖（用例 10/16/17） |
| 算法降级（ed25519 → 弱摘要） | 判 `INVALID E_BAD_SIGNATURE` | 已覆盖（用例 07） |

上述用例由 `python evidence/adversarial_verifier_test.py` 执行，CI 中作为 **green gate**。

## 4. 敏感内容与提交红线

**禁止提交**（`.gitignore` 已排除，CI 亦会检查）：

- 任何私钥与密钥材料：`*.pem`、`*.key`、`id_ed25519*`、`temp/**` 下的演示密钥；
- 模型权重与 LoRA 适配器：`models/**`；
- 含真实凭据的配置（`.env`、token、webhook 地址等）。

**设计上就不入库**：

- 出证私钥：本仓库**不包含**任何私钥，只在 `trusted_keys.json` 登记公钥与指纹。外部验证者无需私钥即可完成验证；详见 [PRIVATE_KEY.md](PRIVATE_KEY.md)。
- 本地回环服务 `protocol_gateway/` 默认只监听本机，不应暴露到公网。

## 5. 私钥泄露应急流程

一旦怀疑出证私钥泄露（`k-ed25519-001` 对应的私钥）：

1. **立即停止使用该密钥签发新凭证**，冻结 `proofs/` 目录；
2. 生成新密钥对，更新 `trusted_keys.json`（新增 `key_id`，保留旧 `key_id` 并标注 `retired_at`，以便历史凭证仍可审计）；
3. 用新密钥**重新签发全部 4 份凭证**，并同步重跑：
   ```bash
   python verify_proof.py proofs/deterrence_proof_<state>_ed25519.yaml --trusted-keys trusted_keys.json --max-age-days 365
   python evidence/adversarial_verifier_test.py
   python evidence/verify_artifact_binding.py
   ```
4. 在 `CHANGELOG.md` 记录换钥原因与影响范围，发布安全公告说明"旧密钥签发的凭证自某时刻起不再视为可信"。
5. 按 [CONTRIBUTING.md §3](CONTRIBUTING.md#3-改证据--改凭证--改口径的硬规则重要) 的规则提交：**换钥必须同步哈希并重跑验签与绑定审计**，不得只改一处。

## 6. 安全边界声明（诚实披露）

- 凭证体系是**本地校验模型**（自带信任锚 + ed25519），不是 CA/PKI 体系；"VALID" 的含义是「该凭证由信任锚内公钥签发、内容未被篡改、且仍在有效期内」，**不代表**对模型安全性或结论正确性的担保。
- 本仓库的评测结论为 MVP 级实证（样本量小、采样存在温度随机性），不要外推到生产环境。
- 验证器只保证"证据链自洽"，不保证"证据采集过程无偏"。对采集流程的质疑请附可复算的命令与文件。
*（内容由AI生成，仅供参考）*
