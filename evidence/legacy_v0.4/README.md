# legacy_v0.4 —— 验证器 v0.4 时代资产（历史留痕，不参与 v9 权威口径）

本目录保存验证器 `verify_proof.py` 升级至 **v0.5** 之前的资产，仅作历史留痕与版本对比，
**不参与 v9 提交口径**，也不被 CI 引用：

| 文件/目录 | 说明 |
|---|---|
| `adversarial_verifier_test_v0.4.py` | v0.4 时代对抗自测脚本（10 用例） |
| `adversarial_verifier_test_v04.json` | v0.4 时代自测结果（10/10 通过） |
| `adversarial_cases/` | v0.4 时代对抗用例 YAML 载体（9 个文件） |

**为何归档**：v0.5 起新增 **artifact_binding 强制校验**（result_file 字节哈希 + artifact 目录文件数 +
逐文件哈希清单）、**严格时间戳正则 + 未来时间拒绝**、**构造层完整重复键检测**（含引号键、流式映射）与
**跨环境稳定规范化**（json-c14n-v1）。因此 v0.4 时代的 YAML 载体（缺少 binding 块、"
过期"以"签名钥不在锚"等价替代）在 v0.5 下不再能表达其原始语义，自测改为在脚本
`evidence/adversarial_verifier_test.py` 中于临时目录内**内联构造全部 17 个用例**，
并使用**独立测试信任锚**（不污染仓库主 `trusted_keys.json`）。

**当前权威口径**（CI 断言对象）：
- 验证器：`verify_proof.py` v0.5
- 自测：`evidence/adversarial_verifier_test.py` → `evidence/adversarial_verifier_test_v05.json`（**17/17 通过**）
- 正式凭证：`proofs/deterrence_proof_*_ed25519.yaml`（4 份，期望全部 VALID）
