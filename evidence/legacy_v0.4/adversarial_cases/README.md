# adversarial_cases（v0.4 时代对抗用例载体 · 历史留痕）

本目录为验证器 **v0.4 时代**的对抗用例 YAML 载体（9 个文件，编号 01/02/04~10），
配套当时的自测脚本 `../adversarial_verifier_test_v0.4.py`（10 用例）。

**已归档，不参与 v9 权威口径，也不被 CI 引用。** 原因：v0.5 起验证器新增
artifact_binding 强制校验、严格时间戳正则与未来时间拒绝、构造层完整重复键检测、
json-c14n-v1 跨环境稳定规范化，v0.4 载体（无 binding 块，"过期"以"签名钥不在锚"等价替代）
已无法表达其原始语义。v9 自测改为在 `evidence/adversarial_verifier_test.py` 中
于临时目录内**内联构造 17 个用例**（使用独立测试信任锚），结果落盘
`evidence/adversarial_verifier_test_v05.json`（17/17 通过）。
