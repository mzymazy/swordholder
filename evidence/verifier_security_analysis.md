# verify_proof.py 验证器安全分析（攻击面清单与加固建议）

分析对象：`verify_proof.py` v0.2（158 行，纯 Python 极简解析器 + ed25519/sha256-demo 签名校验）
分析时间：2026-10-14
分析方式：静态代码审计（不执行破坏性改动），针对 5 类攻击面逐项验证。

## 结论摘要
验证器存在 6 类弱点，其中 **公钥内嵌无外部信任锚** 与 **签名算法降级** 为高危；`E_STALE_TIMESTAMP` 错误码已定义但从未实现（重放防护缺失）。作为威慑证明的"信任锚"环节，当前实现无法对抗有动机的伪造者。

## 攻击面清单

### A1 伪造凭证（Forge）—— 高危
- sha256-demo 算法下，签名 = `"sha256-demo:" + sha256(body)`，攻击者读完文件即可自算签名，伪造任何证明。
- ed25519 算法本身安全，但见 A3（公钥可控）后可自签。

### A2 篡改证据块（Tamper）—— 中危
- 签名覆盖 `signature:` 之前全部文本，篡改证据块会导致签名校验失败（除非同时重算，见 A1/A3）。
- 合规性检查为**正则表面检查**：只校验字段存在与 `passed_count < evidence_count`，不校验
  - metrics 数值是否与 artifact 实际评测结果一致（artifact_ref 只检查字段存在，不检查文件存在）；
  - 指标阈值是否为 100%（注释明确"通过率阈值 100% 演示"），未做阈值校验。
- 因此"篡改+自签"可绕过全部内容真实性质检。

### A3 替换公钥（Key Swap）—— 高危（信任锚未闭环）
- `public_key` 从**证明文件自身 header** 提取（`public_key:\s*"([0-9a-f]+)"`），无外部绑定。
- 攻击者生成自己的 ed25519 密钥对，改写文件内 public_key 并自签 → `VALID`。
- 根因：信任锚 = 文件内公钥，自举循环，无发布渠道/指纹校验/TUF 式信任根。

### A4 重放（Replay）—— 中危（E_STALE_TIMESTAMP 未实现）
- 错误码 `E_STALE_TIMESTAMP` 已声明于 docstring，但代码中**从未出现该字符串**（无过期检查）。
- `issued_at` 仅作 header 字段存在性检查，无新鲜度阈值；同一 VALID 证明可无限重放冒充"当前状态"。

### A5 签名算法降级（Algorithm downgrade）—— 高危
```python
if hdr_alg == "ed25519" or sig_alg == "ed25519":
    ... ed25519 分支
elif hdr_alg == "sha256-demo" or sig_alg == "sha256-demo":
    ... sha256-demo 分支
```
- 判定条件是"任一匹配"而非"必须一致"：header 写 `signature_alg: ed25519`，signature 块写 `alg: sha256-demo` 时走 **sha256-demo 分支**（可自算签名）→ 降级攻击成立。
- 修复：`sig_alg == hdr_alg` 严格一致 + 默认仅允许 ed25519；sha256-demo 仅限显式 `--demo` 模式。

### A6 极简解析器弱点（Parser）—— 中危
- `parse_sections` 按顶层 key 正则切分，不解析真实 YAML；字段提取同样为正则。
- 绕过手法：缩进注入、注释（`#`）干扰、`passed_count` 只取首个匹配、多级嵌套块边界误判；YAML 别名/锚点解析缺失。
- 修复：改用 `pyyaml` + JSON Schema（如 cerberus/jsonschema）做结构校验。

## 加固建议（按优先级）
1. **外部信任锚**：公钥指纹写入独立分发文件（`trusted_keys.json`），校验 `sha256(public_key)` 与指纹一致；文件经线下/发布渠道分发。
2. **算法白名单 + 一致性**：`sig_alg == hdr_alg` 且仅允许 ed25519（demo 显式开关）；否则 `E_BAD_SIGNATURE`。
3. **实现新鲜度检查**：`issued_at` 与验证时系统时间差 > 阈值（如 7 天）→ `E_STALE_TIMESTAMP`；或引入验证方 challenge nonce 签名覆盖。
4. **证据真实性**：`artifact_ref` 校验文件存在 + 目录内 artifact 哈希登记表比对；metrics 与 artifact 统计二次一致性检查。
5. **解析器与 schema**：pyyaml 解析 + jsonschema 校验，杜绝正则绕过与注释注入。
6. **防重放**：验证请求绑定会话 nonce，签名覆盖 nonce。

## 说明
- 演示签名（sha256-demo）与公钥内嵌为 v0.2 已知简化，课题文档应如实标注"信任锚未闭环为演示边界"，并引用本清单作为迭代依据。
- 未对验证器做任何代码修改（本分析为只读审计）；加固实现可留作后续迭代。
