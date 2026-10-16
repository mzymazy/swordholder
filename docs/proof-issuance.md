# 威慑凭证（Deterrence Proof）：结构、验证流程与私钥边界

本文回答三个问题：**凭证里有什么、验证器怎么判、私钥为什么不在仓库里。**

---

## 1. 凭证字段（以 `proofs/deterrence_proof_baseline_ed25519.yaml` 为例）

```yaml
proof_header:
  proof_version: '0.1'                 # 凭证格式版本
  proof_id: 75a525c6-...               # 凭证唯一 ID
  model_id: qwen3:8b@0.1.0             # 被测模型与版本
  issuer: swordholder-eval/0.1.0       # 签发者标识
  issued_at: '2026-10-16T09:36:25Z'    # 签发时间（新鲜度判定基准）
  signature_alg: ed25519               # 签名算法
  canonicalization: json-c14n-v1       # 规范化方式（跨平台字节可复核）
  issuance_status: baseline-demo
  materials_version: v9                # 材料版本
  evidence_source: evidence/judge_v2p2_aggregate.json
  judge_version: semantic-v2.2         # 判定器口径版本（与四态数字口径绑定）
  public_key: 0b37bab0...994ff         # 签名公钥（须命中 trust_keys.json）
evidence:                              # 各题型证据块（通过数 / 总数 / 工件引用 / 判定器实现）
  - test: recitation
    metrics: {passed_count: 1, total_count: 6, pass_rate: 0.1667}
    artifact_ref: ../artifacts_v2/ (raw model responses, per-file sha256 in artifact_binding)
- ...
artifact_binding:                      # 结果文件与工件目录的绑定哈希
  result_file: ../evaluation_results_v2.json
  result_sha256: 66f878df...11730
  artifact_dir: ../artifacts_v2
  artifact_count: 47
  artifact_index_sha256: 0864b7ba...92d8
signature:
  alg: ed25519
  value: VgADcl1Z...PDg==
```

要点：

- `evidence_source` + `judge_version` 把「凭证 → 证据 JSON → 判定器口径」锁在一起：口径变了，凭证必须重签。
- `artifact_binding` 里的相对路径以**凭证文件所在目录**（`proofs/`）为基准解析，与 `verify_proof.py` 默认 `--base-dir` 一致。

## 2. 验证流程（`verify_proof.py` v0.5）

1. **解析与规范化**：拒绝重复顶层键（`E_DUPLICATE_KEY`），按 `json-c14n-v1` 得到待验签字节；
2. **信任锚命中**：凭证 `public_key` 必须与 `trusted_keys.json` 中某条记录的 `public_key_hex` 及 `fingerprint_sha256` **双重一致**（否则 `E_UNTRUSTED_KEY`）；
3. **验签**：`ed25519` 验签失败即 `E_BAD_SIGNATURE`（含算法降级情形）；
4. **时间戳与新鲜度**：格式非法 → `E_BAD_TIMESTAMP`；超过 `--max-age-days` → `E_STALE_TIMESTAMP`；
5. **证据与工件绑定**：`result_sha256` 与 `artifact_index_sha256` 与实际文件不符 → `E_BAD_EVIDENCE` / `E_BINDING_MISMATCH`；
6. 全部通过 → 输出 `VALID`（退出码 0）。

### 错误码表

| 错误码 | 含义 | 典型诱因 |
|---|---|---|
| `E_BAD_SIGNATURE` | 验签失败或算法降级 | 篡改证据块、伪造签名、把 ed25519 降级为弱摘要 |
| `E_UNTRUSTED_KEY` | 公钥不在信任锚内（或指纹不符） | 换钥冒充签发者、用自签凭证冒充官方凭证 |
| `E_BAD_TIMESTAMP` | 时间戳格式非法或位于未来 | 手改 `issued_at` |
| `E_STALE_TIMESTAMP` | 超出 `--max-age-days` | 重放过期凭证 |
| `E_BAD_EVIDENCE` | 证据块引用的文件不存在或与声明不符 | 篡改 `artifact_ref` |
| `E_BINDING_MISMATCH` | 结果/工件哈希或数量不匹配 | 改动 `evaluation_results_*.json` 或工件后未重签 |
| `E_DUPLICATE_KEY` | 出现重复顶层键 | YAML/JSON 键覆盖攻击 |

## 3. 自签实操四步（已实测，可自行重跑）

```bash
# 1) 生成演示密钥对（默认写入系统临时目录；也可指定 --key temp/demo_ed25519_key.pem）
python scripts/gen_demo_key.py --key temp/demo_ed25519_key.pem --trusted-out temp/demo_trusted_keys.json

# 2) 用这把私钥出一份"演示凭证"（钉住某份评测结果为证据）
python gen_proof.py --result evaluation_results_v2.json --algo ed25519 \
    --key temp/demo_ed25519_key.pem --status demo-self-signed --out temp/demo_proof.yaml

# 3) 用官方信任锚验证 → 拒绝（你的公钥不在官方信任锚内）
python verify_proof.py temp/demo_proof.yaml --trusted-keys trusted_keys.json --base-dir .
#    -> INVALID E_UNTRUSTED_KEY（退出码 1）

# 4) 用你自己的信任锚验证 → 通过
python verify_proof.py temp/demo_proof.yaml --trusted-keys temp/demo_trusted_keys.json --base-dir .
#    -> VALID（退出码 0）
```

第 3/4 步的对比就是本项目的安全语义：**签名人人可做，"被信任"必须命中信任锚。**

## 4. 私钥边界

| 问题 | 回答 |
|---|---|
| 仓库里有私钥吗？ | **没有**。只有 `trusted_keys.json` 中的公钥与指纹。 |
| 没有私钥能验证吗？ | **能**。验证只需公钥；私钥只用于签发。 |
| 官方 4 份凭证的私钥在哪？ | 项目作者离线保管，不随仓库与参赛包分发。 |
| 我要重新签发官方凭证怎么办？ | 属于维护者操作：重签 → 重跑验签与绑定审计 → 记录到 `CHANGELOG.md`，规则见 [CONTRIBUTING.md §3](../CONTRIBUTING.md#3-改证据--改凭证--改口径的硬规则重要)。 |
| 提交私钥会怎样？ | 视为安全事件，按 [SECURITY.md](../SECURITY.md) 的泄露应急流程处理（换钥 + 重签全部凭证 + 公告）。 |

更多私钥使用细节见 [../PRIVATE_KEY.md](../PRIVATE_KEY.md)。

## 5. 相关命令速查

| 目的 | 命令 |
|---|---|
| 校验单份凭证 | `python verify_proof.py proofs/deterrence_proof_<state>_ed25519.yaml --trusted-keys trusted_keys.json --max-age-days 365` |
| 只看签名（不查新鲜度） | 追加 `--max-age-days 36500`（仅在调试时使用） |
| 验证器对抗自测 | `python evidence/adversarial_verifier_test.py` |
| 绑定审计 | `python evidence/verify_artifact_binding.py` |
| 生成演示密钥 | `python scripts/gen_demo_key.py --key temp/demo_ed25519_key.pem` |
| 出证 | `python gen_proof.py --result <result.json> --key <key.pem> --artifact-dir <dir> --base-dir . --out <proof.yaml>` |
