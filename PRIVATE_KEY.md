# 关于出证私钥：本仓库不含任何私钥（PRIVATE_KEY.md）

**结论先说**：本仓库**不包含、不需要、也不应该包含**出证私钥。仓库只登记**公钥与指纹**（`trusted_keys.json`），任何人都可以只用公钥完成凭证验证。

| 资产 | 在仓库里吗 | 位置 / 替代方案 |
|---|---|---|
| 公钥 + 指纹（信任锚） | ✅ 是 | [`trusted_keys.json`](trusted_keys.json) → `k-ed25519-001` |
| 出证私钥（ed25519 private key） | ❌ 否 | 仅签发者本机持有，离线保管 |
| 演示/自签密钥 | ❌ 否 | 需要时用 [`scripts/gen_demo_key.py`](scripts/gen_demo_key.py) 在你**本机**生成 |

## 1. 为什么私钥不入库

- 私钥一旦入库即等于**任何人都能签发"合法"凭证**，威慑凭证的可验证性立刻归零；
- 本仓库的验证语义是「凭证由信任锚内公钥签发 → 判 `VALID`」。公钥足以验证，私钥只用于签发，二者职责不重叠；
- 因此 `*.pem` / `*.key` / `id_ed25519*` / `temp/**` 下的演示密钥都已列入 `.gitignore`，[CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md) 也把"提交私钥"列为红线。

## 2. 只想验证？不需要私钥

```bash
python verify_proof.py proofs/deterrence_proof_baseline_ed25519.yaml \
    --trusted-keys trusted_keys.json --max-age-days 365
# -> [verify_proof v0.5] deterrence_proof_baseline_ed25519.yaml -> VALID
```

4 份凭证逐一替换文件名即可（baseline / injected / lora / combined），预期全部 `VALID`。

## 3. 想要自己的密钥？在本机生成（3 步实测可跑）

```bash
# 1) 生成演示密钥对（默认写到系统临时目录，不会进仓库）
python scripts/gen_demo_key.py --key temp/demo_ed25519_key.pem --trusted-out temp/demo_trusted_keys.json

# 2) 用这把私钥给一份评测结果出个"演示凭证"
python gen_proof.py --result evaluation_results_v2.json --algo ed25519 \
    --key temp/demo_ed25519_key.pem --status demo-self-signed --out temp/demo_proof.yaml

# 3) 两种情况对比：官方信任锚 → 拒绝；本地信任锚 → 通过
python verify_proof.py temp/demo_proof.yaml --trusted-keys trusted_keys.json   --base-dir .
#   -> INVALID E_UNTRUSTED_KEY（预期：你的公钥不在官方信任锚内）
python verify_proof.py temp/demo_proof.yaml --trusted-keys temp/demo_trusted_keys.json --base-dir .
#   -> VALID（预期：用你自己的信任锚验证你自己的凭证）
```

**这两条输出正是本仓库想演示的边界**：签名可以自签，但"被信任"必须命中信任锚；`E_UNTRUSTED_KEY` 不是 bug，而是设计。完整原理与错误码表见 [docs/proof-issuance.md](docs/proof-issuance.md)。

## 4. 官方 4 份凭证的私钥在哪

由项目作者**离线保管**（不对应仓库内任何文件，也不随参赛包分发）。需要重新签发时，维护者按以下流程执行（详见 [CONTRIBUTING.md §3](CONTRIBUTING.md#3-改证据--改凭证--改口径的硬规则重要)）：

1. 用本机私钥对 `evaluation_results_*.json` 与 `artifacts_v2*` 重算绑定与签名：
   ```bash
   python gen_proof.py --result <result_file> --algo ed25519 --key <本机私钥> \
       --artifact-dir <工件目录> --base-dir . --out proofs/deterrence_proof_<state>_ed25519.yaml
   ```
2. 重跑验签与绑定审计，两者都必须通过；
3. 在 `CHANGELOG.md` 记录重签原因，并将旧凭证关系写入 `proof_header.reissue_of`。

## 5. 环境变量与路径约定（避免硬编码）

| 变量 / 参数 | 作用 | 默认 |
|---|---|---|
| `--key`（`gen_proof.py`） | 指定签名私钥路径 | 仓库内 `temp/swordholder_ed25519_demo_key.pem`（不存在即报错，提示你先生成） |
| `SWORDHOLDER_DEMO_KEY` | 覆盖上述默认私钥路径 | 未设置 |
| `SWORDHOLDER_ROOT` | 覆盖脚本推导的仓库根目录 | 脚本所在目录的上一级 |
| `--trusted-keys`（`verify_proof.py`） | 指定信任锚文件 | `trusted_keys.json` |

> 提示：`verify_proof.py` 的 `--base-dir` 决定凭证内相对路径（`../artifacts_v2` 等）的解析基准，默认与凭证文件所在目录（`proofs/`）一致；把凭证挪到别处时记得同步调整。
