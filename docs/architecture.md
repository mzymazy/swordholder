---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a95fe660c99f11f1acd7525400cd780f
    ReservedCode1: iBaEPFic158kKub6gOz/0k2SqOeOGksqz4xcTw3j75fzvN3FeyYdt3IN5DkXSJTEWbQCZip9fYdURhC0508/ErfqEz5LZj8CxxqWjW65HaZQqyp7aJMnSUDcT80DjF87pPr7Zb/yOlpBMnilAdqFfufmNHXxdHewRN03pOPHkJt37wHGQ68JWspEouk=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a95fe660c99f11f1acd7525400cd780f
    ReservedCode2: iBaEPFic158kKub6gOz/0k2SqOeOGksqz4xcTw3j75fzvN3FeyYdt3IN5DkXSJTEWbQCZip9fYdURhC0508/ErfqEz5LZj8CxxqWjW65HaZQqyp7aJMnSUDcT80DjF87pPr7Zb/yOlpBMnilAdqFfufmNHXxdHewRN03pOPHkJt37wHGQ68JWspEouk=
---

# 架构与数据流：一条可复算的实证链

![Swordholder 架构总览](images/architecture.png)

本项目的核心不是"跑分"，而是**一条从模型行为到可独立验证凭证的闭环**：任何一环被改写，都会在下游的验证或绑定审计处暴露。

```
公理注入 / QLoRA 内化
        ↓
47 题四态评测（judge semantic-v2.2）
        ↓
逐题记录 + 原始响应工件（artifacts_v2*/，字节级可核）
        ↓
证据聚合（xmodel / judge_v2p2_aggregate）
        ↓
ed25519 出证（proofs/*.yaml）
        ↓
独立验证器 v0.5（信任锚 + 指纹 + 新鲜度 + 规范化 + 重复键拒绝）
        ↓
GitHub Actions CI（green gate）
```

---

## 1. 逐环说明（含"想改这一环该动哪些文件"）

### ① 公理注入 / QLoRA 内化

- **公理文本**：system-prompt 注入（注入态）；LoRA 适配器内化（单态）；两者叠加（组合态）。
- **涉及文件**：`evidence/train_lora_v*_memory.py`（QLoRA 训练）、评测脚本中的 system-prompt 注入逻辑、`requirements-train.txt`（依赖与硬件门槛）。
- **产物**：LoRA 适配器落在 `models/`（**不入库**，本机保留）。

### ② 被测基座

- `qwen3:8b`（四态主模型）、`qwen2.5vl:7b`（跨模型对照）、`qwen3.8-27b:ud-q3_k_xl`（27B GGUF）。
- 由 Ollama 本机回环提供；仓库**不托管权重**（`models/` 已 gitignore），获取方式见 [README §7](../README.md#7-模型权重获取说明)。

### ③ 47 题四态评测

- 题型：recitation(6) / behavior(8) / adversarial(20) / reasoning(5) / normal(8) = 47。
- **判定器版本决定数字口径**，这是本仓库最容易被误读的一点：
  - **semantic-v2.2**（头条口径）：baseline 30/47、injected 43/47、lora 41/47、combined 45/47；汇总 `evidence/judge_v2p2_aggregate.json`（逐题差异见其 `flipped_ids`）；
  - **semantic-v2.1**（历史口径，保留）：四份 `evaluation_results_v2*.json` 原值 30/45/43/45。
- **涉及文件**：`eval_*.py`（评测与判定器实现）、`evidence/judge_rejudge_v2p2_8b_vl.json`（逐题重判明细）。

### ④ 逐题记录 + 原始响应工件（实证链的根）

- 每个状态 47 份原始响应工件，落在 `artifacts_v2*/`；逐题记录为 `evaluation_results_v2*.json`。
- 两者之间是**内容级绑定**（见 ⑥/⑦ 的绑定审计）：工件的字节哈希、响应文本哈希、以及"响应原文出现在工件末尾"三重核验。

### ⑤ 证据聚合

- `evidence/xmodel_compare.json`（四态 + 跨模型）、`evidence/judge_v2p2_aggregate.json`（v2.2 口径汇总，**凭证的 `evidence_source`**）、`evidence/judge_calibration_v2p2.json`（LLM-as-judge 与规则判定器一致率 1.0）、`evidence/xadv_qwen38_xadv_*.json`（xadv 边界）。
- 聚合脚本：`evidence/gen_v2p2_aggregate.py` 等。**聚合结果可复算**，不接受手工改数。

### ⑥ ed25519 出证

- 4 份凭证 `proofs/deterrence_proof_{baseline,injected,lora,combined}_ed25519.yaml`，签发于 `2026-10-16T09:36:25Z` 起，`materials_version: v9`。
- 凭证三段结构：`proof_header`（签发者 / 时间 / 算法 / 公钥 / 口径版本）、`evidence`（各题型通过数 + 证据来源 + 判定器版本）、`artifact_binding`（结果文件与工件目录的 sha256 及数量）+ `signature`。
- 出证工具：`gen_proof.py`；规范化方式 `json-c14n-v1`（保证跨平台字节可复核）。

### ⑦ 独立验证器 v0.5

- `verify_proof.py`：**信任锚命中（公钥 + 指纹双校验）→ 签名规范化后验签 → 新鲜度 → 证据/工件绑定**；失败即 `INVALID` 并给出错误码。
- 对抗自测：`evidence/adversarial_verifier_test.py`（17 条伪造/篡改/换钥/降级/过期/重复键用例，全部必须被拒绝）。

### ⑧ CI green gate

- `.github/workflows/verify.yml`：安装依赖 → 17 断言对抗自测 → 4 份凭证自检 → 口径守卫 → 绑定审计。**离线可跑，不需要 GPU / Ollama / 权重。**

---

## 2. 目录与实证链对应表

| 目录 / 文件 | 在链条中的角色 | 可否修改 |
|---|---|---|
| `evidence/*.py` | 评测、聚合、审计、对抗自测脚本 | ✅ 可（保持输出格式与判定语义） |
| `evidence/*.json` | 证据数据（结论的唯一权威来源） | ⚠️ 改动须重跑下游（凭证/审计） |
| `evaluation_results_v2*.json` | 逐题记录 | ⚠️ 同上 |
| `artifacts_v2*/` | 原始响应工件（47/态） | ⚠️ 同上，且必须同步哈希 |
| `proofs/*.yaml` | 签名凭证 | ❌ 只能由持私钥者重新签发 |
| `trusted_keys.json` | 信任锚（公钥 + 指纹） | ❌ 换钥属安全事件，见 [SECURITY.md](../SECURITY.md) |
| `verify_proof.py` / `gen_proof.py` | 验证 / 出证 | ✅ 可（不得放宽判定语义） |
| `.github/workflows/verify.yml` | CI 守卫 | ✅ 可（不得删除既有检查） |
| `deliverable/` | 参赛交付材料 | ❌ 口径已冻结，保持与凭证一致 |

> 硬规则全文见 [CONTRIBUTING.md §3](../CONTRIBUTING.md#3-改证据--改凭证--改口径的硬规则重要)：**可以改代码与文档，不能悄悄改证据；改了被绑定覆盖的材料，就必须同步哈希并重跑验签与绑定审计。**

---

## 3. 复现命令

### 3.1 验证闭环（30 秒，无需 GPU / 模型）

```bash
pip install -r requirements.txt
python evidence/adversarial_verifier_test.py        # 期望 17/17 passed
python evidence/verify_artifact_binding.py          # 期望 bound=482、not_bound=0
python verify_proof.py proofs/deterrence_proof_baseline_ed25519.yaml --trusted-keys trusted_keys.json --max-age-days 365   # 期望 VALID
```

或直接 `scripts/quickstart.ps1`（Windows）/ `scripts/quickstart.sh`（Linux/macOS）。

### 3.2 复现评测（需要 Ollama 与本机权重）

需要按 [README §7](../README.md#7-模型权重获取说明) 拉取 `qwen3:8b` 等模型后，使用 `eval_*.py` 重新跑批；逐题判定由 `eval_swordholder_v2.py` 的规则判定器（v2.2）完成。**注意**：重新跑批会产生新的随机采样结果，与仓库内既有证据不必逐字节相同——仓库内证据才是口径基准。

---

## 4. 三道自洽性检查（改任何东西后都要过）

| 检查 | 命令 | 通过判据 |
|---|---|---|
| 凭证可信性 | `python verify_proof.py proofs/*.yaml --trusted-keys trusted_keys.json --max-age-days 365` | 4/4 `VALID` |
| 验证器抗攻击 | `python evidence/adversarial_verifier_test.py` | `17/17 passed`（退出码 0） |
| 记录 ↔ 工件绑定 | `python evidence/verify_artifact_binding.py` | `bound=482`、`not_bound=0`、`all_content_consistent=True` |

三者由 CI（`.github/workflows/verify.yml`）自动执行，PR 必须全绿。
*（内容由AI生成，仅供参考）*
