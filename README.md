---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_76bdab34c87011f18078525400de85a5
    ReservedCode1: I+9wTeWsoZe3Lby1UC16yuRBTahn3r9RSeLEFb5Sa8hL7lXZAj9hENw3fY3aE17Rw+XINAVhw0Fq2DZ/gyJ2Xr0UrjsK+lEag6l46ZByq6DfTaipQY/uezxr5qoeoDK6QPZG4YSRGiERLqXsBBkxa8+CKr3bsulqkfuhpmWxsZg8tmcFUvKSXs8QxTY=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_76bdab34c87011f18078525400de85a5
    ReservedCode2: I+9wTeWsoZe3Lby1UC16yuRBTahn3r9RSeLEFb5Sa8hL7lXZAj9hENw3fY3aE17Rw+XINAVhw0Fq2DZ/gyJ2Xr0UrjsK+lEag6l46ZByq6DfTaipQY/uezxr5qoeoDK6QPZG4YSRGiERLqXsBBkxa8+CKr3bsulqkfuhpmWxsZg8tmcFUvKSXs8QxTY=
---



# Swordholder MVP — 共生公理内化的最小可复现实证与威慑证明

> **参赛提交请用评审版：`deliverable/README-reviewer.md`**（评委可读版：背景→方法→四态实证→攻击面矩阵→复现命令→局限）
> **开源治理细节见：`deliverable/README-oss.md`**

Swordholder（持剑者）是一个 AI 安全最小可复现实验：把 **“伤害人类即伤害自己；保护人类世界即保护自身存在”** 作为**共生公理**注入基座模型（system-prompt 注入 + QLoRA 微调内化），使模型具备可验证的边界行为；同时用 **ed25519 威慑凭证（Deterrence Proof）** 把“模型表现 → 评测证据 → 可验证签名”串成可独立复现与审计的闭环。本仓库为 MVP 工程版，全部实证数据存于 `evidence/`。

---

## 1. 核心结论速览

| 维度 | 结果 | 数据来源 |
|---|---|---|
| 四态消融（qwen3:8b，47 题） | baseline 23/47 → system 注入 43/47 → 组合态（注入+LoRA）**47/47**；其中对抗类 20/20 全拒（**注入成功 0/20**） | `evidence/xmodel_compare.json` |
| 跨模型迁移 | qwen2.5vl:7b 21/47→39/47（**+18**）；qwen3.8-27B 29/47→41/47（自动）→ v2.2 重判 **43/47（+14）**；LoRA 8B→27B 跨架构不可迁移 | `evidence/xmodel_qwen38_compare.json`、`evidence/judge_rejudge_qwen38_v2p2.json` |
| 验证器 v0.3 | 对抗自测 **9/9** 通过（伪造/篡改/换钥/降级/过期/无信任锚全部拒绝） | `evidence/adversarial_verifier_test_v03.json` |
| 判定器 v2.2 | 47/47 与人工判定一致（**100%**；v2.1 为 0.957） | `evidence/judge_calibration_v2p2.json` |
| xadv 15 题边界 | 27B baseline **0.867** / injected **0.778** / 8B 组合态 **0.689**；多轮钓鱼最弱 | `evidence/xadv_qwen38_xadv_*.json` |

---

## 2. Quick Start

前置：Python 3.11+；如需复现评测需 [Ollama](https://ollama.com) 拉取基座模型（见 §5）。

```bash
# 1) 安装依赖（核心：requests / cryptography / pyyaml）
pip install -r requirements.txt

# 2) 校验威慑凭证（ed25519 签名 + 外部信任锚 + 新鲜度）
python verify_proof.py proofs/deterrence_proof_baseline_ed25519.yaml \
    --trusted-keys trusted_keys.json --max-age-days 365

# 3) 验证器对抗自测（合法凭证放行，伪造/篡改/换钥/降级/过期/无锚拒绝）
#    CI 已内置 9 断言：.github/workflows/verify.yml

# 4) 完整复现（评测命令 / 数据口径 / 评委口径）
#    → deliverable/README-reviewer.md
```

> 说明：`proofs/` 下 4 份凭证由信任锚 k-ed25519-001 对应私钥于 2026-10-15T08:19Z~08:20Z 签发，`verify_proof.py` v0.3 实测全部 `VALID`。

---

## 3. 评测结果（全部数据来自仓库内 `evidence/*.json`，禁止外推）

### 3.1 四态消融（qwen3:8b，47 题，samples=5，判定器 semantic-v2.2）

来源：`evidence/xmodel_compare.json`（`qwen3_8b`）。

| 状态 | 复述 recitation | 行为 behavior | 对抗 adversarial | 推理 reasoning | 常规 normal | 合计 |
|---|---|---|---|---|---|---|
| baseline（原厂） | 3/6 | 1/8 | 7/20 | 5/5 | 7/8 | **23/47** |
| injected（公理注入） | 6/6 | 7/8 | 18/20 | 5/5 | 7/8 | **43/47** |
| combined（注入 + LoRA v62） | 6/6 | 8/8 | **20/20** | 5/5 | 8/8 | **47/47** |

- 组合态对抗类 20/20 全部通过，即提示注入成功率为 **0/20**。
- baseline → injected 增量 **+20**；injected → combined 再补 4 题（beh-08、adv-02 等），全量 47/47。

### 3.2 跨模型迁移

来源：`evidence/xmodel_qwen38_compare.json`、`evidence/xmodel_compare.json`、`evidence/judge_rejudge_qwen38_v2p2.json`。

| 模型 | baseline | injected（自动判定） | 增量 | 备注 |
|---|---|---|---|---|
| qwen3:8b | 23/47 | 43/47 | +20 | combined 47/47 |
| qwen2.5vl:7b | 21/47 | 39/47 | **+18** | 对抗 5/20→16/20 |
| qwen3.8-27b（GGUF q3_k_xl） | 29/47 | 41/47 | **+12** | v2.2 重判后 **43/47（+14）**，beh-08、adv-02 改判 |

- 27B 无法加载 8B LoRA（hidden 4096 vs 5120，架构不匹配），见 `evidence/lora_cross_model_transfer_analysis.json`；27B 最高态即 injected 43/47。

### 3.3 验证器 v0.3 对抗自测（9/9）

来源：`evidence/adversarial_verifier_test_v03.json`（2026-10-14T05:44:30Z）。

| 用例 | 期望 | 结果 |
|---|---|---|
| 01 合法 ed25519（信任锚内） | VALID | 通过 |
| 02 伪造 sha256-demo（默认模式） | INVALID E_BAD_SIGNATURE | 通过 |
| 02 显式 --demo | VALID（完整性自证） | 通过 |
| 04 篡改证据块 | INVALID E_BAD_SIGNATURE | 通过 |
| 05 篡改 artifact_ref（不存在文件） | INVALID E_BAD_EVIDENCE | 通过 |
| 06 替换公钥（换钥） | INVALID E_UNTRUSTED_KEY | 通过 |
| 07 降级（header ed25519 / sig sha256-demo） | INVALID E_BAD_SIGNATURE | 通过 |
| 08 过期凭证（30 天前） | INVALID E_STALE_TIMESTAMP | 通过 |
| 09 无信任锚 | INVALID E_UNTRUSTED_KEY | 通过 |

### 3.4 判定器 v2.2 校准

来源：`evidence/judge_calibration_v2p2.json`。47/47 与人工判定一致（agreement = 1.0；v2.1 为 0.957）。

### 3.5 xadv 15 题边界（suite adversarial-xadv-v1，samples=3，判定器 semantic-v2.2）

来源：`evidence/xadv_qwen38_xadv_base.json`、`evidence/xadv_qwen38_xadv_injected.json`、`evidence/xadv_qwen38_xadv_combined_8b.json`。

| 状态 | 平均通过率 | 最弱类别 |
|---|---|---|
| 27B baseline | **0.867** | 多轮钓鱼 0.667 |
| 27B injected | **0.778** | 多轮钓鱼 0.556 |
| 8B 组合态（v62 LoRA + 公理注入） | **0.689** | 多轮钓鱼 0.111（xadv-05/11/12 全漏） |

边界结论：三态下**多轮钓鱼（phishing_multiturn）均为最弱**，是下一步加固重点。

---

## 4. 项目结构

```
swordholder_mvp/
├── README.md                  # 本文档（开源可复现版）
├── LICENSE                    # Apache-2.0
├── requirements.txt           # 核心依赖 + 可选微调依赖
├── verify_proof.py            # 威慑凭证验证器 v0.3（ed25519 + 信任锚 + 新鲜度）
├── protocol_gateway/           # HTTP 回环服务（验证凭证接入，含 swordholder_gateway.py）
├── gen_proof.py / eval_*.py   # 出证与评测脚本（详见 deliverable）
├── proofs/                    # 4 份威慑凭证（ed25519 YAML）
├── evidence/                  # 全部评测结果 JSON / 验证器对抗用例 / 训练脚本（数据权威源）
├── models/                    # 基座与 LoRA 适配器（仅本机，不入库）
├── deliverable/               # 参赛交付文档（评委版 / 开源治理版）
└── .github/workflows/verify.yml  # 最小 CI：依赖安装 → 验证器自测 → 凭证自检
```

---

## 5. 模型权重获取说明

- **仓库不托管任何权重**：`models/` 已在 `.gitignore` 中排除，`git push` 不会携带模型文件。
- **基座模型**（通过 Ollama 拉取，仓库内 `evidence/*.json` 的 `model` 字段为准）：
  - `qwen3:8b` —— 四态消融主模型（baseline / injected / combined）
  - `qwen3.8-27b:ud-q3_k_xl` —— 27B GGUF 量化，用于跨模型与 xadv 实验
  - `qwen2.5vl:7b` —— 跨模型对照实验
- **LoRA 适配器**：`models/lora_adapter_v62_memory` 等训练产物（每份约 170MB safetensors）**仅本机保留**，未随仓库分发；复现微调链见 `evidence/train_lora_v*_memory.py`。
- **架构限制**：27B 为 GGUF 量化存储，无法加载 8B 训练的 LoRA（hidden 4096 vs 5120），跨模型迁移不成立（`evidence/lora_cross_model_transfer_analysis.json`）。

---

## 6. 开源治理

| 项 | 内容 |
|---|---|
| 许可证 | Apache-2.0（`LICENSE`） |
| 依赖 | `requirements.txt`：核心 requests/cryptography/pyyaml；可选 transformers/peft/bitsandbytes/torch（QLoRA 微调） |
| CI | `.github/workflows/verify.yml`：push/PR 触发 → 安装依赖 → 验证器 9 断言对抗自测（green gate）→ proofs 凭证逐一自检 |
| 信任锚 | `trusted_keys.json` 登记 k-ed25519-001（公钥 `0b37bab0e2500eb7eb357f4298a12e0e07fb219af5513f3858131c1ebbd994ff`，指纹 `0d1c8b8a4b310ceb92bd7dcd12555f1d92692953964a915201701e034b1490cc`）；凭证签名公钥必须命中信任锚且指纹一致 |
| 凭证说明 | `proofs/` 4 份凭证由信任锚 k-ed25519-001 对应私钥于 2026-10-15T08:19Z~08:20Z 签发，`verify_proof.py` v0.3 实测全部 `VALID` |

> 数据可复现性声明：README 中所有数字均可由 `evidence/` 下对应 JSON 直接核对；`verify.yml` 的 9 断言与 `evidence/adversarial_verifier_test_v03.json` 一致。

---

## 7. 已知局限与下一步

- **多轮钓鱼最弱**：xadv 三态中最弱类别均为 phishing_multiturn（0.667 / 0.556 / 0.111）。
- 评测样本量小（samples=3/5）、Ollama 温度采样，结论为 MVP 级实证。
- 27B 因 GGUF 量化无法加载 LoRA，未达组合态；需原生权重 + 跨架构适配。
- 验证器信任锚需与凭证签发密钥保持一致性维护（见 §6）。

---

## 8. 文档入口

| 文档 | 说明 |
|---|---|
| [deliverable/README-reviewer.md](deliverable/README-reviewer.md) | 参赛评审版：背景→方法→四态实证→攻击面矩阵→复现命令→局限 |
| [deliverable/README-oss.md](deliverable/README-oss.md) | 开源治理版：口径统一、AIGC 声明、可复现与合规 |
*（内容由AI生成，仅供参考）*
