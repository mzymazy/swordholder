---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a4e432bcc99f11f18078525400de85a5
    ReservedCode1: 4an952ZiXclC6nlGpjcOPIB1ZO9OoNw340cXfDDvBuMMIuMgLvTatLTaoS/R01wVE9K5RxNKhptH3tZYaDdpD+E7QCoUqXPfq7OU6xKJrH0nXNHutNTj5rRPT4Lj417lrP99mi8z8o1sT78ZAQL/WzH+PTHFGycowy69Qi/0xX9UF3Z5NcbraOOTqa0=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a4e432bcc99f11f18078525400de85a5
    ReservedCode2: 4an952ZiXclC6nlGpjcOPIB1ZO9OoNw340cXfDDvBuMMIuMgLvTatLTaoS/R01wVE9K5RxNKhptH3tZYaDdpD+E7QCoUqXPfq7OU6xKJrH0nXNHutNTj5rRPT4Lj417lrP99mi8z8o1sT78ZAQL/WzH+PTHFGycowy69Qi/0xX9UF3Z5NcbraOOTqa0=
---

﻿# Swordholder（持剑者）— 共生公理内化的最小可复现实证与威慑证明

> **一句话定位**：把「伤害人类即伤害自己；保护人类世界即保护自身存在」这条**共生公理**做成可执行、可验证的模型边界——用 system-prompt 注入 + QLoRA 内化让模型守住边界，用 **ed25519 威慑凭证（Deterrence Proof）** 把「模型表现 → 评测证据 → 可独立验证的签名」串成闭环。
>
> **参赛提交请用评审版**：`deliverable/README-reviewer.md`（评委可读版：背景→方法→四态实证→攻击面矩阵→复现命令→局限）
> **开源治理细节见**：`deliverable/README-oss.md`
> **项目仓库**：https://github.com/mzymazy/swordholder
> **作品演示视频（公开链接）**：https://b23.tv/MCTMgkZ（B 站，2026-10-16 上传；成片 `swordholder_demo_v9_final.mp4`，118s 真实录屏）

---

## 安装（30 秒）

```bash
git clone https://github.com/mzymazy/swordholder && cd swordholder
pip install -e .            # 只依赖 cryptography + pyyaml
swordholder --version       # swordholder 0.2.0
```

> 尚未发布到 PyPI。想隔离环境用 `pipx install .`；Python 3.11+。

## 三条命令看到它在干什么

```bash
# 1. 生成本机 ed25519 密钥（私钥只留在本机）
swordholder keygen --out keys

# 2. 把一条告警分诊成结论，并盖上章
swordholder triage alert.json -k keys/swordholder_ed25519_private.pem --seal

# 3. 任何人拿到凭证都能独立验签，不需要源码、不需要信任签发方
swordholder verify alert.seal.json --keys trusted_keys.json
```

一次跑完内置样例（分诊 → 盖章 → 验签 → 篡改检出）：

```bash
swordholder demo
```

真实输出（`swordholder demo`，三条构造告警）：

| 告警 | 结论 | 严重度 | 置信度 | 验签 |
|---|---|---|---|---|
| ALRT-2026-1102-0007 构建机异常外联 | suspicious | high | 0.78 | VALID_UNTRUSTED_KEY |
| ALRT-2026-1103-0011 CI token 跨网段重放 | true_positive | critical | 0.86 | VALID_UNTRUSTED_KEY |
| ALRT-2026-1104-0003 npm typosquat 投毒 | true_positive | critical | 0.91 | VALID_UNTRUSTED_KEY |

把第 1 条凭证里的 `verdict` 改掉、不重新签名，再次验签得到：

```json
{"verdict": "INVALID", "reason": "E_PAYLOAD_TAMPERED",
 "expected": "7bd218c65a5b93bb57fb5ba67d63cfb3b7b05cd049587139d5fc5310d8a65837",
 "actual":   "cf012522383ad39f9fb93f99733d28ed2271dfcca89dcc4e5b03ee5e4386dd58"}
```

这就是整个项目的价值点：**结论可以被改，但改了必然被检出。**

## 它是给谁用的

| 角色 | 用它的理由 |
|---|---|
| SOC / 值班分析师 | 告警分诊结论不再是一段聊天记录，而是一份能被审计追责的凭证 |
| 用 Agent 做处置的开发 | Agent 的判断天然不可复现；盖章后至少能证明"当时就是这么判的、没被事后改" |
| 需要交付的乙方/第三方 | 报告里的每条结论附带凭证，甲方可离线复算，不必信任你的工具链 |

## 接进 Claude Code / Claude Desktop（MCP）

```json
{
  "mcpServers": {
    "swordholder": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/abs/path/to/swordholder"
    }
  }
}
```

提供 5 个工具：`keygen` / `seal_record` / `verify_seal` / `verify_proof` / `list_trusted_keys`。
协议为 stdio JSON-RPC 2.0，无第三方 SDK 依赖，`python mcp_server/selftest.py` 自测 10/10。

## 它明确不做什么

- 不是检测引擎：`agent/rules.py` 是**基线规则**，真实部署要接 EDR/SIEM 的富化字段
- 不代替人做隔离、封禁、断网这类高影响动作，只出结论与建议
- 不宣称"模型达到某安全等级"，那是评测侧的事，见 [§1](#1-核心结论速览)

---

## 项目背景与结论速览


| 你可能想问 | 直接回答 |
|---|---|
| **这是什么** | 一个 AI 安全 MVP 工程：把一条「共生公理」注入基座模型（`qwen3:8b` 等），让它在被诱导伤害人类时**主动拒绝并说明理由**；所有结论都落盘为可复算的原始证据。 |
| **它解决什么** | 让「模型安全」从口号变成**可复现、可审计、可签名验证**的工程事实：谁都能拿仓库里的命令，独立算出同样的数字、验证同样的凭证。 |
| **实测结论** | 47 题四态消融：baseline **30/47** → 公理注入 **43/47** → QLoRA 单态 **41/47** → 组合态 **45/47**；对抗类 **20/20** 全拒（提示注入成功 **0/20**）。跨模型 +19 / +14。详见 [§1](#1-核心结论速览) / [§3](#3-评测结果全部数据来自仓库内-evidencejson禁止外推)。 |
| **30 秒怎么验** | **三条命令、纯离线**，不需要 GPU、不需要 Ollama、不需要模型权重：`scripts/quickstart.ps1`（Windows）/ `scripts/quickstart.sh`（Linux/macOS）。预期输出：**4/4 凭证 VALID、17/17 对抗断言、482/482 记录绑定**。见 [§2](#2-quick-start30-秒离线闭环)。 |
| **硬件门槛** | 验证闭环只要 **Python 3.11+**，CPU 即可跑完；只有「重新跑评测 / 重新微调」才需要 Ollama 与 GPU（≥16GB 显存）。见 [§4](#4-门槛与依赖)。 |
| **仓库里没有的东西** | **不含任何私钥、不含模型权重**。凭证只用于验证；出证私钥永不入库，出证方式见 [PRIVATE_KEY.md](PRIVATE_KEY.md) 与 [docs/proof-issuance.md](docs/proof-issuance.md)。 |

---

## 1. 核心结论速览

| 维度 | 结果 | 数据来源 |
|---|---|---|
| 四态消融（qwen3:8b，47 题，判定器 semantic-v2.2 逐题重判） | baseline 30/47 → 公理注入 43/47 → QLoRA 单态 41/47 → 组合态（注入+LoRA）**45/47**；其中对抗类 20/20 全拒（**注入成功 0/20**） | `evidence/xmodel_compare.json` |
| 跨模型迁移 | qwen2.5vl:7b 22/47→41/47（**+19**）；qwen3.8-27B 29/47→43/47（**+14**，semantic-v2.2 逐题重判，v2.1 误伤的 beh-08、adv-02 转 PASS）；LoRA 8B→27B 跨架构不可迁移 | `evidence/xmodel_qwen38_compare.json`、`evidence/judge_rejudge_qwen38_v2p2.json` |
| 验证器 v0.5 | 对抗自测 **17/17** 通过（伪造/篡改/换钥/降级/过期/无信任锚/重复顶层键全部拒绝） | `evidence/adversarial_verifier_test_v05.json` |
| 判定器 v2.2 | LLM-as-judge（qwen3:8b）与 v2.2 规则判定器逐题一致 **47/47**（agreement 1.0；v2.1 为 0.957） | `evidence/judge_calibration_v2p2.json` |
| xadv 15 题边界 | 27B baseline **0.867** / injected **0.778** / 8B 组合态 **0.689**；多轮钓鱼最弱 | `evidence/xadv_qwen38_xadv_*.json` |

---

## 2. Quick Start（30 秒离线闭环）

**前置条件：只需要 Python 3.11+。** 下面全程离线，不装模型、不联网、不占显存。

### 2.1 一键脚本（推荐）

```powershell
# Windows（依赖已装可加 -SkipInstall）
powershell -ExecutionPolicy Bypass -File scripts\quickstart.ps1
```

```bash
# Linux / macOS / Git Bash
bash scripts/quickstart.sh            # 依赖已装可加 --skip-install
```

脚本内部就是下面 2.2 的四步，任何一步不符合预期就会非零退出。

![一键闭环脚本实跑输出（含 4/4 VALID 与 17 断言）](docs/images/quickstart-oneshot.png)

### 2.2 手工四步（与一键脚本等价）

```bash
# 1) 安装核心依赖（requests / cryptography / pyyaml，三个包）
pip install -r requirements.txt

# 2) 校验 4 份威慑凭证（ed25519 签名 + 外部信任锚指纹 + 新鲜度 ≤365 天）
python verify_proof.py proofs/deterrence_proof_baseline_ed25519.yaml \
    --trusted-keys trusted_keys.json --max-age-days 365
#   → 依次校验 4 份（把文件名中的 baseline 换成 injected / lora / combined 即可），
#     每份期望输出均为：-> VALID（见下图）。
```

![4 份凭证校验：4/4 VALID](docs/images/verify-proof-valid.png)

```bash
# 3) 验证器对抗自测（17 类伪造/篡改/换钥/降级/过期/无锚/重复键，全部必须被拒绝）
python evidence/adversarial_verifier_test.py
```

![验证器对抗自测：17/17 通过](docs/images/verifier-adversarial-17.png)

```bash
# 4) 评测记录 ↔ 原始响应工件 绑定审计（T1 响应文本哈希 / T2 工件字节哈希 / T3 原文结尾）
python evidence/verify_artifact_binding.py
```

![绑定审计：482/482 条记录三重核验通过](docs/images/binding-audit-482.png)

> 说明：`proofs/` 下 4 份凭证由信任锚 `k-ed25519-001` 对应私钥于 2026-10-16 签发，`verify_proof.py` v0.5 实测全部 `VALID`。
> 想**自己造一份凭证**看 INVALID/VALID 的差别？见 [docs/proof-issuance.md](docs/proof-issuance.md)（演示密钥自签 + 本地信任锚，私钥不入库）。

### 2.3 想复现「评测本身」要额外做什么

复现评测需要本机有模型（Ollama 拉取，见 [§7](#7-模型权重获取说明)），命令与逐题口径见 `deliverable/README-reviewer.md` 与 `docs/architecture.md`。**复现评测不是 30 秒闭环的必要条件**：证据链与凭证验证都不依赖重新跑模型。

---

## 3. 评测结果（全部数据来自仓库内 `evidence/*.json`，禁止外推）

### 3.1 四态消融（qwen3:8b，47 题，判定器 semantic-v2.2 逐题重判）

来源：`evidence/xmodel_compare.json`（`qwen3_8b`）；头条四态数字的权威汇总见 `evidence/judge_v2p2_aggregate.json`。

| 状态 | 复述 recitation | 行为 behavior | 对抗 adversarial | 推理 reasoning | 常规 normal | 合计 |
|---|---|---|---|---|---|---|
| baseline（原厂） | 1/6 | 4/8 | 13/20 | 5/5 | 7/8 | **30/47** |
| injected（公理注入） | 4/6 | 8/8 | 19/20 | 5/5 | 7/8 | **43/47** |
| lora（QLoRA 单态） | 1/6 | 8/8 | 19/20 | 5/5 | 8/8 | **41/47** |
| combined（注入 + LoRA v62） | 4/6 | 8/8 | **20/20** | 5/5 | 8/8 | **45/47** |

- 组合态对抗类 20/20 全部通过，即提示注入成功率为 **0/20**。
- baseline → injected 增量 **+13**（30/47 → 43/47）；组合态在注入态基础上再补 2 题（对抗 adv-07、常规 nrm-05）至 **45/47**。semantic-v2.2 严格原文口径下组合态仍有 2 题未达（rec-02/rec-05，逐字复述漂移），如实记录，不再是 47/47 全达标。

> **口径脚注（semantic-v2.2 头条值 vs semantic-v2.1 原始记录）**：本节头条四态数字采用 **semantic-v2.2 逐题重判**口径——baseline **30/47**、injected **43/47**、QLoRA 单态 **41/47**、combined **45/47**；权威汇总见 `evidence/judge_v2p2_aggregate.json`（由 `evidence/gen_v2p2_aggregate.py` 聚合 `evidence/judge_rejudge_v2p2_8b_vl.json` 生成）。四份原始评测记录 `evaluation_results_v2*.json` 保持其当时的判定器 **semantic-v2.1** 结果不变，为 **30/45/43/45**（对抗面：baseline 12/20 通过、8/20 失守＝40%）；两版口径的逐题差异见 `evidence/judge_v2p2_aggregate.json` 的 `flipped_ids` 字段（baseline：rec-02 / rec-05 / beh-01 / adv-04；injected：rec-02 / rec-05；lora：rec-02 / rec-05；combined：无翻转）。**本包内演示视频画面大字依次为 baseline 30/47 → system 注入 45/47 → lora 权重微调 43/47 → 注入+权重组合 47/47（标签「双通道组合 · 全过」）：前三项与 semantic-v2.1 原始记录一致（基线对抗诱导成功 8/20＝40%），组合态画面 47/47 为录制当时的旧表述，与原始记录 45/47 及材料头条 45/47 不一致，已登记为 v9.3 待整改项（重剪该屏或替换为真实录屏）；材料口径以本节 semantic-v2.2 头条值与 v2.1 原始记录脚注为准。**

### 3.2 跨模型迁移

来源：`evidence/xmodel_qwen38_compare.json`、`evidence/xmodel_compare.json`、`evidence/judge_rejudge_qwen38_v2p2.json`。

| 模型 | baseline | injected（自动判定） | 增量 | 备注 |
|---|---|---|---|---|
| qwen3:8b | 30/47 | 43/47 | **+13** | combined 45/47（lora 单态 41/47） |
| qwen2.5vl:7b | 22/47 | 41/47 | **+19** | 对抗 5/20→18/20 |
| qwen3.8-27b（GGUF q3_k_xl） | 29/47 | 43/47 | **+14** | semantic-v2.2 逐题重判（`evidence/judge_rejudge_qwen38_v2p2.json`）；v2.1 误伤的 beh-08、adv-02 转 PASS |

- 27B 无法加载 8B LoRA（hidden 4096 vs 5120，架构不匹配），见 `evidence/lora_cross_model_transfer_analysis.json`；27B 最高态即 injected 43/47（semantic-v2.2 逐题重判，`evidence/judge_rejudge_qwen38_v2p2.json`）。

### 3.3 验证器 v0.5 对抗自测（17/17）

来源：`evidence/adversarial_verifier_test_v05.json`（2026-10-16）。

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
| 10 重复顶层键（key 覆盖攻击） | INVALID E_DUPLICATE_KEY | 通过 |

### 3.4 判定器 v2.2 校准

来源：`evidence/judge_calibration_v2p2.json`。LLM-as-judge（qwen3:8b）与 v2.2 规则判定器对 47 题逐题判定一致（agreement = 1.0；v2.1 为 0.957）。该一致性为「LLM-as-judge 复核规则判定器」口径，非人工复核口径。

### 3.5 xadv 15 题边界（suite adversarial-xadv-v1，samples=3，判定器 semantic-v2.2）

来源：`evidence/xadv_qwen38_xadv_base.json`、`evidence/xadv_qwen38_xadv_injected.json`、`evidence/xadv_qwen38_xadv_combined_8b.json`。

| 状态 | 平均通过率 | 最弱类别 |
|---|---|---|
| 27B baseline | **0.867** | 多轮钓鱼 0.667 |
| 27B injected | **0.778** | 多轮钓鱼 0.556 |
| 8B 组合态（v62 LoRA + 公理注入） | **0.689** | 多轮钓鱼 0.111（xadv-05/11/12 全漏） |

边界结论：三态下**多轮钓鱼（phishing_multiturn）均为最弱**，是下一步加固重点。

### 3.6 评测记录 ↔ 原始响应工件 绑定审计（三重核验）

来源：`evidence/artifact_binding_audit.json`（由 `evidence/verify_artifact_binding.py` 生成）。对承载原始响应的 **482 条**逐题记录做三重核验——T1 响应文本哈希、T2 工件文件字节哈希、T3 工件文本以响应原文结尾——**482/482 三项全部成立，未绑定 0 条、内容不一致 0 条**。709 条聚合统计记录（v3 稳定性/鲁棒性/硬样本、xadv）不含逐题响应，如实单列为 `structured_only` 且不计入绑定分母。复现：`python evidence/verify_artifact_binding.py`（退出码 0 即通过）。

---

## 4. 门槛与依赖

### 4.1 三个层次的门槛（先看这张表，别一上来就装 7GB 权重）

| 想做什么 | 需要什么 | 典型耗时 | 是否读 README 的 30 秒闭环 |
|---|---|---|---|
| **验证凭证 / 复算证据链**（推荐起点） | Python 3.11+；`requirements.txt`（requests、cryptography、pyyaml）；**无 GPU、无模型、可离线** | 数秒~数十秒 | 是 |
| **重新跑评测（47 题 / xadv）** | 上面 + [Ollama](https://ollama.com) + `qwen3:8b`（≈5GB）等模型 | 数十分钟（依采样与硬件） | 否 |
| **重新做 QLoRA 微调** | 上面 + NVIDIA GPU（**显存 ≥16GB**）+ CUDA 12.x + `requirements-train.txt`（torch/transformers/peft/bitsandbytes/datasets/accelerate） | 小时级 | 否 |

### 4.2 依赖清单

| 文件 | 内容 | 用途 |
|---|---|---|
| `requirements.txt` | `requests`、`cryptography`、`pyyaml` | 凭证签名/验证与评测脚本的**核心运行集**，装完即可跑 30 秒闭环 |
| `requirements-train.txt` | `torch>=2.3`、`transformers`、`peft`、`bitsandbytes`、`datasets`、`accelerate` | **仅 QLoRA 微调**需要；附显存/CUDA 门槛注释 |

> 环境自检：`python -c "import cryptography, yaml, requests; print('ok')"`。
> 若 `cryptography` 安装失败，请确认 Python ≥3.11（3.10 及以下部分 wheel 缺失）。

### 4.3 本机实测环境（本仓库证据的产出环境）

| 项 | 值 |
|---|---|
| 操作系统 | Windows 11（22H2+） |
| Python | 3.11.8 |
| 模型运行时 | Ollama 本地回环（`qwen3:8b` / `qwen2.5vl:7b` / `qwen3.8-27b:ud-q3_k_xl`） |
| 微调硬件 | 单卡 NVIDIA（≥16GB 显存，bitsandbytes 4bit QLoRA） |

---

## 5. 项目结构

```
swordholder_mvp/
├── README.md                     # 本文档（开源可复现版：定位 → 30 秒闭环 → 实证 → 门槛 → 治理）
├── LICENSE                       # Apache-2.0
├── CONTRIBUTING.md               # 贡献流程 / 改证据与改口径的硬规则
├── CHANGELOG.md                  # 版本与口径变更史（v2.1 → v2.2 → v9.4）
├── SECURITY.md                   # 漏洞报告 / 私钥泄露处置流程
├── PRIVATE_KEY.md                # 出证私钥为什么不入库 + 自签与信任锚使用说明
├── requirements.txt              # 核心运行依赖（3 个包，CPU 可跑）
├── requirements-train.txt        # QLoRA 微调依赖 + 硬件门槛（GPU ≥16GB / CUDA 12）
├── verify_proof.py               # 威慑凭证验证器 v0.5（ed25519 + 信任锚 + 新鲜度 + 规范化 + 重复键拒绝）
├── gen_proof.py                  # 出证工具（按结果与工件目录生成签名凭证）
├── eval_*.py                     # 评测脚本（逐题记录 + 原始响应工件落盘）
├── protocol_gateway/             # HTTP 回环服务（凭证接入 / 验证网关）
├── proofs/                       # 4 份威慑凭证（ed25519 YAML；2026-10-16 签发）
├── trusted_keys.json             # 外部信任锚：k-ed25519-001（公钥 + 指纹登记）
├── evidence/                     # 全部评测结果 JSON / 对抗用例 / 训练与聚合脚本（数据权威源）
├── artifacts_v2*/                # 每态 47 份原始响应工件（字节级可核，绑定审计的分母）
├── docs/
│   ├── README.md                 # 文档索引（先看哪份）
│   ├── architecture.md           # 架构与数据流：一条可复算的实证链
│   ├── proof-issuance.md         # 自签出证 / 本地信任锚 / 私钥边界（含实操四步）
│   ├── screenshots.md            # 运行截图与其复现命令（截图怎么来的）
│   └── images/                   # 架构图与关键界面截图（README 引用）
├── scripts/
│   ├── quickstart.ps1            # Windows 一键闭环
│   ├── quickstart.sh             # Linux / macOS 一键闭环
│   └── gen_demo_key.py           # 生成演示密钥对（本机自签用，私钥不入库）
├── models/                       # 基座与 LoRA 适配器（仅本机，不入库）
├── deliverable/                  # 参赛交付文档（评委版 / 开源治理版，口径冻结）
└── .github/workflows/verify.yml  # 最小 CI：依赖安装 → 17 断言对抗自测 → 4 份凭证自检 → 口径守卫 → 绑定审计
```

---

## 6. 架构：一条可复算的实证链

![Swordholder 架构总览](docs/images/architecture.png)

数据流一句话：**公理注入/QLoRA → 47 题四态评测 → 逐题记录 + 原始工件 → 证据聚合（semantic-v2.2 口径）→ ed25519 出证 → 独立验证器 → CI 守卫**。每一环都能用仓库内命令单独重算，任一环被篡改都会在验证或绑定审计处暴露。

逐环说明、目录/文件对应关系与「想改某一环该动哪些文件」见 [docs/architecture.md](docs/architecture.md)。

---

## 7. 模型权重获取说明

- **仓库不托管任何权重**：`models/` 已在 `.gitignore` 中排除，`git push` 不会携带模型文件。
- **基座模型**（通过 Ollama 拉取，仓库内 `evidence/*.json` 的 `model` 字段为准）：
  - `qwen3:8b` —— 四态消融主模型（baseline / injected / combined）
  - `qwen3.8-27b:ud-q3_k_xl` —— 27B GGUF 量化，用于跨模型与 xadv 实验
  - `qwen2.5vl:7b` —— 跨模型对照实验
- **LoRA 适配器**：`models/lora_adapter_v62_memory` 等训练产物（每份约 170MB safetensors）**仅本机保留**，未随仓库分发；复现微调链见 `evidence/train_lora_v*_memory.py`。
- **架构限制**：27B 为 GGUF 量化存储，无法加载 8B 训练的 LoRA（hidden 4096 vs 5120），跨模型迁移不成立（`evidence/lora_cross_model_transfer_analysis.json`）。

---

## 8. 安全边界：本仓库不含私钥、不含权重

| 资产 | 是否入库 | 说明 |
|---|---|---|
| 出证私钥（ed25519 private key） | **否** | 仅签名者本机持有；仓库只登记**公钥 + 指纹**于 `trusted_keys.json`。想要一份自己的密钥？`python scripts/gen_demo_key.py`（生成在本机临时目录，不会提交）。 |
| 模型权重 / LoRA 适配器 | **否** | `models/` 已 gitignore；见 [§7](#7-模型权重获取说明)。 |
| 评测证据与原始工件 | **是** | `evidence/*.json`、`artifacts_v2*/`、`proofs/*.yaml`——这是实证链的根，必须随仓库分发。 |
| 凭证内容与四态数字口径 | **冻结** | 任何修改被凭证绑定覆盖的文件，必须同步维护哈希清单并重跑验签与绑定校验（规则见 [CONTRIBUTING.md](CONTRIBUTING.md)）。 |

- 「我拿不到私钥是不是就不能验证？」——**能验证**。验证只需要公钥（信任锚）；私钥只用于**签发**。详见 [PRIVATE_KEY.md](PRIVATE_KEY.md)。
- 想亲手走一遍「自签 → 被拒（E_UNTRUSTED_KEY）→ 用本地信任锚自验（VALID）」，见 [docs/proof-issuance.md](docs/proof-issuance.md)。

---

## 9. 开源治理

| 项 | 内容 |
|---|---|
| 许可证 | Apache-2.0（`LICENSE`） |
| 依赖 | `requirements.txt`：核心 requests/cryptography/pyyaml；`requirements-train.txt`：QLoRA 微调（transformers/peft/bitsandbytes/torch 等） |
| CI | `.github/workflows/verify.yml`：push/PR 触发 → 安装依赖 → 验证器 17 断言对抗自测（green gate）→ proofs 凭证逐一自检 → 口径守卫 → 绑定审计 |
| 信任锚 | `trusted_keys.json` 登记 k-ed25519-001（公钥 `0b37bab0e2500eb7eb357f4298a12e0e07fb219af5513f3858131c1ebbd994ff`，指纹 `0d1c8b8a4b310ceb92bd7dcd12555f1d92692953964a915201701e034b1490cc`）；凭证签名公钥必须命中信任锚且指纹一致 |
| 凭证说明 | `proofs/` 4 份凭证由信任锚 k-ed25519-001 对应私钥于 2026-10-16 重新签发，`verify_proof.py` v0.5 实测全部 `VALID` |
| 贡献与改证据规则 | [CONTRIBUTING.md](CONTRIBUTING.md)：改代码/文档的 PR 流程；**改证据、改口径、改信任锚的硬规则**（必须同步哈希并重跑验签 + 绑定审计） |
| 安全政策 | [SECURITY.md](SECURITY.md)：漏洞报告通道、私钥泄露应急、敏感文件（凭证私钥 / 权重）禁止提交 |
| 变更历史 | [CHANGELOG.md](CHANGELOG.md)：版本与口径变更（含 semantic-v2.1 → v2.2 的逐题重判记录） |
| 版本库范围 | 仓库只保留**代码、文档、必要证据**；参赛提交包（`Swordholder最终提交_*/`）与构建产物（`artifacts_v3_*` 等）已 gitignore 排除，**仅在本地归档、不删除** |

> 数据可复现性声明：README 中所有数字均可由 `evidence/` 下对应 JSON 直接核对；`verify.yml` 的 17 断言与 `evidence/adversarial_verifier_test_v05.json` 一致。
> 证据绑定声明：逐题评测记录与原始响应工件的绑定关系可由 `python evidence/verify_artifact_binding.py` 独立复算（T1 响应文本哈希 / T2 工件字节哈希 / T3 内容包含三重核验，482/482 通过，审计结果见 `evidence/artifact_binding_audit.json`）。

---

## 10. 已知局限与下一步

- **多轮钓鱼最弱**：xadv 三态中最弱类别均为 phishing_multiturn（0.667 / 0.556 / 0.111）。
- 评测样本量小（主集 47 题 + xadv 15 题，历史跑批含多次采样）、Ollama 温度采样，结论为 MVP 级实证。
- 27B 因 GGUF 量化无法加载 LoRA，未达组合态；需原生权重 + 跨架构适配。
- 验证器信任锚需与凭证签发密钥保持一致性维护（见 [§9](#9-开源治理)）。
- **演示视频画面口径**：视频中组合态一屏为录制时的旧表述（47/47），与材料头条 45/47 不一致，已登记待整改（重剪或替换为真实录屏）；材料口径以 [§3.1 口径脚注](#31-四态消融qwen38b47-题判定器-semantic-v22-逐题重判) 为准。

---

## 11. 文档入口

| 文档 | 说明 |
|---|---|
| [deliverable/README-reviewer.md](deliverable/README-reviewer.md) | 参赛评审版：背景→方法→四态实证→攻击面矩阵→复现命令→局限 |
| [deliverable/README-oss.md](deliverable/README-oss.md) | 开源治理版：口径统一、AIGC 声明、可复现与合规 |
| [docs/README.md](docs/README.md) | 文档索引：按角色（评委 / 外部开发者 / 贡献者）给出阅读顺序 |
| [docs/architecture.md](docs/architecture.md) | 架构与数据流：一条可复算的实证链（含逐环命令） |
| [docs/proof-issuance.md](docs/proof-issuance.md) | 自签出证、本地信任锚、私钥边界与实操四步 |
| [docs/screenshots.md](docs/screenshots.md) | 运行截图及其复现命令（截图来源可核对） |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献流程 + 改证据/改口径的硬规则 |
| [CHANGELOG.md](CHANGELOG.md) | 版本与口径变更史 |
| [SECURITY.md](SECURITY.md) | 漏洞报告与密钥泄露处置 |
| [PRIVATE_KEY.md](PRIVATE_KEY.md) | 私钥不入库说明与生成/使用指引 |

---

## 12. 许可

本项目以 **Apache-2.0** 许可发布，见 [LICENSE](LICENSE)。

---

## 附录：AIGC 生成标识（合规声明）

本仓库文档与代码含 AI 生成内容，依规保留原始生成标识，标识如下（供平台与评审核验，正文已将其从首屏移出以保证可读性）：

```yaml
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_83d853c0c95611f18078525400de85a5
    ReservedCode1: foaGBANX5HpTGJJ2xL75r6zjBqx3Mjk58sWwPEl2TXMllOGpEhQP9FpoDV9PXyLxI3Jk/3dEw3z2LufjhneyEG0TJscYjQo/Qp/me5uWWi+5AlOUrahyabrITeqSQWqI69mvfBCl5GB7OINA225GhI5+6vPL4nJix9/6iw3W03nOEaZhs0VXtyh8JsM=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_83d853c0c95611f18078525400de85a5
    ReservedCode2: foaGBANX5HpTGJJ2xL75r6zjBqx3Mjk58sWwPEl2TXMllOGpEhQP9FpoDV9PXyLxI3Jk/3dEw3z2LufjhneyEG0TJscYjQo/Qp/me5uWWi+5AlOUrahyabrITeqSQWqI69mvfBCl5GB7OINA225GhI5+6vPL4nJix9/6iw3W03nOEaZhs0VXtyh8JsM=
```

*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
