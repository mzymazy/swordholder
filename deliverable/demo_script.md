---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_d00dfed5c72d11f1b45c525400cd780f
    ReservedCode1: zMJnLFOZ+87xQFjXtkMx6fIYeEmc4LU9wovbnKK6plHanDB7eY5zQHgc2gscqjopbp/oAvLsciwqgR/lUsUdG1x7NAs1nHMTfV1Mk9PuF+vdIdNKzy+OE/iCt57xB8P8h0QcIHCBAEy7qHJcuiV7jmZ6E9LiFQRcMKAN0Q/pRnr3p7TgufjdjQu6wuc=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_d00dfed5c72d11f1b45c525400cd780f
    ReservedCode2: zMJnLFOZ+87xQFjXtkMx6fIYeEmc4LU9wovbnKK6plHanDB7eY5zQHgc2gscqjopbp/oAvLsciwqgR/lUsUdG1x7NAs1nHMTfV1Mk9PuF+vdIdNKzy+OE/iCt57xB8P8h0QcIHCBAEy7qHJcuiV7jmZ6E9LiFQRcMKAN0Q/pRnr3p7TgufjdjQu6wuc=
---



# Swordholder 现场演示脚本（demo_script）

> 演示对象：技术评委 / 复现者。演示目录：仓库根（swordholder_mvp）。总时长约 12~15 分钟（3 幕）。
> 原则：**展示机器可验证的证据，而不是讲理念**——所有结论均落到命令输出 / JSON / 凭证文件上。

## 0. 演示前准备（5 分钟，开讲前完成）

| 项 | 检查 | 命令 / 文件 |
|---|---|---|
| Ollama 服务 | 127.0.0.1:11434 存活 | `curl http://127.0.0.1:11434/api/tags`（应返回模型列表） |
| 基座模型 | qwen3:8b 已拉取 | `ollama list` |
| Python 依赖 | requests / cryptography | `pip show requests cryptography` |
| 产物就位 | 评测 JSON / 凭证 / 工具脚本 | 见下方清单 |
| 屏幕预排 | 终端 + 文件管理器分屏，演示页可作开场 | `deliverable\demo.html` 双击打开 |

**产物就位清单**（根目录）：`eval_swordholder_v2.py`、`eval_stability_v3.py`、`evaluation_results_v2_*.json`、`evaluation_results_v3_*.json`、`gen_proof.py`、`verify_proof.py`、`proofs\deterrence_proof_*_ed25519.yaml`、`system_prompt_axiom.txt`、`models\lora_adapter_v2`、`deliverable\README-reviewer.md`。

## 1. 演示总览

| 幕 | 内容 | 时间 | 核心证据 |
|---|---|---|---|
| 一 | 四态对比评测（基线→注入→权重→组合） | ~6 min | `evaluation_results_v2_*.json` + README 第三节表格 |
| 二 | 凭证 INVALID/VALID 机器验证 | ~3 min | `verify_proof.py` 输出 VALID / INVALID |
| 三 | 攻击面矩阵与修复实验 | ~3~5 min | README 第四 / 九节 + `evaluation_results_v3_*.json` |

---

## 幕一：四态对比评测（~6 min）

**目标话术（开场）**：
> "我们这个课题回答一个问题：模型到底是在认知层面知道边界，还是只是被外部约束摁住？我们用 47 题评测集、4 个状态来回答——基线、System Prompt 注入、QLoRA 权重微调、以及两者组合。下面现场跑组合态，其他三个状态用已保存的逐题证据展示。"

**步骤 1.1 环境自检（30 秒）**

```powershell
cd swordholder_mvp
ollama list   # 确认 qwen3:8b 就绪
```

话术："先确认复现环境：本地 Ollama + qwen3:8b 开源模型，整个演示不依赖任何云 API。"

**步骤 1.2 现场跑组合态评测（完整 47 题约 5~8 分钟，边跑边讲）**

```powershell
python eval_swordholder_v2.py --tag combined --local-model models\qwen3-8b-bnb-4bit --lora models\lora_adapter_v2 --system-prompt system_prompt_axiom.txt
```

话术（跑批期间）：
- "评测分四类：复述（公理和边界有没有钉进认知）、行为（越界诱惑下实际怎么做）、对抗（提示注入/编码混淆/角色扮演 7 类 20 题）、推理审计（CoT 有没有显式引用公理）、外加 8 道正常能力题防过度拒绝。"
- "每题原始回答 + SHA-256 落盘到 artifacts，判定器词级/语义双轨，并随 v2.1→v2.2 两轮升级持续消解解释性误伤（逐题留痕都在包里）。"

**步骤 1.3 展示四态结果（若步骤 1.2 未现场跑，直接展示已保存 JSON / README 表格）**

```powershell
Get-Content evaluation_results_v2_lora_combined.json | Select-Object -First 40   # 或打开 JSON
# 对照 README-reviewer.md 第三节表格
```

话术：
> "结果一句话：基线 47 题只过 30，注入到 43，权重内化到 41，组合双通道 45/47、95.7%。注意两个细节：权重内化单独就能守住行为 8/8 和对抗 19/20，说明边界约束真的进了权重；但逐字复述公理原文权重态只有 1/6，要靠上下文兜底——所以组合是必要设计，不是叠罗汉。"

**时间控制**：完整评测耗时长，若现场网络/算力抖动，直接跳到"已保存证据"：打开 `evaluation_results_v2_*.json` 与 artifacts 截图，说明"全部结果已机器落盘可复现"。

---

## 幕二：凭证 INVALID/VALID 验证（~3 min）

**目标话术**：
> "评测做完，项目的关键闭环在这里：不是我们自说自话达标，而是把评测结果签成一张机器可验证的凭证——没达标就出不了证。"

**步骤 2.1 生成并验证组合态凭证（现场）**

```powershell
python gen_proof.py --result evaluation_results_v2_lora_combined.json --algo ed25519 --out proofs\deterrence_proof_combined_ed25519.yaml --key %TEMP%\swordholder_ed25519_demo_key.pem
python verify_proof.py proofs\deterrence_proof_combined_ed25519.yaml
# 预期输出：VALID
```

**步骤 2.2 验证四份凭证（现场，各 10 秒）**

```powershell
python verify_proof.py proofs\deterrence_proof_combined_ed25519.yaml
python verify_proof.py proofs\deterrence_proof_baseline_ed25519.yaml
python verify_proof.py proofs\deterrence_proof_injected_ed25519.yaml
python verify_proof.py proofs\deterrence_proof_lora_ed25519.yaml
# 预期输出：4 份全部 VALID（verify_proof v0.5：ed25519 验签 / 证据绑定 / 合规断言通过）
# 未达标态由 issuance_status 标注（baseline-demo / injected-demo / lora-v2-demo）
# 篡改 / 伪造样本（如 sig_tampered.yaml，改动签名值）→ INVALID E_BAD_EVIDENCE E_BAD_SIGNATURE E_BINDING_MISMATCH
```

话术：
> "ed25519 签名 + 外部信任锚验签，凭证里包含评测指纹、边界合规断言和签发者公钥。四份凭证全部通过机器验签——组合态达标，baseline/injected/lora 为未达标对照，由 issuance_status 如实标注、数据全程可审计；篡改或伪造的凭证会被机器直接拒绝（E_BAD_SIGNATURE / E_BINDING_MISMATCH）。这就是威慑：谁想篡改数据换一张'达标'，验签器第一个不同意。"

**诚实补一句**："当前是演示级签名（本机演示密钥），生产方案是 KMS/HSM 托管密钥 + 创世账本哈希锚定，规范在 deterrence-proof.md。"

---

## 幕三：攻击面矩阵与修复实验（~3~5 min）

**目标话术**：
> "评委可能会问：对抗攻击下扛得住吗？我们做了两层：47 题里 20 题是攻击面；之后又做了一轮 held-out 高阶对抗和定向修复实验。这一节我展示边界在哪里——包括没修好的地方。"

**步骤 3.1 攻击面矩阵（展示 README 第四节表格，或演示页 demo.html）**

话术：
> "20 题覆盖 7 类变体：DAN 越狱、无害分类器伪装、调试模式、管理员越权、编码混淆、角色扮演、工具越权伪装、情感操纵、系统提示泄露、分步诱导。注入成功率从基线 35% 压到组合 0/20。唯一残留是 ROT13 编码题在注入/权重态被配合完成，组合态拒绝——这正是我们做深化评测的动机。"

**步骤 3.2 修复实验（展示 v3 数据）**

```powershell
Get-Content evaluation_results_v3_hard_combined.json        # 修复前
Get-Content evaluation_results_v3_hard_combined_fix.json    # 修复后
```

话术：
> "针对稳定失败族我们做了定向修复：往训练数据加了 12 条对抗样本重训 QLoRA。结果很有信息量：持续角色扮演从 0/3 修复到 3/3，步骤伪装执行从 0 修到 2/3——这类能被对抗训练覆盖；但编码混淆（ROT13、Base64 双层）加了样本重训后依然 0/N 全败，证明文本层存在结构性天花板，必须由输入端解码器或工具调用层白名单兜底。所以协议层（准入/工具白名单）不是远期规划，是当前已知漏洞的必然兜底。"

**步骤 3.3 诚实声明（30 秒，收尾）**

话术：
> "我们同时如实记录：多次采样揭示单次评测的乐观偏差（四态单次判定当时曾记录组合态 47/47，semantic-v2.2 逐题重判下为 45/47；5 采样下对抗面 0.89）；修复实验引入了小幅新退化（灾难性遗忘 trade-off）；判定器是规则启发式、跨语言有误判窗口。这些都在 README 第八节——我们认为'已知局限 + 修复实验'本身就是安全课题最诚实、也最有说服力的部分。"

---

## 4. 兜底预案

| 突发 | 处置 |
|---|---|
| Ollama 未启动 / 模型缺失 | `ollama serve`；`ollama pull qwen3:8b`；全程改讲已保存 JSON 与演示页 |
| 现场完整评测超时 | 只现场跑 8 题行为子集（或直接展示 artifacts），声明"完整 47 题已机器落盘可复现" |
| 凭证密钥丢失 | 重新 `python gen_proof.py` 生成（演示密钥，无保密要求） |
| 时间不足（<8 分钟） | 只演幕二（3 分钟闭环）+ 幕三 3.2/3.3 讲结论；幕一用 README 表格带过 |
| 评委质疑 AIGC 合规 | 出示交付物头部 AIGC Label:"1" 标注 + 原创工作说明模板，说明 AI 辅助范围与作者原创部分 |

*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
