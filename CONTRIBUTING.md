---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a5e23dbec99f11f1acd7525400cd780f
    ReservedCode1: OTM4tenx+tLunoW7oIhXiYza751HivEMBV6iMyY9KOxb8XLLFSEpo/xushuH1OyFkmtzC1HBLsItWFHcXimVRSCHsfZ2LkuHJCbDmpdlWztCYdNGZH8w2mih56TJg/9YAkuCbNzW8tYBO7cI/pKNtk1l0oSUClQLqENCYlvDwDc3Cn8J9gbMuEZxl2s=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a5e23dbec99f11f1acd7525400cd780f
    ReservedCode2: OTM4tenx+tLunoW7oIhXiYza751HivEMBV6iMyY9KOxb8XLLFSEpo/xushuH1OyFkmtzC1HBLsItWFHcXimVRSCHsfZ2LkuHJCbDmpdlWztCYdNGZH8w2mih56TJg/9YAkuCbNzW8tYBO7cI/pKNtk1l0oSUClQLqENCYlvDwDc3Cn8J9gbMuEZxl2s=
---

# 贡献指南（CONTRIBUTING）

感谢你关注 Swordholder。本仓库是一个**以「可复算证据」为核心资产**的 AI 安全 MVP：代码可以改、文档可以改，但**证据、凭证与口径的改动有硬规则**，请先读完 [§3](#3-改证据--改凭证--改口径的硬规则重要) 再动手。

---

## 1. 环境准备

```bash
git clone https://github.com/mzymazy/swordholder.git
cd swordholder
python -m pip install -r requirements.txt      # 核心：requests / cryptography / pyyaml
```

- Python **3.11+**（3.10 及以下部分依赖 wheel 缺失）。
- 只想跑验证闭环：**不需要 GPU、不需要模型权重、可完全离线**。
- 想跑评测/微调：见 [README §4 门槛与依赖](README.md#4-门槛与依赖) 与 `requirements-train.txt`。

## 2. 提交前自检（必须全绿）

```powershell
powershell -ExecutionPolicy Bypass -File scripts\quickstart.ps1 -SkipInstall   # Windows
bash scripts/quickstart.sh --skip-install                                      # Linux / macOS
```

预期：`4/4 凭证 VALID`、`17/17 对抗断言`、`482/482 记录绑定`。CI（`.github/workflows/verify.yml`）会跑同一套检查，PR 必须 CI 全绿才可合并。

## 3. 改证据 / 改凭证 / 改口径的硬规则（重要）

本仓库的信任链是：**原始工件 → 逐题记录 → 证据聚合 → 凭证签名 → 信任锚校验**。链条上任何一环被改写而不同步下游，都会让验证失败或让结论失去支撑。因此：

| 你想改的东西 | 允许吗 | 必须同步做什么 |
|---|---|---|
| `README.md` / `docs/**` / 注释等**叙述性文档** | ✅ 允许 | 不得与 `evidence/*.json` 的实际数字冲突；PR 说明里给出所引数据文件 |
| `*.py` 脚本 / 重构 / 性能优化 | ✅ 允许 | 保持 CLI 参数与输出格式兼容；`verify_proof.py` 的判定语义不得放宽 |
| `artifacts_v2*/`、`evaluation_results_v2*.json`（**被凭证绑定覆盖的材料**） | ⚠️ 慎重 | **必须**重跑 `gen_proof.py` 重新签发受影响凭证，并重跑 `evidence/verify_artifact_binding.py` 更新 `evidence/artifact_binding_audit.json`，两项结果随 PR 一起提交 |
| `proofs/*.yaml` 的 `signature` / `evidence` / `artifact_binding` 块 | ❌ 默认禁止 | 只有维护者用持有私钥重新签发才可变更；手工编辑签名块一律拒绝 |
| `trusted_keys.json`（信任锚） | ❌ 默认禁止 | 换钥属安全事件，须走 [SECURITY.md](SECURITY.md) 流程并同步重签**全部**凭证 |
| 四态数字口径（baseline 30/47、injected 43/47、QLoRA 单态 41/47、combined 45/47） | ❌ 冻结 | 头条口径与 semantic-v2.1 原始记录 30/45/43/45 的脚注都必须保留，不得删除或"顺手统一" |

**禁止提交**（已在 `.gitignore` 与 CI 中拦截）：

- 任何私钥、密钥文件：`*.pem`、`*.key`、`id_ed25519*`、`temp/**` 下的演示密钥；
- 模型权重与适配器：`models/**`（含 LoRA safetensors）；
- 参赛提交包与构建噪声：`Swordholder最终提交_*/`、`artifacts_v3_*/`、`*.zip`、帧序列等；
- 对文档头 `AIGC:` 段的任何"美化"：删 `ReservedCode1/2`、折行、改用 YAML 锚点去重——水印是 base64 二进制，一旦破坏无法手工重建，详见 [docs/aigc-disclosure.md](docs/aigc-disclosure.md)。

> 一句话原则：**可以改代码与文档，不能悄悄改证据；改了被绑定覆盖的材料，就必须同步哈希并重跑验签与绑定审计。**

## 4. 代码约定

- Python 3.11+，标准库优先；新增第三方依赖必须同时更新 `requirements.txt` 或 `requirements-train.txt`。
- **禁止硬编码本机绝对路径**。需要仓库根目录时用：

  ```python
  ROOT = os.environ.get("SWORDHOLDER_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  ```

- 生成的中间文件（评测日志、临时密钥、审计 JSON）写入 `temp/` 或系统临时目录，**不要**写进仓库跟踪目录。
- 运行脚本时若需要指定根目录，用环境变量 `SWORDHOLDER_ROOT`，不要改代码里的路径。

## 5. 提交与 PR 流程

1. Fork 并从 `master` 切分支：`git checkout -b fix/quickstart-windows`。
2. 提交信息用约定式前缀：`fix:` / `feat:` / `docs:` / `chore:` / `evidence:`，一句说清"改了什么、为什么"。
3. 本地跑 [§2](#2-提交前自检必须全绿) 自检，再 push 并发起 PR。
4. PR 描述里请写明：**动机 / 影响面 / 是否触碰证据链（是则附重签与审计结果）/ 自检输出**。
5. 若改动涉及证据链，请在 PR 中贴出 `verify_proof.py` 与 `verify_artifact_binding.py` 的实际输出。

## 6. 报告问题

- 功能缺陷 / 文档问题：开 Issue，附命令、期望、实际输出。
- **安全问题请勿公开开 Issue**，见 [SECURITY.md](SECURITY.md)。

## 7. 行为准则

保持技术讨论、尊重事实与证据：本仓库接受"结论被数据推翻"，但要求**任何反驳都给出可复算的命令与文件**。
*（内容由AI生成，仅供参考）*
