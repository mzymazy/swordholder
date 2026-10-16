# 变更日志（CHANGELOG）

本文件记录**对外可观察的变更**：版本、证据链、判定器口径与仓库治理。数字口径的权威来源始终是仓库内 `evidence/*.json` 与 `proofs/*.yaml`，本文件只做索引式记录。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号对应材料版本（`materials_version`）。

---

## [未发布] — 开源治理与工程化补齐

### 新增（Added）

- `scripts/quickstart.ps1`、`scripts/quickstart.sh`：**30 秒离线闭环**一键脚本（凭证校验 → 17 断言对抗自测 → 482 条绑定审计），无需 GPU / 模型 / 联网。
- `scripts/gen_demo_key.py`：生成演示用 ed25519 密钥对（**私钥不入库**），并可选导出本地信任锚，供外部开发者自签自验。
- `requirements-train.txt`：QLoRA 微调依赖与硬件门槛（GPU ≥16GB、CUDA 12.x）从核心依赖中拆出。
- `docs/`：文档目录（`README.md` 索引、`architecture.md` 架构与数据流、`proof-issuance.md` 自签出证与私钥边界、`screenshots.md` 截图与复现命令、`images/` 架构图与运行截图）。
- `CONTRIBUTING.md`、`SECURITY.md`、`PRIVATE_KEY.md`、`CHANGELOG.md`。

### 变更（Changed）

- `README.md` 首屏重写为「TL;DR 一张表」：定位 / 价值 / 实测结论 / 30 秒验证方式 / 硬件门槛 / 仓库不含什么，**AIGC 合规标识移至文末附录**（标识内容逐字保留）。
- `evidence/` 下 15 个脚本的**本机绝对路径硬编码**（`HERE = "O:\..."`）改为相对定位：`SWORDHOLDER_ROOT` 环境变量优先，否则取脚本上一级目录；出证脚本的演示私钥默认路径改为仓库内相对路径并支持 `SWORDHOLDER_DEMO_KEY` 覆盖。**验证与审计结论未变**（详见下条）。
- `verify_proof.py` / `gen_proof.py` 的调用方式不变；凭证文件、信任锚与四态数字口径**未做任何改动**。

### 未变更（Unchanged，明确声明）

- `proofs/*.yaml`（4 份凭证，含签名块、证据块、工件绑定块）：**字节级未改动**。
- `trusted_keys.json`：信任锚 `k-ed25519-001` 公钥与指纹**未改动**。
- 四态头条口径 baseline **30/47**、injected **43/47**、QLoRA 单态 **41/47**、combined **45/47**；semantic-v2.1 原始记录 **30/45/43/45** 脚注**保留**。
- `deliverable/` 参赛交付文档：**未改动**（参赛材料已发出，口径必须保持一致）。

### 治理（Chore）

- `.gitignore` 扩充：参赛提交包目录（`Swordholder最终提交_*/`）、构建/实验噪声（`artifacts_v3_*/`、`artifacts_xadv_*/`）、打包残留、`temp/` 演示密钥等排除在版本库外。**仅归档与忽略，未删除任何文件。**

---

## [v9.4] — 参赛材料重打包

- README 补录作品演示视频公开链接（B 站 `b23.tv/MCTMgkZ`，118s 真实录屏），材料重打包为 v9.4。
- 变更范围：9 个文件（+24 / −14）；本地提交 `9d1d173`。

## [v9] — 凭证重新签发（绑定一致性重签）

- 4 份威慑凭证（baseline / injected / lora / combined）统一以 LF 字节基准重算 `result_sha256` 与工件索引哈希后重新签发，签发时间 `2026-10-16T09:36:25Z` 起，签发者 `swordholder-eval/0.1.0`，签名算法 ed25519（`json-c14n-v1` 规范化）。
- 信任锚 `trusted_keys.json` 登记 `k-ed25519-001`（公钥 `0b37bab0…994ff`，指纹 `0d1c8b8a…490cc`）；私钥不入库。
- `verify_proof.py` v0.5 实测 4 份凭证全部 `VALID`。

## [semantic-v2.2] — 判定器口径重判（头条口径切换）

- 引入 semantic-v2.2 判定器逐题重判，头条四态数字定为 **baseline 30/47、injected 43/47、LoRA 单态 41/47、combined 45/47**；权威汇总 `evidence/judge_v2p2_aggregate.json`，逐题差异见其 `flipped_ids` 字段。
- **semantic-v2.1 原始记录保留不变**：四份 `evaluation_results_v2*.json` 仍为 **30/45/43/45**（对抗面 baseline 12/20 通过、8/20 失守＝40%），作为历史口径脚注随材料一并保留，不得删除或覆盖。
- LLM-as-judge 与规则判定器一致率：v2.2 **1.0**（v2.1 为 0.957），见 `evidence/judge_calibration_v2p2.json`。

## [v0.5] — 验证器对抗加固

- 验证器 `verify_proof.py` v0.5 增加：签名规范化（`json-c14n-v1`）、重复顶层键拒绝、信任锚公钥+指纹双重校验、凭证新鲜度（`--max-age-days`）、工件绑定校验（`artifact_index_sha256` / `result_sha256`）。
- 对抗自测用例扩展到 **17 条**（伪造签名 / 篡改证据 / 篡改工件引用 / 换钥 / 算法降级 / 过期 / 无信任锚 / 重复键 / 绑定不匹配 / 时间戳非法与未来时间等），全部通过，见 `evidence/adversarial_verifier_test_v05.json`。

## [v0.4] — 绑定审计

- 新增 `evidence/verify_artifact_binding.py`：对承载原始响应的逐题记录执行 T1 响应文本哈希 / T2 工件字节哈希 / T3 原文结尾包含三重核验；当前 **482/482** 通过，审计结果 `evidence/artifact_binding_audit.json`。

---

## 已知局限（长期挂账）

- 演示视频组合态一屏为录制时旧表述（47/47），与材料头条 45/47 不一致，已登记为待整改项（重剪该屏或替换为真实录屏）。
- xadv 三态最弱类别均为多轮钓鱼（0.667 / 0.556 / 0.111）；样本量小（主集 47 题 + xadv 15 题），结论为 MVP 级实证。

> 注：本文件早期条目的具体提交日期与硬指标均可在 `evidence/*.json`、`proofs/*.yaml` 与 `git log` 中回溯核对；本文件不替代证据本身。
