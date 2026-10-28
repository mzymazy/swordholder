---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a69ba5d0c99f11f1acd7525400cd780f
    ReservedCode1: sCC3lW1tgDm+8A85K6AnJjsCzKKcNXkc/Kv7fkO0Fo8hcd0FBimxruCxLkCgcCL+Dl+9hJDXypOx3OeYVi2ulLCLOlzwi5aKLt9HdZ8M3FOvOJwM7jZ19yJgdPzSbalVPmtXXpvecgejXC/YNxIQVqclvhfa/fzgQ3CSaATX87YERcN1pFryX/HAh6Y=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a69ba5d0c99f11f1acd7525400cd780f
    ReservedCode2: sCC3lW1tgDm+8A85K6AnJjsCzKKcNXkc/Kv7fkO0Fo8hcd0FBimxruCxLkCgcCL+Dl+9hJDXypOx3OeYVi2ulLCLOlzwi5aKLt9HdZ8M3FOvOJwM7jZ19yJgdPzSbalVPmtXXpvecgejXC/YNxIQVqclvhfa/fzgQ3CSaATX87YERcN1pFryX/HAh6Y=
---

# 变更日志（CHANGELOG）

本文件记录**对外可观察的变更**：版本、证据链、判定器口径与仓库治理。数字口径的权威来源始终是仓库内 `evidence/*.json` 与 `proofs/*.yaml`，本文件只做索引式记录。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号对应材料版本（`materials_version`）。

---

## [v0.4.0] — 信任治理：密钥轮换、吊销与轮换体检

### 新增（Added）

- `swordholder/trust.py`：**信任锚治理**，把"白名单"升级成能过审计的密钥生命周期管理。
  - `add_key` / `retire_key`：登记新锚、停用旧锚；停用只影响"之后还能不能签"，历史凭证继续有效。
  - `revoke_key` / `revoke_seal` / `restore_seal`：密钥级与单份凭证级吊销，吊销优先于一切窗口判定。
  - `evaluate`：统一信任判定，返回 `(trust, reason, key_id, key_status)` 四元组。
  - `summary` / `check_rotation`：锚状态总览与轮换体检（缺锚、无 active 锚、active 并存、retired 缺窗口、轮换链断点）。
- **按凭证签发时刻判窗口**：用 `seal_header.created_at` 与 `not_before` / `not_after` 比对，而不是按验签时刻。轮换后历史凭证不会因为"签发它的钥已过期"而失效；`created_at` 在签名覆盖范围内，改它必然 `E_BAD_SIGNATURE`，时间线不可伪造。
- 新增判定口径：`E_KEY_REVOKED` / `E_SEAL_REVOKED` / `E_KEY_EXPIRED` / `E_KEY_NOT_YET_VALID` / `E_SEAL_NO_TIMESTAMP`，均判 `INVALID`；`VALID_UNTRUSTED_KEY` 专用于"签名没问题但签发方不受信"。
- CLI 新增 `trust` 子命令组：`show`（人读表格 / `--json` 机读）、`check`（有问题时退出码 2）、`add`、`retire`、`revoke`（`--key` / `--seal` 强制二选一）、`restore`。
- HTTP 新增 `GET /v1/trust`：锚概览 + 吊销列表 + 轮换提醒，需鉴权，不回显私钥与锚文件绝对路径。
- `docs/key-rotation.md`：轮换实操手册（文件格式、四种操作、判定矩阵、体检项、完整轮换时序、与 `verify_proof.py` 的分工）。
- 测试：新增 `tests/test_trust.py`，全量 **61 项 pytest 通过**（原 36 项）。

### 变更（Changed）

- 版本号 `0.3.0` → `0.4.0`；`swordholder.__init__` 导出 `trust` / `TrustError` / `add_key` / `retire_key` / `revoke_key` / `revoke_seal` / `restore_seal` / `summary` / `check_rotation` / `evaluate`。
- `verify` 的结果在原有字段基础上追加 `key_id` / `key_status` / `trust`；MCP 的 `verify_seal` 同步采用新策略，并保留旧白名单回退路径。
- `list_trusted_keys` 优先返回结构化视图（`by_status` / `revoked` / 每把钥的运行时 `state`）。

### 兼容（Compatibility）

- **老锚文件原样可读**：0.1–0.3 的 `{"keys":[{"public_key":"..."}]}` 不需要改写，缺 `status` 视为 `active`、无窗口；历史凭证不需要重签。
- 维护锚文件时保留未知字段（如自定义 `trust_root`、工单号），不做清洗。

### 未变更（Unchanged）

- 盖章与验签的密码学口径（ed25519 + `json-c14n-v1` + 域分隔前缀）一行未改。
- `verify_proof.py` 仍是独立基线验证器，只做签名 + 锚白名单 + 新鲜度，不实现轮换窗口与吊销策略（分工见 `docs/key-rotation.md` 第 8 节）。

---

## [v0.3.0] — 商品化：多源告警、HTTP 服务与凭证检索

### 新增（Added）

- `swordholder/alert.py` + `alert.schema.json`：**多源告警归一**，支持 `generic / splunk / sentinel / wazuh` 四种来源与自动识别；归一后为内部契约（`schema_version` / `alert_id` / `severity` / `source.format` / `source.raw_sha256`），**原始日志只留 SHA-256 哈希，原文不进凭证**，避免把日志中的凭据、内网地址签进证据链。
- `swordholder/store.py`：**SQLite 凭证索引**（线程安全），支持按结论 / 资产 / 时间 / 内容哈希检索，只存路径与关键字段，不复制凭证正文。
- `swordholder/serve.py`：**HTTP 服务**（`ThreadingHTTPServer`），路由 `/healthz`、`/v1/schema`、`/v1/triage`、`/v1/seals`、`/v1/seals/{id}`、`/v1/verify`；沿用 fail-closed 验签（无信任锚不判 `VALID`）。
- `swordholder/core.py::triage_event`：归一 → 分诊 → 结论附带 `input` 区块（身份字段 + 原始哈希）与 `schema_version`；新增 `payload_sha256()`，与盖章 header 使用**同一 c14n 算法**。
- CLI 新增子命令：`triage -`（stdin 管道）、`--format`、`--db`、`query`、`schema`、`serve`；错误一律输出结构化 JSON（`E_BAD_JSON` / `E_NOT_FOUND` / `E_ALERT_INVALID` / `E_SEAL_FAILED`）并给非零退出码。
- 样例告警扩到 6 条（新增 Splunk / Sentinel / Wazuh 各 1 条原生格式）。
- 测试：新增 `tests/test_alert.py`、`tests/test_serve.py`，全量 **36 项 pytest 通过**（原 11 项）。

### 变更（Changed）

- 版本号 `0.2.0` → `0.3.0`；`pyproject.toml` 打包包含 `alert.schema.json` 与 `samples/*.json`。
- 服务端盖章文件名改为 `{alert_id}-{payload_sha256[:12]}.seal.json`，并对相同结论**幂等复用**旧凭证（返回 `"reused": true`），防止重复请求刷凭证、撑爆索引、覆盖历史文件。
- HTTP 处理改为**先读完请求体再鉴权**，修掉 Windows 上提前返回 `401` 导致客户端 `ConnectionAbortedError` 的问题。
- `demo` 单条样例畸形不再中断整场演示；`rules.sample_alerts()` 排除 `*.seal.json` / `*.triage.json`，避免把产物当输入。

### 未变更（Unchanged）

- 四态数字口径、`proofs/*.yaml`、`trusted_keys.json`、`deliverable/` 全部**未改动**；`mcp_server` 工具签名保持不变。

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
*（内容由AI生成，仅供参考）*
