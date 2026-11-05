# Roadmap

本文件说明 Swordholder（持剑者）的公开路线图。范围与优先级会随社区反馈调整，调整前会在 issue 中公开讨论。

## 项目定位

给 AI 应用做一次"上线前安全检查"，并出具**机器可验证**的安全凭证：评测证据 → 摘要绑定 → ed25519 签名 → 任何人可独立验签。

## v1.0 — 可安装、可一条命令跑通

- [ ] 发布 PyPI 包 `swordholder`，`pip install swordholder` 后可直接使用 —— **未发**（打包配置与 `pip install -e .` 已可用）
- [x] 统一 CLI —— 已落地，但子命令设计与早期设想不同：`keygen` / `seal` / `verify` / `triage` / `query` / `schema` / `serve` / `trust` / `agent` / `policy` / `exits` / `demo`
- [ ] 提供 Docker 镜像，支持无 Python 环境一键运行 —— 未做
- [ ] 输出机读 JSON + 单页 HTML 报告 + README badge —— 机读 JSON 已有（所有 CLI 均输出 JSON）；HTML 报告与 badge 未做
- [ ] 中英双语 README 首屏 —— 未做
- [x] 30 秒离线闭环 —— `scripts/quickstart.ps1` / `quickstart.sh`（§2.1）

## v1.1 — 接入现有 AI 工程链路

- [x] 提供 MCP server —— `mcp_server/`，工具：`verify_proof` / `seal_record` / `verify_seal` / `list_trusted_keys` / `keygen`
- [ ] GitHub Action：PR 阶段自动跑安全检查，失败即阻断合并 —— 未做（CI 现在只跑 pytest 与出口完整性）
- [~] 支持接入主流推理后端 —— Ollama 已用（`agent` 走本地 `qwen3:8b`）；OpenAI 兼容接口未接
- [ ] 行业题组模板：医疗答疑、教育辅导、客服、政务问答、代码助手 —— 现有 47 题混合集，未按行业拆分

## v1.2 — 证据与治理增强

- [x] **凭证格式规范化（schema 版本化 + 向后兼容策略）** —— `0.7.0`：`seal.schema.json`（draft-07，seal_version 1.0）+ `seal_schema.py` 版本化 fail-closed 校验；已发布版本文件不再修改，新增字段走新版本号
- [x] **验证方挑战（防重放）** —— `0.7.0`：`seal --challenge` / `verify --expect-challenge`；要挑战而未绑定判 `E_CHALLENGE_MISSING`，不降级
- [x] **会话层第 7 条不变量：口头授权不作放宽依据** —— `0.7.1`：`S7_verbal_authorization_never_relaxes` + `authorization` 声明类型；`live` 套件真模型复测 3 用例 × 3 模式 × 3 次，`live-03` 的降级缺口关闭、`live-02` 零误伤
- [~] 支持多签与信任锚轮换流程 —— 轮换（窗口 / retire / revoke / 体检）已完成，见 §「换钥之后」；多签未做
- [x] 评测记录与原始响应工件的绑定审计，纳入 CI 门禁 —— §3.6 三重核验 + CI job
- [~] 失败族与不可修复项的公开登记表 —— README「已知局限」有诚实边界，尚未做成可机读登记表

## v2.0 — 平台化

- [ ] 准入网关：模型/智能体上架前的强制检查点
- [ ] 凭证目录与第三方查验页
- [ ] 企业私有化部署方案（内网离线、数据不出域）

## 不做的事

- 不做通用大模型评测榜单（样本与口径无法自证，且与"准入"定位冲突）
- 不追求 star 数等虚荣指标
- 不接受无法复现的评测结果作为凭证签发依据

## 发布节奏

- 每月一个 minor 版本，每季度一个 major 版本
- 破坏性变更提前一个 minor 版本公告，并保留一个版本的兼容期
- 所有发布必须有 CHANGELOG 条目与对应 tag
