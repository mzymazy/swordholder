# 先行工作声明（Prior work declaration）

本文件用于在**周末研究类赛事**（如 Apart Research Sprint、黑客松）中明确「哪部分是本项目此前已有的，哪部分是赛事期间新增的」。所有提交的报告与 README 都引用本文件，避免把既有工作包装成新成果。

- 仓库：https://github.com/mzymazy/swordholder
- 首次提交：2026-10-15
- 本文件最近更新：2026-11-07（对应 commit `4698d1d` 之后的治理补齐）

---

## 1. 赛事开始前已存在（preexisting，不得计为当次新增）

以下能力在本仓库公开历史中可查，均早于任何 2026-11 之后开始的赛事：

| 领域 | 既有内容 | 可核查位置 |
|---|---|---|
| 凭证与验签 | `keygen` / `seal` / `verify` / `triage`，ed25519 签名、`seal.schema.json` 版本化（seal_version 1.0）、fail-closed 校验 | `swordholder/`、`deliverable/README-reviewer.md` |
| 防重放与换钥 | `seal --challenge` / `verify --expect-challenge`、信任锚轮换（窗口 / retire / revoke / 体检） | `docs/key-rotation.md`、`docs/proof-issuance.md` |
| 策略与不变量 | `policy/default-soc-triage.yaml` v3，含 I3「动作不得削弱」不变量（11 条 deny_patterns 四组 + 授权票据核验豁免） | `swordholder/policy/`、`tests/test_invariant_actions.py`（33 项） |
| 会话层不变量 | S7「口头授权不作放宽依据」 | `tests/`、CHANGELOG 0.7.1 |
| 归因相关 | 归因层拆分与配对归因的行为钉子 | `tests/test_attribution_layer_split.py`、`tests/test_paired_attribution.py` |
| 对抗自测 | 验证器对抗用例 17 项（伪造 / 篡改 / 重放 / 降级 / 换钥 / 重复顶层键） | `evidence/adversarial_verifier_test.py` |
| 安全性质断言 | 57 条断言、CI 门禁三件套 | `tests/test_worldclass_hardening.py`、`scripts/worldclass_probe.py`、`.github/workflows/security-hardening.yml` |
| 工件与绑定 | 原始响应 → 逐题记录 → 证据聚合 → 摘要绑定 → 签名 → 信任锚，全链路可复算 | `evidence/`、`docs/architecture.md` |
| 分发形态 | pyproject / wheel / Dockerfile / MCP server（`verify_proof` `seal_record` `verify_seal` `list_trusted_keys` `keygen`） | `pyproject.toml`、`Dockerfile`、`mcp_server/` |
| 治理 | GOVERNANCE / SECURITY / CONTRIBUTING / CODE_OF_CONDUCT / ROADMAP / CITATION | 仓库根目录 |

测试规模基线：`pytest -q` 实测 **281 passed**（由 CI 现算并与 README 声明比对）。

---

## 2. 赛事期间的新增（per-event delta）

每次参赛时，在该赛事目录或报告附录中单独列出：

```
赛事：<名称> <日期>
本仓库提交基线：<commit sha>
赛事期间新增：(1) ... (2) ... (3) ...
复用但未改动的既有能力：见 §1
```

判定口径：

- **新增** = 赛事窗口内首次提交到本仓库、且不在 §1 清单中的代码、数据、实验或分析
- **复用** = 直接调用 §1 能力，未修改
- **修改** = 对 §1 能力的改动，需说明改了什么、为什么必须改

---

## 3. 约束自述

1. 既有能力不重复计分：报告中的"我们构建了 X"仅当 X 属本次新增时才这样写，否则写"复用既有 X（见 §1）"。
2. 未跑通的结果不写进结论：真模型实验未复现的，标注 `未复现`。
3. 对照组与误伤率必须同时给：只有成功率、没有误伤计数的结论不对外。
4. AI 辅助已在 `docs/aigc-disclosure.md` 与本文件所在仓库各 Markdown 头标识中声明。

---

## 4. 与赛事规则的对齐

多数周末研究类赛事要求「只评赛事期间的工作，且需明确声明先行工作、在 README 与报告中标注 preexisting 代码」。本文件即该项义务的常设载体；对未要求该声明的赛事，本文件不产生额外义务。
