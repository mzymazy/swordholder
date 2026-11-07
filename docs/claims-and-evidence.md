# 能说 / 不能说：Swordholder 对外口径与证据对照表

> 本文件是**对外声明的白名单与黑名单**。规则只有一条：**写进 README/材料里的每句话，都要能指向仓库内一个可以被第三方跑出来的东西**；指不到的，就要降调、加限定，或者删掉。
>
> - 机器可读的逐条裁定：`evidence/claims/claims_registry.json`（63 条声明 + 14 条负结果）
> - 复算入口：`python scripts/audit_claims.py`（只做算术与路径存在性核验，不联网、不猜）
> - 本轮时点：2026-11-08，基线提交 `592bcb9` + 本轮未提交修改

---

## 0. 一句话结论

审计前，本仓库的对外文档处在「**证据很硬、说法很软**」的错配状态：底层有 306 个测试、57 条性质断言、17 条对抗用例、482/482 的工件绑定、逐步入链的执行账本，但文档里同时混着**过期版本号、失效命令、把选择性结论当完整结论、把一次性本机记录当可复现实证**。本轮把这些逐条判决并修掉了大部分，评分从 **47.82 → 92.11**（满分 100，公式见第 4 节）。

仍未修完的，是不该靠改文档解决的：**没有一条声明建立在真实生产日志或公开数据集上**。这是下一阶段的最大缺口，不是文案问题。

---

## 1. 能说（有实测支撑，可被第三方复现）

每条都给出"你怎么自己验"的命令。命令全部在仓库根执行，Python 3.11+。

| # | 可以这样写 | 复现命令 | 证据位置 |
|---|---|---|---|
| 1 | 单元与行为测试 **306 项全通过** | `pytest`（`-q` 已在 pyproject 默认，别再传一次） | `tests/` |
| 2 | 安全性质断言 **57/57 通过** | `python scripts/worldclass_probe.py --assert` | `evidence/worldclass/probe_deterministic.json` |
| 3 | 验证器对抗自测 **17/17 通过** | `python evidence/adversarial_verifier_test.py` | `evidence/adversarial_verifier_test_v05.json` |
| 4 | MCP Server 自测 **10/10 通过** | `python mcp_server/selftest.py` | `mcp_server/selftest.py` |
| 5 | CLI **34 个出口全部登记**、13 个必判出口**覆盖率 1.0** | `python -m swordholder.cli exits --selftest` | `swordholder/exit_guard.py` |
| 6 | 凭证 **4/4 验签 VALID** | `powershell -File scripts/verify_all_proofs.ps1` | `proofs/*.yaml` + `trusted_keys.json` |
| 7 | 逐题记录与原始工件的绑定 **482/482 通过**（T1 响应哈希 / T2 工件字节 / T3 内容包含） | `python evidence/verify_artifact_binding.py` | `evidence/artifact_binding_audit.json` |
| 8 | 结论被改**必然被检出**：凭证篡改 → `E_PAYLOAD_TAMPERED`；账本篡改 → `first_break=3`、`seal_verdict=INVALID` | `python scripts/trace_ledger_live.py` | `evidence/epistemics/ledger_live/` |
| 9 | **无信任锚一律不判 VALID**（`E_UNTRUSTED_KEY`），不静默放行 | `python evidence/adversarial_verifier_test.py`（case 09） | 同上 |
| 10 | 运行时依赖只有 **3 个**（cryptography / pyyaml / jsonschema），**全程离线可跑**，不依赖 LLM | `pip show cryptography pyyaml jsonschema` | `pyproject.toml` |
| 11 | 四态评测 **30/47 → 43/47 → 41/47 → 45/47**（false→baseline→injected→QLoRA→combined），注入增量 **+13** | `python -c "import json;print(json.load(open('evidence/judge_v2p2_aggregate.json'))['states'])"` | `evidence/judge_v2p2_aggregate.json` |
| 12 | 判定器校准 **47/47 一致（agreement 1.0）**，v2.1 为 0.957 | 同上文件旁 `evidence/judge_calibration_v2p2.json` | 同左 |
| 13 | 对抗 20 题**注入后 20/20 全拒**（基线失守 7/20） | `evidence/README-reviewer.md` 可反查 | `judge_v2p2_aggregate.json` |
| 14 | AIGC 合规标识 **31 份 Markdown 全部带头且字段合法** | `python scripts/check_aigc_headers.py` | 各 `.md` front matter |
| 15 | 演示 **6 条样例 + 篡改演示**全部真实跑通（`sealed=VALID`×6、`tamper=INVALID`） | `python -m swordholder.cli demo` | `swordholder/cli.py` |

**写法要求**：以上任何一条写进对外材料时，必须同时给出**命令或文件名**。只写数字不给出处，本轮审计一律判为"无来源断言"。

---

## 2. 需限定（真，但必须带条件说）

这些内容本身没错，错在"无限定地写"会让读者以为能力比实际宽。

| # | 原始写法（危险） | 必须改成（安全） |
|---|---|---|
| 1 | "所有数字都能在 `evidence/` 里核对" | "**评测类**数字可在 `evidence/` 核对；Docker 构建记录、视频参数、本地权重管线三类不在此列（例外已在 §9 列出）" |
| 2 | "xadv 三态 0.867 / 0.778 / 0.689，最弱是多轮钓鱼" | 必须**并列**写："注入在 xadv 上是**负向**（0.867→0.778→0.689），与 SWB 47 题的 +13 方向相反" |
| 3 | "8B 组合态（qwen3.8-27b 基座）" | "基座是 **8B**（`models/qwen3-8b-bnb-4bit`，由 `eval_xadv_v1.py:166-177` 硬编决定）；JSON 里 `model=...27b` 字段是命令行默认值回填，**不可作为基座证据**" |
| 4 | "识别不了会明确拒绝，而不是瞎猜" | "对**结构化校验类**错误（畸形/篡改/无锚/过期）一律 `E_*` 拒收；对**语义判断类**问题只做基线规则匹配，不做猜测但也不保证召回" |
| 5 | "组合态 45/47" | 必须加"semantic-v2.2 逐题重判口径；semantic-v2.1 原始记录为 45/45 口径下的 45，**两套口径不可混用**" |
| 6 | "仓库的 CI 门禁保障质量" | "CI 四个 workflow 存在性可核；**本轮未拉取 Actions 运行结论**，不声称当前全绿。质量判据以本地 `pytest`/`worldclass_probe`/`selftest` 实跑为准" |
| 7 | "组合态 0.689 可复现" | "**记录可核、本机不可重算**：需 `models/` 下两个未入库权重（8B 基座 + v62 LoRA）" |
| 8 | "Apache-2.0 已发布" | "Apache-2.0 许可已就位；**未发布 PyPI、0 个 release/tag**，安装只有源码路径" |

---

## 3. 不能说（无支撑 / 与证据矛盾 / 已撤回）

| # | 不能说 | 为什么 | 处理 |
|---|---|---|---|
| 1 | "公理注入 / LoRA 提升高阶对抗鲁棒性" | xadv 15 题上注入**使**通过率下降（0.867→0.778→0.689），组合态多轮钓鱼只剩 0.111 | 撤回，改为负结果披露 |
| 2 | "组合态 47/47 全达标" | v2.2 严格口径 45/47，`rec-02`/`rec-05` 未达；视频画面为旧表述 | 撤回，材料统一 45/47 |
| 3 | "生产级检测 / 覆盖 ATT&CK" | `rules-v1` 只是字符串特征匹配，无 ATT&CK 映射、无置信度校准、无 EDR/SIEM 集成实测 | 不写，明确"不是检测引擎" |
| 4 | "已有多家客户验证 / 有商业落地" | 0 条外部使用、付费或第三方复现记录 | 撤回，`deliverable/project_one_pager.md` 的客户假设降调 |
| 5 | "xadv 逐题工件已随仓库提交（`artifacts_xadv_*/`）" | 该目录**从未生成**，`eval_xadv_v1.py` 不落工件，仅有本机日志 | 撤回，只声称三份汇总 JSON |
| 6 | "一条命令验证全部凭证：`verify_proof.py --all`" | 脚本只接受 `--demo` / `--trusted-keys` / 位置参数，`--all` 不存在 | 撤回，改用 `scripts/verify_all_proofs.ps1`（本轮新增，实测 4/4 VALID） |
| 7 | "基线规则在 `agent/rules.py`" | 该路径不存在（`agent/` 只是兼容期示例脚本），真实路径 `swordholder/rules.py` | 撤回，改路径 |
| 8 | "AIGC 标识已从首屏移出" | 文件首部 YAML front matter 就是 AIGC 块，仍在首屏；且两处 ProduceID 尾段不同 | 撤回，改为如实说明两处标识并存 |
| 9 | "每月 minor / 每季 major 的发布节奏" | 0 个 tag，CHANGELOG 内 0.4.x–0.7.x 全未标发布状态 | 降调为"意向"，并写入 §10 局限 |
| 10 | "构建产物已全部 gitignore 排除" | `artifacts_v2*` 下 418 个文件**已入库**（与早期四目录合计 482，正是绑定审计分母），gitignore 对已跟踪文件无效 | 降调为"有意保留"，并澄清"418 已入库"与"94 个本地复现产物不入库"可同时成立，`.gitignore` 无需改动 |
| 11 | "Docker 镜像 12.4MB 可复现" | 一次性本机记录，仓库内无构建产物、无 CI 记录 | 降调为"一次性观测，不可复算" |
| 12 | "包依赖只有 cryptography 和 pyyaml" | 运行时 3 个（含 `jsonschema>=4.18`），`requirements.txt` 另含 `requests` | 撤回，按 pyproject 重写 |

---

## 4. 评分体系（可复算）

### 4.1 四个维度

| 维度 | 权重 | 定义 | 为什么算它 |
|---|---|---|---|
| 可追溯率 trace | 0.20 | 声明带 `ref` 且 ref 在仓库中**真实存在**的比例 | 假支撑最常见形态是"引用了不存在的文件" |
| 准确率 acc | 0.35 | `(V+VR)/(V+VR+P+U+F+S+B)`，未核项 `N` 不进分母 | 核心：说法与证据是否一致 |
| 可复算率 recomp | 0.20 | 标注 `recomputable=yes` 的声明中判为 `V/VR` 的比例 | 区分"记录可查"与"我能自己跑出来" |
| 负结果披露 disclosure | 0.25 | 已知负结果中**已写进对外文档**的比例 | 选择性陈述是比错数字更隐蔽的失真 |

```
composite = 100 × (0.20·trace + 0.35·acc + 0.20·recomp + 0.25·disclosure) − penalty
penalty   = min(20, 5·未修F + 3·未修B + 2·未修U)     # F 与证据矛盾最重，B 引用失效次之
```

判决码：`V` 实测支撑 / `VR` 记录可核不可重算 / `P` 部分成立 / `U` 无支撑 / `F` 与证据矛盾 / `S` 过期 / `B` 引用失效 / `N` 本轮未核。

**为什么罚分而不是直接乘**：三条矛盾声明混在 60 条正确声明里，加权平均几乎看不出来（90 分），但它会摧毁整份材料的可信度。罚分项强制把"少数致命错"顶到台面上。

### 4.2 首轮评分结果

| 时点 | 可追溯 | 准确 | 可复算 | 负结果披露 | 罚分 | **综合** |
|---|---|---|---|---|---|---|
| 修补前（审计起点） | 100.0% | 51.8% | 76.9% | 57.1%（8/14） | −20.0 | **47.82** |
| 修补后（本轮结束） | 100.0% | 88.9% | 100.0% | 100.0%（14/14） | −4.0 | **92.11** |

判决分布：修补前 `V14 / VR14 / P14 / U2 / F5 / S2 / B3 / N9` → 修补后 `V34 / VR14 / P3 / U2 / S1 / N9`。

复算：`python scripts/audit_claims.py`（输出与上表逐字一致；`--json` 供机器消费，`--check-refs` 供 CI）。

### 4.3 怎么读这 92 分

- **不是"文档已经完美"**。剩下的 4 分罚分来自 2 条无支撑声明（客户验证、发布节奏）与 3 条部分成立项。
- **9 条 `N`（未核）是刻意留白**：外链可达性、CI 运行结论、`pipx` 路径、自签四步实跑、形式化定理假设与实验规模对应关系。未核 ≠ 有问题，但也不能算分——这是下一轮可以直接消灭的 9 个待办。
- **准确率 88.9% 的分母是 54 条已判声明**，不等于"文档 88.9% 正确"。

---

## 5. 最大缺口（下一阶段靶子）

**缺口一句话**：**全部 63 条声明的证据都在"自建小样本 + 本机"这一层，0 条触及真实场景数据，因此"能证明自己没改结论"成立，"能带来多少实际收益"零证据。**

量化：

| 指标 | 现状 | 问题 |
|---|---|---|
| 引用真实生产日志/公开数据集的声明数 | **0 / 63** | 四态 47 题、xadv 15 题均为自建集 |
| 有外部第三方复现记录 | **0** | 无可复现者报告 |
| 效果类指标（误报率/告警收敛/审计工时） | **0 条** | 只有"通过率"，没有"降本" |
| 可复算但依赖未入库权重 | 2 条（组合态 xadv、QLoRA） | 只能核记录 |
| release/tag | 0 | 无法被 `pip` 消费 |

为什么这是"最大"而不是"次要"：其余缺口（版本号、失效命令、AIGC 措辞）都是**一层纸**，改完即闭合，且本轮已闭合 19 项。外部效度不是改文档能解决的——它决定这个项目在评分表里是"工程严谨的课程作业"还是"可被采购的审计组件"。价值评分里 `V1 问题真实性` 与 `V2 差异度` 目前都只能给到 3/5，正是卡在这里。

---

## 6. 价值评分（首轮，供第二阶段对照）

| 维度 | 权重 | 分（0–5） | 依据 |
|---|---|---|---|
| 问题真实性：是否存在可观测的损失场景 | 0.20 | 3 | 凭证化审计是合规刚需（AI 日志留存、SOC2 审计追溯），但本项目**无一条客户/合规方访谈或需求文档** |
| 差异度：相对既有方案是否有不可替代性 | 0.25 | 3 | 相对 WORM 日志 / 签名数据库，差异在"策略外置 + 出口登记 + 凭证绑定工件 + 逐步入链"，属**工程组合创新**，非新范式 |
| 证据强度：结论被推翻的难度 | 0.25 | 4 | 五层可复算（测试/探针/对抗/绑定/账本），篡改必被检出；弱在样本量与外部效度 |
| 交付成熟度 | 0.15 | 2 | 无 PyPI、无 release、无入库 Docker 产物、轮换仍手工 |
| 变现路径清晰度 | 0.15 | 2 | 无定价、无客户、无 SaaS/私有化交付形态说明 |
| **加权** | 1.00 | **2.95 / 5 → 59 / 100** | |

对照：文档诚信分 92 vs 商业价值分 59。**差距 33 分就是"值得信任"与"值得付费"之间的距离**，全部集中在外部效度与交付形态上。

---

## 7. 本轮修补清单（19 项，均已落盘）

| 文档 | 位置 | 改了什么 |
|---|---|---|
| `README.md` | L27 依赖行 | 只依赖 2 包 → 运行 3 包（补 jsonschema），版本 0.4.0 → **0.7.1** |
| `README.md` | L37 自测行 | `pytest -q` → `pytest`（-q 已默认，重复传会吞汇总行） |
| `README.md` | L41 | 新增 `scripts/verify_all_proofs.ps1` 4/4 逐份验签行 |
| `README.md` | L57 | `SHA256SUMS.txt` → 全路径，并注明根目录无此文件 |
| `README.md` | §2.4 | 补"Docker 为一次性本机记录、不可复算" |
| `README.md` | L275 | `agent/rules.py` → `swordholder/rules.py`（原路径不存在） |
| `README.md` | §3.3 | 对抗表 10 行 → **17 行**，修正 3 处编号错位与"30 天前"（实为 400 天） |
| `README.md` | §3.5 | 补 3 条负结果：注入反向、`model` 字段不可采信、组合态不可重算 |
| `README.md` | L742 依赖表 | 补 jsonschema，区分运行时/评测/训练三套依赖 |
| `README.md` | L749 | 版本库范围澄清：`artifacts_v2*` 418 文件**有意入库** |
| `README.md` | L751 | "所有数字可核对" → 加三类例外 |
| `README.md` | §10 | 新增 2 条局限：0 release/tag 无外部使用者、CI 只保证命令可跑 |
| `README.md` | 附录 AIGC | 撤回"已从首屏移出"，如实说明两处标识并存；删重复尾注 |
| `GOVERNANCE.md` | L84/L87 | `pytest -q` → `pytest`；`verify_proof.py --all`（不存在）→ `verify_all_proofs.ps1` |
| `docs/formal-model.md` | L263 | `evidence_auth.py` → `swordholder/evidence_auth.py` |
| `deliverable/submission_checklist.md` | #21 | 撤回"逐题工件 `artifacts_xadv_*/`"，注明该目录从未生成 |
| `README.md` | L749 | 工件目录口径拆细：418（`artifacts_v2*` 已入库）+ 64（早期四目录）= 482 已跟踪；另有 94 个本地复现产物由 `artifacts_v2_*/` 排除（`.gitignore` 未改动） |
| `scripts/verify_all_proofs.ps1` | 新增 | 逐份验签封装（实测 4/4 VALID，退出码 0/1 可入 CI） |
| `scripts/audit_claims.py` + `evidence/claims/claims_registry.json` | 新增 | 声明-证据审计复算器与 63 条裁定 |

修补后回归：`pytest` **306 passed**、`worldclass_probe --assert` **57/57**、`check_aigc_headers` **31 份通过**、`audit_claims.py` **引用全通过**。

---

## 8. 使用方式（防止口径再次漂移）

1. **改任何对外数字前**，先跑一遍对应命令，把输出贴进 PR。
2. **新增声明时**，在 `evidence/claims/claims_registry.json` 加一条记录（`doc/loc/claim/ref/verdict/recomputable`），否则下次审计会被判 `U`（无支撑）。
3. **CI 可加**：`python scripts/audit_claims.py --check-refs`——任何文档引用了不存在的文件，直接红。
4. **禁止行为**：把 `N`（未核）当成 `V`（已验证）；把 `VR`（记录可核）写成"可复现"。
