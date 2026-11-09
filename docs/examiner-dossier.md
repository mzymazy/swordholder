# Swordholder 模型说明与验证手册（Examiner Dossier）

> 面向对象：不熟悉本项目、第一次接触代码库的审查者（examiner / 模型验证岗 / 第三方审计）。
> 目标：读完这一册，你应当能回答三个问题——**它做什么、它凭什么说自己有效、它在什么条件下会失效**，
> 并能自己把关键数字跑出来核对一遍。
> 版本：0.9.0（第十一阶段）｜代码库：本仓库根目录｜本册为 SR 11-7 Documentation 要求的成册文档。

---

## 1. 这个系统做什么

一句话：**给 AI 智能体的动作与结论盖章，并让「谁在什么时候改了什么」可被第三方独立发现。**

拆成三层，从下到上：

| 层 | 模块 | 做的事 |
| --- | --- | --- |
| 结论层 | `swordholder/core.py`（`seal` / `verify`） | 把任意 JSON 结论用 ed25519 私钥签成凭证；验证方只需公钥，不需要源码、不需要信任签发方 |
| 动作层 | `swordholder/trace_ledger.py` | 智能体每执行一步追加一条记录，`prev` 指向上一条的哈希，形成前向链接；支持步级锚点（`build_anchors` / `locate_step`）做篡改定位；整条轨迹可 `seal_trace` 成凭证 |
| 留存层 | `swordholder/retention.py` | 按 EU AI Act Art.19/26(6) 的六个月下限做留存期判定（`classify` / `plan`），到期只做**可验证归档**（`archive_record` 写副本并复核链），不提供任何删除接口 |
| 运行期层 | `swordholder/monitor.py` | 部署期按周期扫描轨迹目录，量「链断 / 摘要不符 / 验签失败 / 不可解析 / 失败率」，越阈值出告警；每次量写进**自身也是哈希链**的监控日志 |

配套能力（同一套密钥与验签口径）：
- `swordholder/trust.py`：信任锚治理（密钥轮换窗口、密钥与凭证吊销、轮换体检验）。
- `swordholder/session.py`：会话状态，防止多轮诱导把判定一轮轮「谈」下来。
- `swordholder/agent_loop.py`：判定前置闸门（取证步骤是否齐、证据引用是否真、授权单时间窗是否覆盖）。
- `swordholder/alert.py`：把 Splunk / Sentinel / Wazuh / 自定义告警无损归一，未知格式不猜、直接报错。
- `swordholder/reproduce.py` + `scripts/stage11/external_verify.py`：交付清单与**离线复算**（见第 6 节）。

---

## 2. 它不做什么

写清楚「不做什么」比写「做什么」更重要，因为越界承诺是这类工具最常见的失效方式。

1. **不承诺「不可篡改」，只承诺「改了会被发现」。** 单机单钥方案里，持有私钥的一方可以整链重算再重签：本系统对这种情形只能做到「重签后的历史与已外发凭证对不上」（见探针 P07，判定为 FAIL，属已知缺口）。
2. **不替代外部时间戳或不可写存储。** 锚点目前封在签名凭证内部，而凭证还在被记录方自己的磁盘上；能整体删掉、整体替换。P11 因此判 FAIL。
3. **不做合规认证。** 本系统不签发「符合 EU AI Act / NIST / SR 11-7」的结论，只按条文里的**可执行动词**逐条给出现场实测，并把做不到的写进缺口清单。
4. **不做告警外发。** `monitor` 只写本地观测日志，不接 PagerDuty、不发短信、不做值班升级；升级路径由部署方自己的调度与告警体系承担。
5. **不是常驻守护进程。** `monitor` 是库 + CLI，由部署方用 cron / 计划任务 / systemd timer 按周期调用（第 7 节给示例）。
6. **不做删除。** 留存层刻意不暴露 `delete / purge / prune / shred` 类接口；归档只写副本，不动源文件（tests 里有断言）。
7. **不判断结论是否正确。** 它证明「这段话是谁说的、说完有没有被改」，不证明「这段话在业务上是对是错」。

---

## 3. 关键假设

审查者需要知道：本系统的安全结论**在什么前提下**成立。

| 编号 | 假设 | 不成立会怎样 |
| --- | --- | --- |
| A1 | 验证方拿到的是**可信的公钥**（通过带外渠道，或 `trusted_keys.json` + 信任锚治理流程） | 公钥被换掉后，攻击者可自签自验，全部验证结论失效 |
| A2 | ed25519 私钥不离开签发侧，且签发侧主机未被完全接管 | 私钥泄露后，任何人都能生成「看起来合法」的新凭证 |
| A3 | 追踪的记录范围等于**经由本库写入**的那部分动作；绕过本库直接调工具的动作不会被记录 | 覆盖率被高估，日志看起来干净但不完整 |
| A4 | 哈希函数（SHA-256）抗碰撞；`entry_hash` 的 canonical JSON 序列化在跨语言实现时保持一致 | 第三方复算结果不一致，或碰撞可构造 |
| A5 | 留存期判定的「现在」由调用方传入（`now`），系统不偷偷用本机时钟 | 时钟被回拨时留存期判定会被操纵 |
| A6 | `monitor` 的阈值是部署方按自身风险偏好设定的，不是本系统推荐值 | 「无告警」被误读为「无风险」 |
| A7 | 复算依赖的 Python 版本与依赖版本与清单一致（清单里有记录）；核心库仅依赖 `cryptography` | 跨版本浮点/序列化差异导致摘要不一致（正文类判定不受影响） |

---

## 4. 已知局限

诚实清单，逐条对应可复核的证据位置，不用「架构上支持」「后续可扩展」这类措辞遮掩。

| 编号 | 局限 | 现状证据 | 影响 |
| --- | --- | --- | --- |
| L1 | 仅有 tamper-evident（发现篡改），无 tamper 意义上的绝对防护；重签能力在持有私钥一方手上 | 探针 P07 = FAIL | 内部人整链重写无法在单机内自证 |
| L2 | 锚点未离开被记录方介质，无外部时间戳、无 WORM 存储 | 探针 P11 = FAIL | 「连证据一起处理掉」这条路径未封死 |
| L3 | 事件分类的完备性靠策略包枚举，未做行业事件字典的全覆盖 | 探针 P03 = PARTIAL | 新型事件可能落到兜底类别，粒度不足 |
| L4 | `monitor` 无常驻进程、无告警外发、无跨机聚合 | 探针 P09 证据字段 | 单机部署可用，多机需部署方自aggregation |
| L5 | 归档只做「副本可验证」，不做介质级不可写（对象锁 / 一次写多次读） | `retention.archive_record` + tests | 归档目录被整体删除时无法阻止 |
| L6 | 覆盖判定依赖条文原文可公开核引；ISO/IEC 42001 正文为付费标准（官网脚本访问 403），本项目**不判定**其条款 | 第九阶段缺口记录 | 该标准维度留空而非填「满足」 |
| L7 | 单机性能：`verify_chain` 为 O(n) 逐条复算，百万步轨迹需分段（锚点已支持分段定位） | `build_anchors` / `locate_step` | 超长轨迹需调用方配合分段 |

---

## 5. 验证与实测证据

判定口径只有三档，且**没有「基本满足」**：

- **PASS**：条文原文 + 可复跑实测数字直接对应条文里的动词；
- **PARTIAL**：能力存在但缺机制或需上层自建约定，必须写明缺哪一半；
- **FAIL**：探针实测做不到。

当前（第十一阶段，v0.9.0）12 条探针结果：**PASS 9 / PARTIAL 1 / FAIL 2**。原始数据：`evidence/stage11/s11_probes.json`。

| 探针 | 条文 / 断言 | 结果 | 关键实测 |
| --- | --- | --- | --- |
| P01 | EU AI Act Art.12(1) 自动记录 | PASS | 20 步全部由 `append` 自动生成 prev/hash，第三方独立重算 20/20 一致，调用方零次手写哈希 |
| P02 | Art.12(1) / Recital 71 「over the lifetime」 | PASS | 子进程 `TraceLedger.load` 恢复 10 步→追加第 11 步→落盘，主进程复验链自洽且第 10 步头部未变；被改历史被拒（`E_TRACE_LOAD_BROKEN`） |
| P03 | Art.12(2)(a)(b)(c) 记录内容粒度 | PARTIAL | 动作/输入/观察/时间已记录，事件分类靠策略包枚举，未覆盖行业事件字典全集 |
| P04 | Art.12(3) Annex III 1(a) 必备字段 | PASS | 缺 `db_ref`/`identity_check`/`matched_input`/`period` 拒写，错误码分别可复现；篡改任一步骤 `first_break` 精确定位 |
| P05 | Art.19(1) / Art.26(6) 留存 ≥6 个月 | PASS | `MIN_RETENTION_DAYS=183`，策略低于下限抛 `E_RETENTION_BELOW_FLOOR`；归档只写副本且可验 |
| P06 | Art.73(6) 严重事件取证保全 | PASS | 凭证封存后 `seal_verdict=INVALID` 可判定，篡改定位 `segment=[1,1]` |
| P07 | NIST AI 600-1 MS-2.8-003 历史不可篡改 | FAIL | 见 L1：单机单钥下重签无法自证（主动披露） |
| P08 | NIST AI 600-1 MS-2.7-005 误报/漏报评估 | PASS | 已入库评估数据可复算检出/误报计数 |
| P09 | NIST AI RMF 1.0 MEASURE 3.1 部署期持续跟踪 | PASS | 首轮 4/4 通过无告警；改一个观察值后下一轮报 `E_MON_CHAIN_BREAK`(critical)；跨进程 CLI 第三次扫描日志链接续成功；监控日志被改后拒写（`E_MON_LOG_BROKEN`） |
| P10 | SR 11-7 Documentation（p.21） | PASS | 本册：章节齐备、零处「不可篡改」越界自称、引用探针证据与复算脚本 |
| P11 | Art.73(6) + Art.19 外部锚定 / WORM | FAIL | 见 L2：`external_timestamp=false`、`worm_storage=false` |
| P12 | 交付断言 S11-01 外部可复现 | PASS | `python -I external_verify.py` 在隔离模式离线复算：干净树 exit=0；追加一个字节 exit≠0 且列出 mismatched；分档与 `expected` 不符同样 exit≠0 |

复跑命令（PowerShell，仓库根目录）：

```powershell
.venv\Scripts\python.exe scripts\stage11\compliance_probe.py --out evidence\stage11\s11_probes.json
```

输出会逐行打印 `P01..P12` 的分档与 `counts`；JSON 里每条探针都带 `evidence`（数字与代码事实）与 `note`（为什么是这个档）。

---

## 6. 外部复跑

**目标**：第三方在**无网络、不安装本包**的条件下，验证交付树没被改过，并核对分档数字。

三条命令，顺序执行：

```powershell
# 1) 复跑探针，得到实测分档与计数
.venv\Scripts\python.exe scripts\stage11\compliance_probe.py `
  --out evidence\stage11\s11_probes.json `
  --counts-out evidence\stage11\s11_probes_counts.json

# 2) 生成交付清单（逐文件哈希 + 环境 + 期望分档）
.venv\Scripts\python.exe scripts\stage11\build_manifest.py `
  --root . --probes evidence\stage11\s11_probes.json --out evidence\stage11\s11_manifest.json

# 3) 外部视角复算（只用标准库，-I 隔离模式）
python -I scripts\stage11\external_verify.py `
  --manifest evidence\stage11\s11_manifest.json `
  --root . `
  --actual evidence\stage11\s11_probes_counts.json `
  --json-out evidence\stage11\s11_external_verify.json
```

第 3 步做三件事：

1. 逐文件重算 `sha256`，与清单比对，输出 `missing` / `mismatched` 明细；
2. 重算整树摘要 `tree_digest`（排序后的 `路径\0哈希` 串联再哈希），改一个字节或挪一个文件都会变；
3. 把清单里的 `expected`（期望分档与计数）与 `--actual`（本次实测）逐项比对，不一致即 `exit=1`。

因此「我这边数字不一样，但结论照旧通过」这条路是堵死的：**分档是清单的一部分，不是报告的一部分**。

脚本自身约束：`scripts/stage11/external_verify.py` 只 import 标准库（探针 P12 用 AST 检查真实 import，而不是 grep 注释）；它不是「再跑一次被测代码」，而是「用另一条实现复算同一批哈希」。

---

## 7. 部署期持续跟踪（怎么接）

`monitor` 的部署形态是「调度器 + 一次扫描」，不是常驻服务。

```powershell
# 单次扫描（写 <dir>\monitor_log.jsonl）
python -m swordholder.monitor scan --dir D:\agent\traces

# 连续三轮，间隔 60 秒（演示 / 补数据用）
python -m swordholder.monitor scan --dir D:\agent\traces --cycles 3 --interval 60

# 汇总最近 50 次观测
python -m swordholder.monitor report --dir D:\agent\traces --last 50

# 校验监控日志自身没被改
python -m swordholder.monitor verify-log --log D:\agent\traces\monitor_log.jsonl
```

Windows 计划任务示例（每 15 分钟一次）：

```powershell
schtasks /create /tn "Swordholder Monitor" /sc minute /mo 15 /tr ^
  "C:\path\to\.venv\Scripts\python.exe -m swordholder.monitor scan --dir D:\agent\traces"
```

告警项与默认阈值（部署方可改，未知阈值键会直接报 `E_MON_THRESHOLD_UNKNOWN`，防止拼错后静默失效）：

| 代码 | 级别 | 触发条件 |
| --- | --- | --- |
| `E_MON_CHAIN_BREAK` | critical | 链断文件数 > 0 |
| `E_MON_DIGEST_MISMATCH` | high | 摘要与重算值不一致 > 0 |
| `E_MON_SEAL_INVALID` | high | 已签轨迹验签失败 > 0 |
| `E_MON_UNREADABLE` | medium | 不可解析文件数 > 0 |
| `E_MON_ERROR_RATE` | medium | 失败率 > 0.05 |

监控日志本身是哈希链：删一条、改一条、插一条都会被 `verify_log` 指到具体行号；日志不可信时 `scan_once` 直接拒写（`E_MON_LOG_BROKEN`），避免在脏历史上继续盖新章。

---

## 7.5 Art.12(2) 用途级风险字段：怎么按用途筛（S12 新增）

轨迹默认只记「做了什么」（`action / args / observation / ts`）。监管报送场景常被问的是
「哪些记录属于风险识别，严重度多高」——这类问题在默认口径下只能人工读日志。

声明 `profile="art12-2"` 后，条目内建四个字段并**进入哈希链**：

| 字段 | 取值 | 对应条文 |
| --- | --- | --- |
| `purpose` | `risk_identification` / `post_market_monitoring` / `deployer_evaluation` | Art.12(2)(a) / (b) / (c) |
| `event_type` | 自由字符串（事件类型） | 同上 |
| `severity` | `info` / `low` / `medium` / `high` / `critical`（有序） | 同上 |
| `risk_flag` | 布尔 | 同上 |
| `monitor_tag` | 可选自由标签 | — |

- 缺任一项**拒写**，错误码逐项可辨（`E_ART12_2_*_MISSING`）；非法取值拒写
  （`E_ART12_2_PURPOSE_INVALID` / `E_ART12_2_SEVERITY_INVALID`）。
- 审计方直接筛：`select_entries(body, purpose=...)` / `min_severity="high"` / `risk_flag=True`；
  汇总：`risk_summary(body)` 给 `total / risk_flagged / unclassified / by_severity / by_purpose`。
- **默认口径不变**：不声明档位时条目键集合与 0.9.0 逐字节一致，历史轨迹照旧可验。

**边界**：库只保证"写了就进链、缺了拒写、能按值筛出来"，**不替部署方定义严重度评级标准**。
什么算 `high` 是部署方策略层的事，审查时应索取该策略文件。

---

## 7.6 外部时间戳：证明「这个时刻已存在」，不证明「没有被整册重做」（S12 新增）

签名只能说明"谁用某把私钥签的"，说明不了时间：持钥者今天补签，验签方无从分辨。
接入 RFC 3161 TSA 后，摘要被交给独立第三方签一份含 `genTime` 的 `TSTInfo`，此后任何人
可**离线**验证「这个 digest 在 genTime 之前已存在」——要伪造得攻破 TSA 私钥。

- 实现：`swordholder/timestamp.py`（DER 自写、零第三方依赖）。校验项：messageImprint、
  nonce 回环、CMS 签名（signedAttrs 的 DER 重算）、`messageDigest`、`signingCertificateV2`
  的 ESSCertIDv2 绑定、证书有效期、可选证书链。
- 凭证层：`seal_trace(..., timestamp_url=..., timestamp_roots=...)` 先签后取戳、戳原子写回同一凭证；
  `verify_sealed_trace(..., require_external_timestamp=True)` 缺戳即 `INVALID`（`E_TRACE_TSA_ABSENT`）。
- 实测：真实取到公开 TSA 的时间戳（`gen_time` 为实测值），离线复核 CMS 签名与证书链通过；
  未打戳凭证在严格口径下被拒。

**做不到的那一半（请据此判断，不要按"已解决"理解）**：持钥者改写某一步 → 重算整链 →
重签 → **重打一枚新戳**，校验仍判 `VALID`。因为没有任何第三方留存首枚戳值，也没有 WORM 副本。
外部时间戳只承诺"该摘要在该时刻存在"，不承诺"这是唯一的一份"。要闭合需要
append-only 透明日志或第三方存证机构留存首戳（G4a），以及不可改写存储（G4b）。二者均未接入。

---

## 8. 术语表

| 术语 | 含义 |
| --- | --- |
| tamper-evident | 篡改**可被发现**。本项目的能力边界 |
| tamper 类绝对防护 | 篡改**不可能发生**。本项目**不承诺**（见 L1 / P07） |
| 轨迹体（body） | 一条轨迹的 JSON：`trace_id / actor / start_ts / step_count / head / entries` |
| head | 最后一条记录的哈希，等价于「当前状态的指纹」 |
| GENESIS | 链起点的零哈希常量，`entry_hash` 的第一个 `prev` |
| body_digest | 对 `(trace_id, step_count, head, profile)` 的摘要，防止把档位/步数悄悄换掉 |
| 步级锚点（anchor） | 每隔 stride 步记一个中间哈希，用于把篡改定位到区间而非整链 |
| 封存（seal） | 用 ed25519 对 `body_digest` 签名，形成可独立验证的凭证 |
| 留存期下限（legal floor） | EU AI Act Art.19/26(6) 要求的六个月，本库取 183 天作为可判定下限 |
| 归档（archive） | 到期后写出**可验证副本**，源文件不动，不提供删除 |
| 记录档位（profile） | `annex3-1a`，表示启用 Annex III 1(a) 必备字段校验 |

---

## 9. 证据索引

| 想核对什么 | 去哪看 |
| --- | --- |
| 12 条探针的原始判定与数字（现行口径） | `evidence/stage12/s12_probes.json` |
| 实测分档的扁平计数（现行，供外部逐项比对） | `evidence/stage12/s12_probes_counts.json` |
| 交付清单（覆盖真实交付树，逐文件哈希 + 环境 + 期望分档） | `evidence/stage12/s12_manifest.json` |
| 外部复算结果（现行） | `evidence/stage12/s12_external_verify.json` |
| 清单生成脚本（stage12 口径） | `scripts/stage12/build_manifest12.py` |
| 上一轮（第十一阶段）探针与清单 | `evidence/stage11/s11_probes.json`、`evidence/stage11/s11_manifest.json` |
| 外部时间戳实现 | `swordholder/timestamp.py`、证据 `evidence/stage12_tsa_fixture.json` |
| 风险字段与外部时间戳边界说明 | `docs/stage12-risk-fields-and-tsa.md` |
| 12 条探针的原始判定与数字（第十一阶段留档） | `evidence/stage11/s11_probes.json` |
| 实测分档的扁平计数（供外部逐项比对） | `evidence/stage11/s11_probes_counts.json` |
| 交付清单（逐文件哈希 + 环境 + 期望分档） | `evidence/stage11/s11_manifest.json` |
| 外部复算结果 | `evidence/stage11/s11_external_verify.json` |
| 探针脚本本体 | `scripts/stage11/compliance_probe.py` |
| 外部复算脚本（仅标准库） | `scripts/stage11/external_verify.py` |
| 清单生成脚本 | `scripts/stage11/build_manifest.py` |
| 轨迹账本实现 | `swordholder/trace_ledger.py` |
| 留存与归档实现 | `swordholder/retention.py` |
| 部署期监控实现 | `swordholder/monitor.py` |
| 可复现清单实现 | `swordholder/reproduce.py` |
| 轨迹层设计说明 | `docs/trace-ledger.md` |
| 合规字段与档位说明 | `docs/stage10-compliance-fields.md` |
| 声明与证据对照表 | `docs/claims-and-evidence.md` |
| 上一阶段（第十阶段）实测快照 | `evidence/stage10/s10_probes.json`、`evidence/stage10/s10_probes_before_ef2203c.json` |
| 单元测试 | `tests/`（`.venv\Scripts\python.exe -m pytest tests -q`） |

---

## 10. 读到这里还应当追问的三件事

给审查者的提问清单，也是本项目当前真正的风险点：

1. **覆盖率**：A3 说只记录经由本库的动作。请索取「工具调用总数 vs 轨迹步数」的对账，而不是看日志有多漂亮。
2. **信任锚来源**：A1 说公钥需带外可信。请核对公钥分发链路；`trusted_keys.json` 是被审方给的，本身就是单点。
3. **L1/L2 的残余风险**：持有私钥的一方仍能重写历史、能连证据一起删。抗内部重做仍是 FAIL，
   外部时间戳只把「外部存在性」补到 PARTIAL——请不要按「已缓解」理解。
4. **首枚戳谁见证**：请索取「TSA 戳值是否被第三方留存」的证据（透明日志 / 存证机构回执）。
   若只有被审方磁盘上的那份凭证，重打一枚新戳仍可掩盖整册重做。
