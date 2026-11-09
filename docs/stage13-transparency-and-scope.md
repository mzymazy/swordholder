# S13：交付范围可核验 + 外部透明日志锚定

本文档说明第十三阶段新增的两项能力，重点在**审计方如何自己动手核对**，而不是复述交付方
的自述。所有结论都能用仓库内脚本 + 一个公开 HTTP 接口重算，不需要信任本文任何一句话。

---

## 一、交付范围：清单是 git 树的确定子集，且"被排除的部分"也被锁死

### 1.1 上一版的残留问题（R1）

stage12 的清单只声明了"我交付了 74 个文件"，并用 `extra.untracked_excluded` 注明有一个文件
被排除。审计方看到的问题是：**为什么是 74 个而不是 75 个？被排除的那一个凭什么被排除？**
判断权在交付方，第三方只能人工比对，这就是"交付范围由交付方自述"。

### 1.2 现在的做法：全仓库分账（scope ledger）

清单的 `extra.scope` 不再是说明文字，而是一份可重算的分账：

| 字段 | 含义 |
| --- | --- |
| `mode` | 分账模式（`tracked`：以 git 索引为全集） |
| `tracked_count` | `git ls-files` 的条目数（全集大小） |
| `declared_count` | 清单 `files` 的数量（= 交付物） |
| `out_of_scope_count` / `out_of_scope_digest` | 仓库内**未纳入交付**的文件数量，及其路径集合摘要 |
| `delivery_digest` | 声明为交付的那些路径的集合摘要 |
| `not_in_repo` | 声明要交付、但 git 里根本没有的路径（应为空） |
| `delivery_missing` | 交付目录下缺失/未跟踪的目标（应为空） |
| `ignored_under_delivery` / `ignored_explained` / `ignored_unexplained` | 交付目录下被 .gitignore 忽略的文件，以及逐条给出的排除理由；**没有理由的一律进 unexplained** |
| `sample_out_of_scope` | 未交付文件的抽样（便于人工抽查，不参与判定） |

恒等式（任何一方都能用两条命令重算）：

```
tracked_count == declared_count + out_of_scope_count
declared_digest == tree_digest(sorted(declared_paths))
out_of_scope_digest == tree_digest(sorted(universe - declared))
```

因此"少交一个文件"或"多塞一个文件"都会让摘要或恒等式对不上，**不依赖交付方的口头解释**。
唯一允许的排除，是 `ignored_explained` 里逐条写明理由的那些（本仓库只有一条：
`swordholder/samples/alert_02_token.seal.json`，是本机跑 samples 时生成的签封产物，
第三方 clone 后跑测试会自行生成同名文件）。

### 1.3 第三方怎么验

```
python -I scripts/stage11/external_verify.py \
    --manifest evidence/stage13/s13_manifest.json \
    --root . \
    --check-scope \
    --actual evidence/stage13/s13_probes_counts.json
```

`external_verify.py` 不 import 本项目任何模块，仅标准库。`--check-scope` 会：

1. 跑 `git ls-files` 拿全集，重算上面三条恒等式；
2. 用清单声明的逐个文件哈希复算整树摘要（`tree_digest`），任改一个字节即 mismatch；
3. 比对 `--actual`（探针分档与计数）与清单 `expected`，缺项/不同都算失败。

退出码 0 才算通过。

### 1.4 负例是被脚本自己跑出来的，不是我说的

探针 P13 里跑三种破坏，每一种都必须被拒：

| 负例 | 手法 | 期望 |
| --- | --- | --- |
| N1 | 从交付路径里删掉最后一个文件再重算 | `scope.ok=False`（`delivery_missing` 或恒等式破裂） |
| N2 | 往交付目录塞一个未声明的新文件 `swordholder/ghost_module.py` | `scope.ok=False`（进 `out_of_scope` 但摘要与声明不符 / 恒等式破裂） |
| N3 | 把 `ignored_explained` 清空 | `scope.ok=False`（原被解释的忽略项变成 `ignored_unexplained`） |

---

## 二、一键端到端复现：`scripts/stage13/run_all.py`

### 2.1 一条命令

```
python scripts/stage13/run_all.py --root . \
    --out-dir evidence/stage13/e2e \
    --summary evidence/stage13/s13_e2e_summary.json
```

依次做五件事，每步都留原始日志到 `--out-dir`：

| 步骤 | 动作 | 判定 |
| --- | --- | --- |
| `env` | 记录 python 版本、git 版本、HEAD、`.venv` 是否存在 | 信息项 |
| `probes` | 跑 `scripts/stage11/compliance_probe.py`，产出本轮探针 JSON 与 counts | rc==0 |
| `verify` | `external_verify.py -I --check-scope --actual <本轮 counts>` | rc==0 且 `ok` |
| `rebuild` | 用本轮探针重算清单到临时路径，与仓库内清单比 `tree_digest` | 摘要一致 |
| `pytest` | `.venv` 存在则用 `.venv`，否则系统 python，跑 `pytest tests -q` | rc==0 |
| `anchor` | `verify_anchor.py` 离线（或联网 `--verify-set`）复核已公布的回执 | rc==0 或如实标 skip |

退出码：`0` 全通过 / `1` 有步骤不通过 / `2` 环境不满足（缺 python、缺 git 等）。

### 2.2 只依赖什么

- 探针与校验脚本本身只用标准库；
- 主流程只用 `subprocess` + `json` + `pathlib`；
- `.venv` 存在时优先用它（`cryptography` 只在 SET 验签与 TSA 校验时需要，缺了就如实标
  `skipped` 而不是伪装通过）。

### 2.3 为什么"在我机器上能跑"不算数

P13 的判据里写死了 clone 矩阵：用 `git clone -c core.autocrlf=true` 和
`core.autocrlf=false` 各建一个**全新目录**，在克隆里跑同一条命令，要求两边都
`steps_ok=true`。这一关专门打"只在我方工作区自证"和"只在某种换行配置下成立"两个毛病。
（克隆里通过 `SWORDHOLDER_E2E_DEPTH=1` 把 run_all 降级为脚本级自检，避免无终止的递归克隆；
该降级在汇总 JSON 里显式记 `depth=1`，不隐藏。）

---

## 三、P11：把锚点摘要登记到公共只追加日志

### 3.1 缺口

stage12 的 P11 有 RFC 3161 时间戳（证明"该摘要在该时刻存在"），但戳值只有交付方留着。
持钥者改写第 7 步、重算整链、重签、再打一枚新戳，校验仍判 VALID——**整册重做不可发现**。
记 PARTIAL 的理由就在这。

### 3.2 现在的两层锚定

1. **RFC 3161**：凭证内嵌 TSA token，离线可复核 CMS 签名 / messageImprint / nonce；
2. **公共透明日志**（`swordholder/transparency.py`，默认 Rekor 公共实例）：
   把"锚点声明"的规范字节提交为 `hashedrekord` 条目，取回含 `signedEntryTimestamp` 的回执。

锚点声明（`swordholder.anchor_statement/1`）只放标识与摘要，**不放正文**——日志是公开的：

```json
{
  "schema": "swordholder.anchor_statement/1",
  "trace_id": "...",
  "seal_sha256": "...",
  "tsa_token_sha256": "...",
  "tsa_gen_time": "2026...Z",
  "tsa_url": "https://.../tsr",
  "purpose": "existence-at-time of a sealed forensic credential"
}
```

提交后得到的回执（`swordholder.anchor_receipt/1`）含 `entry_uuid`、`log_index`、
`integrated_time`、`artifact_sha256`、`set_verified`、`external=true`。

### 3.3 可插拔后端，接不上不冒充

| 后端 | `external` | 说明 |
| --- | --- | --- |
| `rekor` | `true` | 公共只追加日志，条目写入后不可删除/改写 |
| `file` | `false` | 本机只追加文件，**只是桩**，救不了"持证方自己改" |
| `none` | `false` | 禁用，回执不会被伪造 |

`SWORDHOLDER_TLOG=file|rekor|none` 切换。选 `file`/`none` 时回执 `external=false`，
P11 明确记"未接外部日志"，不会因配置不同而变成 PASS。

### 3.4 第三方独立核验（不用交付方代码）

```
python scripts/stage13/verify_anchor.py \
    --receipt evidence/stage13/s13_anchor_receipts.json \
    --statement evidence/stage13/s13_anchor_statement.json \
    --verify-set
```

该脚本只依赖标准库（`--verify-set` 额外需要 `cryptography`），做的事：

1. 按规范 JSON 重算声明摘要，与回执 `artifact_sha256` 比对；
2. `GET /api/v1/log/entries/<uuid>`：条目必须存在（只追加日志里删不掉）；
3. 解条目体，`spec.data.hash.value` 必须等于上一步摘要；
4. `--verify-set`：用日志公钥验 `signedEntryTimestamp`；
5. `POST /api/v1/index/retrieve {"hash":"sha256:<digest>"}`：按摘要反查应命中同一条目。

退出码 0 通过。

### 3.5 重做可发现性：能到什么程度

持有回执的一方，事后拿回执核对眼前凭证（`transparency.detect_rework`）：

- 摘要一致 → 同一份东西，未检出重做；
- 摘要不符 → 检出重做，且日志里那条旧条目**仍然在**，可作事后举证。

仍然成立的四条边界（写进 P11 证据，不掩）：

1. 日志只锁摘要不锁正文，正文仍躺在持证方磁盘上；
2. 没有 WORM 副本；
3. 首次核验者手里没有历史回执时，重做对他依然隐形（`E_TLOG_NO_PRIOR_RECEIPT`）；
4. 同一 `trace_id` 可以再注册一条新锚点，"哪条权威"要靠外部时间线策略仲裁。

所以 P11 维持 **PARTIAL**：能力从"重做不可发现"提升到"持回执者可发现且可举证"，
但没到"任何人无条件可发现"。
