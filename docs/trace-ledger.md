# 动作轨迹账本（Trace Ledger）

> 一句话：让「AI 智能体到底按什么顺序做了什么」成为一份**改了就会被发现**的记录，
> 并且能指出**第一个断点在第几步**。

本文件只讲三件事：它补的是哪一层缺口、它防得住什么防不住什么、以及凭什么这么说（可复现实验）。

---

## 1. 补的是哪一层缺口

仓内既有能力链是：**原始响应 → 逐题记录 → 证据聚合 → ed25519 凭证 → 信任锚校验**。
它证明的是「一条**结论**有没有被事后改过」。缺的前置一层是**过程**：

| 问题 | 既有能力 | 本模块 |
|---|---|---|
| 结论被改过吗 | 有（凭证 + 信任锚） | — |
| 智能体执行过哪些动作、按什么顺序 | 无 | 有（逐步链） |
| 记录被动过吗，动在第几步 | 只能判「整份不符」 | 判到**具体步号** |
| 只披露片段还能不能验 | 不能（摘要覆盖全文） | 能（段内自成链） |

对 Epistemics 赛道的意义：`provenance` 与 `tamper-evident records of what AI agents did`
不是一句声明，而是一个可被第三方**独立重算**的判据。

## 2. 机制

```
entry[n].hash = SHA256( entry[n-1].hash + "\n" + c14n(n, ts, action, args, observation) )
```

- 每步只把白名单字段（`n/ts/action/args/observation`）纳入哈希，渲染用备注不进哈希，
  避免无关字段造成假断点；
- 头部哈希 `head` 与步数 `step_count` 一起被封存：`seal_trace()` 只签
  `{trace_id, step_count, head, digest}`，**逐字全文留在持有方**，凭证因此很小；
- 验证分三段，任一段不过即 `INVALID`：
  1. `verify_chain()` 重算整链 → 判自洽、定位首断点；
  2. `exit_guard.issue_credential()` 签发的凭证 → `core.verify()` 判签名与信任锚；
  3. 凭证里的 `trace_id / head / step_count / digest` 与实际轨迹逐项比对 → 挡住
     「拿 A 轨迹的凭证去背书被改过的 B 轨迹」。
- 签发**不走** `core.seal()`，走 `exit_guard.issue_credential()`——仓内唯一凭证通道（先取票再盖章），
  否则会被 `tests/test_exit_integrity.py::test_d1` 的 AST 门禁点名。这一点是被测试逼出来的，不是自觉。

## 3. 防得住什么、防不住什么（诚实边界）

| 场景 | 能否发现 |
|---|---|
| 事后改某一步的参数或观测值 | 能，且定位到该步 |
| 插入一步、删除中间某步、交换相邻两步 | 能，定位到首个断点 |
| 删除**尾部**若干步 | 能（靠 `step_count` / `head`），但无 `first_break`——存活部分各自自洽 |
| 只披露轨迹的一段给第三方审 | 能验段内完整（段首自带 `prev`） |
| **持有私钥的人重签一份自洽的篡改版** | **不能**。这是本机制的硬边界：私钥必须离开记录方 |
| 从第一步之前就作假（造假的历史） | **不能**。本机制只防事后改动 |
| 动作内容本身的合法性 | 与本机制无关。账本只保证「没被改」，不保证「做得对」 |

第二类不防必须在报告与 README 中明写，否则就是把 tamper-evident 吹成 tamper-proof。

## 4. 实验（可复现）

```bash
.venv\Scripts\python.exe scripts\epistemics_tamper_bench.py --n 200
# → evidence/epistemics/tamper_bench.json
```

设计：200 条确定性合成轨迹（seed=20261113，步长 5/10/20/50 各 50 条），每条施加
modify / insert / delete / reorder 各一次，**施加后不重签**。三方案对照，结果：

| 方案 | 改值检出 | 插入检出 | 删除检出 | 换序检出 | 定位到步 | 假阳性 |
|---|---|---|---|---|---|---|
| L0 明文 JSON | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | — |
| L1 仅全文摘要签名 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0 |
| L2 链式账本（本模块） | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 / 1.00 / **0.92** / 1.00 | 0 |

部分披露（只给最后 ⌈步长/3⌉ 步）：L2 可验 **200/200 = 1.00**，L1 **0/200 = 0.00**。

读法（不许过度解读）：
- L0 恒为 0 不是"方案弱"，是「无可信基准即不可判」的必然，对照组存在的意义是把这句话量化；
- L1 与 L2 的**检出率相同**，所以本模块的价值不在"更能发现"，而在**定位**与**片段可验**；
- delete 的 0.92 全部来自「删的是末步」，这是已知边界，不是随机误差。

## 5. 复现与回归

- 单测（模块本身）：`tests/test_trace_ledger.py`（12 条）——不误报、四类篡改、尾部截断、凭证错配、challenge 绑定、
  拒绝为不自洽的轨迹盖章；
- 接线测试（实跑 `run_agent`）：`tests/test_agent_ledger.py`（13 条）——逐步入链、逐项重算哈希、
  摘要对得上工具返回值、改值/删步/改步号定位到步、兜底与拒收都留痕、落盘离线可验、盖章三段式 VALID/INVALID；
- 全量：`pytest -q` **306 passed**（基线 281 + 账本单测 12 + 接线测试 13，0 失败 0 跳过）；
- 实跑演示：`scripts/trace_ledger_live.py`（见 §6），产物在 `evidence/epistemics/ledger_live/`；
- 代码：`swordholder/trace_ledger.py`（纯标准库，无新增依赖）。

## 6. 接入真实执行路径（run_agent）

`trace_ledger` 不再只有单测在喂它：`agent_loop.run_agent()` 每跑一步都会 `append` 一条。
接入点与判据如下（`swordholder/agent_loop.py`）：

| 入账动作 | 触发时机 | 入账的观测 |
|---|---|---|
| `policy_resolve` | 解析生效策略包后 | 策略来源 / 规则数 / 加载是否成功 |
| `session_open` | 载入或新建会话状态后 | 会话 id / 是否续接上一轮 |
| 工具名（`get_asset_profile` 等） | **每次工具调用后**（成功与失败都记） | `ok` / 返回值哈希 / 字符数 / 前 400 字预览 / 是否命中注入标记 |
| `llm_error` | 模型调用抛错 | 异常类型与摘要 |
| `PARSE_ERROR` | 模型输出无法解析成动作 | 原始文本摘要 |
| 未定义工具（动作名原样） | 模型调了不存在的工具 | 该动作名 + 报错摘要 |
| `submit_verdict` | 每次提交判定（**采纳与拒收都记**） | 采纳时记判定要点；拒收时记拒收理由 |
| `agent:seal` | 结论盖章成功或失败 | `seal_id` / `payload_sha256`；失败记异常 |
| `fallback` | 走规则兜底 | 兜底结论与引擎 |

三条设计约束：

1. **账本只存摘要，不存全文**：每条观测是 `observation_sha256` + `observation_chars` + ≤400 字 `preview`，
   全文仍在 `trace["steps"]`。两边哈希对不上就说明有人改过其中一份——账本不必背着整份 trace 才能自证。
2. **收口必跑 `verify_chain`**：`_finalize_ledger()` 在返回前真跑一次校验，结果写进
   `trace["ledger"]["check"]`；不自洽时**拒绝签章**（`E_TRACE_BREAK`），不会给坏账本背书。
3. **记账失败不阻断分诊**：账本是可观测面而非判定前提，`append` 抛错只记 `trace["ledger_error"]`，
   不吞掉结论——但"没记上"这件事本身留痕，避免事后分不清"没发生"与"没记上"。

CLI 也把账本结论一并吐出来（`--ledger-out` 落盘、`--ledger-seal-out` 盖章）：

```bash
.venv\Scripts\python.exe -m swordholder.cli agent alert.json ^
    --ledger-out runs\a.ledger.json --ledger-seal-out runs\a.ledger.seal.json ^
    -k keys\swordholder_ed25519_private.pem
```

实跑结果（`scripts/trace_ledger_live.py`，脚本化 LLM，三步取证 + 一次提交）：

```
step_count=7   entries: 0 policy_resolve / 1 session_open / 2 get_asset_profile /
               3 get_process_tree / 4 search_prior_alerts / 5 submit_verdict / 6 agent:seal
chain_ok=True  first_break=None
seal_verdict=VALID
tampered_chain_ok=False  first_break=3  reason=第 3 步内容与其哈希不符（疑似改值）
tampered_seal_verdict=INVALID  reason=E_TRACE_BREAK: 第 3 步内容与其哈希不符（疑似改值）
```

对照：同一份落盘账本，把第 3 条的 `observation.ok` 手改成 `false` 后，`verify_chain` 定位到第 3 步，
凭证校验同步降级为 `INVALID`——账本与凭证不是两套独立故事。

入库的只有 `.ledger.json` 与演示用的 `.ledger.tampered.json`；`*.seal.json` 按仓库策略不入库
（`.gitignore:33`，与所有既有凭证一致），重跑 `scripts/trace_ledger_live.py` 即可原样重现。

## 7. 与后续赛题的关系

同一份账本能直接喂给 12 月的两个赛道：
- **Agent Attribution**：逐步 `actor` + 链式记录 ⇒ 行为归属的最小可验单元；
- **Threat Modelling**：把「私钥持有者重签」这条边界写成威胁模型里的显式假设，而不是脚注。
