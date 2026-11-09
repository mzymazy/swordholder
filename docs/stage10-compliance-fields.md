# 第十阶段：记录必备字段与留存期（0.8.0）

> 本文只讲**机制、边界与复算方式**。判定明细见 evidence/stage10/s10_probes.json，
> 修复前快照见 evidence/stage10/s10_probes_before_ef2203c.json，对外报告见 output 目录。
> 本阶段不涉及任何商业、定价或询价内容。

## 1. 出发点

第九阶段用条文探针把「问题真实性」判成 11 条里 3 PASS / 4 PARTIAL / 4 FAIL。
其中两条 FAIL **不是架构上限，是功能没做**：

| 探针 | 条文 | 修复前判定 | 原因 |
|---|---|---|---|
| P04 | EU AI Act Art.12(3)，指向 Annex III 1(a) | FAIL | 四项必备字段内建命中 0/4，只有单点 `ts`，无法表达起止区间 |
| P05 | EU AI Act Art.19(1) / Art.26(6) | FAIL | 全库 retention/TTL/archive 关键词命中 0，记录是静态 JSON |

另外两条 FAIL（P07 tamper-proof、P11 外部锚定）属机制上限，本阶段不动，继续如实标注。

## 2. 记录必备字段（P04）

### 2.1 设计：显式档位，不默认采集

`TraceLedger(trace_id, actor=..., start_ts=..., profile="annex3-1a")`。
**默认 `profile=None`，条目键集合与 0.7.x 逐字节相同**，哈希与历史轨迹完全兼容。
只有显式启用档位时，Art.12(3) 的四项字段才成为写入前置条件：

| Art.12(3) 项 | 字段 | 语义 |
|---|---|---|
| (a) 起止时间 | `period = {start, end}` | ISO8601；`end` 早于 `start` 直接判 `E_ANNEX3_PERIOD_INVALID` |
| (b) 参考数据库 | `db_ref` | 非空字符串，建议带版本/快照号 |
| (c) 导致命中的输入数据 | `matched_input` | `matched=True` 时必填 |
| (d) Art.14(5) 自然人身份核验 | `identity_check = {verifier, method, at}` | `verified_by=` 传入即自动生成 |

### 2.2 为什么是「写入前置」而不是「事后补」

缺一项直接抛 `TraceError`，不允许先写进去再补。否则日志里会留下无字段的合规空档，
事后无法区分「漏填」与「被删」。六个缺项场景全部拒绝，各有独立错误码：

```
E_ANNEX3_PERIOD_MISSING / E_ANNEX3_PERIOD_INVALID / E_ANNEX3_DB_REF_MISSING
E_ANNEX3_MATCHED_INPUT_MISSING / E_ANNEX3_IDENTITY_MISSING
E_ANNEX3_FIELD_INVALID / E_ANNEX3_IDENTITY_INVALID
```

### 2.3 字段必须入链，且档位不能偷偷摘掉

- 字段进条目后参与 `hash` 计算：只改 `period.end` 即在第 1 步断链，封章验签判 INVALID，
  `segment=[1,1]`。
- 轨迹体显式声明 `profile` 时，摘要 `core` 才并入该键（不含该键的 0.7.x 轨迹摘要不变）。
  因此把 `profile` 删掉冒充普通轨迹，凭证判 `E_TRACE_DIGEST_MISMATCH`——**降级路径被堵死**。

### 2.4 边界（必须明写）

**默认档位仍是 0/4。** 本库不默认采集生物特征检索字段，也不替调用方判断自己是否 Annex III 高风险。
Art.12(3) 的覆盖口径是「显式启用档位 + 写入强制 + 入链可验」，**不是「所有记录自动合规」**。
`ANNEX_III_VARIANTS` 当前只登记 `annex3-1a` 一档，其余 Annex III 子项未实现。

## 3. 留存期与归档（P05）

### 3.1 六个月写成硬下限

`swordholder/retention.py`，`MIN_RETENTION_DAYS = 183`。
`RetentionPolicy(days=180)` 直接抛 `E_RETENTION_BELOW_FLOOR`：
**放宽到条文以下必须走法律评估，不由本库默认放行**。

策略字段：`days`（声明期限）、`rotation`（`month` / `year` / `none`）、`archive_subdir`、`label`、`extra`。

### 3.2 两档状态，且「可归档」≠「可销毁」

`classify(ts, policy, now)` 返回：

- `retained`：未满声明期限，必须继续保留；
- `archive_due`：已满声明期限，**可以**归档。

未到期限强行归档被拒（`E_RETENTION_TOO_EARLY`）。
归档副本写入 `archive/YYYY-MM/<trace_id>.<sha8>.json`，写入后 `verify_archive` 校验
schema、body_sha256、链、digest 四项；事后改副本内一步即被判
`E_RETENTION_ARCHIVE_CHAIN: 第 2 步内容与其哈希不符（疑似改值）`。

### 3.3 本库不提供删除接口

这是刻意的。提供 `delete()` 等于给被记录方提供「合规地销毁证据」的开关，
而 Art.73(6) 的取证保全要求正相反。归档只做「换位置 + 可校验」，销毁留给持有人的运维流程，
并在文档里说明：**到期可归档不等于可销毁**。

## 4. 实测（同一套探针，修复前后对照）

| 探针 | 条文 | 修复前 | 修复后 | 关键数字 |
|---|---|---|---|---|
| P04 | Art.12(3) Annex III 1(a) | FAIL | **PASS** | 档位内 4/4 字段命中；缺项拒写 6/6；改 `period.end` 第 1 步断链；删档位判 `E_TRACE_DIGEST_MISMATCH` |
| P05 | Art.19(1) / Art.26(6) | FAIL | **PASS** | 法定下限 183 天；180 天被拒；190 天策略下 29 天 `retained`、272 天 `archive_due`；归档校验四项全过；改副本被检出；关键词命中 70 处 |

汇总：**PASS 3 → 5，PARTIAL 4 → 4，FAIL 4 → 2**。
剩余两条 FAIL 是 P07（tamper-proof，本库只是 tamper-evident）与 P11（无外部锚定）。

测试：`tests/test_stage10_annex3_retention.py` 16 用例；全量 `pytest tests` **504 passed / 0 failed / 0 skipped**
（此前的条件型 skip 本轮因产物在盘而实际执行，非删测试）。

## 5. 复算

```bash
python scripts/stage10/compliance_probe.py --out evidence/stage10/s10_probes.json
python -m pytest tests -q
```

探针脚本对每条条文只做「能不能给出证据」的判定，不做法律解释；
PASS 不等于整体合规，FAIL 也不等于方案不可用。
