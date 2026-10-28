# 密钥轮换与凭证吊销

> 面向运维的实操手册。目标只有一个：**换钥之后，老证据不能失效，新证据必须走新钥，泄露的钥必须立刻失去效力。**

## 1. 为什么轮换最容易做错

大多数"签名系统"在轮换时踩同一个坑：验签时拿 `now()` 去比密钥有效期。后果很直接——

- 换钥当天，过去一年签发、当时完全合法的凭证，会因为"签发它的钥已过期"全部变成不可信；
- 审计人员看到的不是"历史证据有效"，而是"历史证据全废"，证据链当场断掉。

本项目的口径是：**按凭证的签发时刻 `seal_header.created_at` 判有效期**，不按验签时刻。

```
如果  seal.created_at <= key.not_after   → 这把钥在它签发时是有效的，继续认
如果  seal.created_at >  key.not_after   → 钥已停用后又冒出新凭证，不认（E_KEY_EXPIRED）
```

`created_at` 在签名覆盖范围内（`seal_header` 参与 c14n 与签名），改它必然 `E_BAD_SIGNATURE`。所以这条时间线不可伪造，轮换才是安全的。

## 2. 信任锚文件格式

默认文件名 `trusted_keys.json`，`--keys-file` / `--keys` 可指向别处。

```json
{
  "schema": "swordholder-trust/1.0",
  "trust_root": "acme-soc/2.0",
  "keys": [
    {
      "key_id": "k-2026a",
      "algorithm": "ed25519",
      "public_key_hex": "0b37...94ff",
      "status": "retired",
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2026-10-28T00:00:00Z",
      "retired_at": "2026-10-28T00:00:00Z",
      "replaced_by": "k-2026b",
      "note": "2026 年度主锚"
    },
    {
      "key_id": "k-2026b",
      "algorithm": "ed25519",
      "public_key_hex": "9c11...8a02",
      "status": "active",
      "not_before": "2026-10-01T00:00:00Z"
    }
  ],
  "revoked_seals": [
    {"seal_id": "8f2c...", "reason": "误发：客户名错", "revoked_at": "2026-10-28T02:11:00Z"}
  ]
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `keys[].key_id` | 建议 | 治理时的引用名；缺省取公钥前 12 位 |
| `keys[].public_key_hex` | 是 | 64 位十六进制；也接受旧字段名 `public_key` |
| `keys[].status` | 否 | `active`（缺省）/ `retired` / `revoked` |
| `keys[].not_before` | 否 | 该钥可签发的最早时刻，早于它签的凭证判 `E_KEY_NOT_YET_VALID` |
| `keys[].not_after` | 否 | 该钥可签发的最晚时刻；`retire` 会自动写入 |
| `keys[].replaced_by` | 否 | 轮换链指针，`check` 会提醒缺失 |
| `revoked_seals[].seal_id` | — | 单份凭证吊销（也可直接写字符串） |

**向后兼容**：0.1–0.3 的 `{"keys":[{"public_key":"..."}]}` 原样可读，缺 `status` 视为 `active`、无窗口。升级不需要改文件，也不需要重签历史凭证。

## 3. 四种操作

### 3.1 登记新锚（新钥上线）

```bash
# 用公钥 pem 直接登记
swordholder trust add --pubkey-file keys_new/swordholder_ed25519_public.pem \
    --key-id k-2026b --not-before 2026-10-01T00:00:00Z --note "2026H2 主锚"

# 或直接给十六进制
swordholder trust add --pubkey 9c11...8a02 --key-id k-2026b --trust-root acme-soc/2.0
```

同一公钥重复登记是幂等的（覆盖同一把钥的元数据，不产生重复条目）；用同一 `key_id` 登记另一把公钥会被拒绝。

### 3.2 停用旧锚（重叠窗口）

```bash
swordholder trust retire k-2026a --replaced-by k-2026b
# 指定截止时刻（更严谨：以"最后一份用旧钥签发的凭证时间"为准）
swordholder trust retire k-2026a --at 2026-10-28T00:00:00Z --replaced-by k-2026b
```

`retire` 只做两件事：把 `status` 置为 `retired`、把 `not_after` 写成截止时刻。旧钥签发的历史凭证继续 `VALID`（`key_status: retired`），截止之后还想用旧钥签新凭证会被判 `E_KEY_EXPIRED`。

> 实操建议：先把新锚 `add` 进来，等新钥真正签发过一批凭证、验证通过，再 `retire` 旧锚。中间的并存期不是问题，`trust check` 会提示"存在 N 把 active 锚"。

### 3.3 吊销密钥（私钥泄露）

```bash
swordholder trust revoke k-2026a --reason "私钥疑似泄露"
```

这是**破坏性**动作：该钥签发的全部凭证立即 `INVALID / E_KEY_REVOKED`，没有窗口、不能回滚（回滚只能人工编辑文件把 `status` 改回去）。只在真的怀疑泄露时用。

### 3.4 吊销单份凭证（错签、误发）

```bash
# 直接给 seal.json，自动取 seal_id
swordholder trust revoke seals/ALRT-2026-1102-0007-7bd218c65a5b.seal.json --seal --reason "误发：客户名错"

# 或给 seal_id
swordholder trust revoke 8f2c1d... --seal --reason "内容需作废"

# 误吊销回滚
swordholder trust restore 8f2c1d...
```

`--key` / `--seal` 必须显式二选一，不给就报错退出——避免"手滑把 seal_id 当 key_id 用"。吊销列表用 `INSERT` 语义，重复吊销返回 `already: true`，不写重复条目。

## 4. 验签判定矩阵

签名与摘要校验先跑（不通过一律 `INVALID`），再过信任策略：

| 情况 | verdict | reason | 含义 |
|---|---|---|---|
| 无信任锚 / 锚文件损坏 | `VALID_UNTRUSTED_KEY` | `E_NO_TRUST_ANCHOR` | 签名真，但没人担保签发方 |
| 公钥不在锚列表 | `VALID_UNTRUSTED_KEY` | `E_UNTRUSTED_KEY` | 未知签发方 |
| 锚在窗口内 | `VALID` | `OK` | 可信，附 `key_id` / `key_status` |
| 凭证被吊销 | `INVALID` | `E_SEAL_REVOKED` | 单份作废，附 `revoked_reason` |
| 锚被吊销 | `INVALID` | `E_KEY_REVOKED` | 整把钥作废 |
| 签发时刻晚于 `not_after` | `INVALID` | `E_KEY_EXPIRED` | 停用后仍在使用旧钥 |
| 签发时刻早于 `not_before` | `INVALID` | `E_KEY_NOT_YET_VALID` | 未生效的钥在签字 |
| 凭证无 `created_at` 且锚有窗口 | `INVALID` | `E_SEAL_NO_TIMESTAMP` | 无法放进任何窗口，不认 |

`VALID_UNTRUSTED_KEY` 与 `INVALID` 的区别很重要：前者是"我验了，签名没问题，但我不认识这个签发方"；后者是"这份东西不该被采信"。下游告警/工单系统应按这个区别决定是"提示人工确认"还是"直接拒绝"。

## 5. 轮换体检

```bash
swordholder trust show            # 人读表格：key_id / status / state / not_after / replaced_by
swordholder trust show --json     # 机读，给监控和值班看板
swordholder trust check           # 只输出问题清单；有提醒时退出码 2
```

`state` 是把 `status` 与时间窗口合起来算的运行时状态：`usable` / `pending`（还没到 `not_before`）/ `expired` / `retired` / `revoked`。

`check` 会提醒这几类问题：

- 锚文件缺失或损坏（此时所有凭证只能判 `E_NO_TRUST_ANCHOR`）；
- 没有 `active` 锚（新凭证无法建立信任）；
- 多把 `active` 锚长期并存（轮换期正常，长期不收敛是隐患）；
- `retired` 锚没写 `not_after`（等于没真正停用，窗口无限延伸）；
- `retired` 锚没写 `replaced_by`（轮换链断点，事后无法追溯"谁接替了谁"）。

退出码 2 让它可以挂进 cron / CI：`swordholder trust check || 值班告警`。

## 6. HTTP 出口

`serve` 启动后（`--keys-file` 指定锚文件）：

```bash
curl -H "Authorization: Bearer $SOC_TOKEN" http://127.0.0.1:8080/v1/trust
```

返回锚列表、状态计数、吊销列表与 `rotation_warnings`。**不含私钥、不含 `keys_path`**，可以给值班看板用。该路由要鉴权，与 `/v1/seals` 同一把 token。

## 7. 一个完整轮换的时序

```bash
# 第 0 天：新钥就位，进锚列表，但还没用它签发
swordholder keygen --out keys_2026b
swordholder trust add --pubkey-file keys_2026b/swordholder_ed25519_public.pem \
    --key-id k-2026b --not-before 2026-10-01T00:00:00Z

# 第 1–14 天：新旧并存，新钥签发小流量，验签全绿
swordholder trust check     # 会提示"2 把 active 锚"，这是预期的

# 第 15 天：旧钥停用（窗口截止到停用时刻）
swordholder trust retire k-2026a --replaced-by k-2026b

# 第 16 天：抽查历史凭证仍为 VALID，且 key_status 显示 retired
swordholder verify seals/<历史>.seal.json --keys trusted_keys.json
```

任何时候发现私钥外泄：`trust revoke <key_id> --reason ...`，然后用新钥重签必要的凭证（旧凭证不会被"修复"，只能重签）。

## 8. 与 `verify_proof.py` 的关系

仓库根的 `verify_proof.py` 是**独立基线验证器**（给"不装本包、只想核对一份凭证"的第三方用），只做 ed25519 + 锚白名单 + 新鲜度，**不实现轮换窗口与吊销策略**。

- 需要完整治理语义（轮换、吊销）→ 用 `swordholder verify` / `POST /v1/verify`；
- 只需要"签名对不对、锚认不认"→ `verify_proof.py` 足够。

两份实现的分工写在这里，是为了避免"两个验证器结论不一致却没人说得清为什么"。
