# S12 能力边界：Art.12(2) 风险字段档位 + RFC 3161 外部时间戳

本文件只写**这两块新能力各自成立到什么程度、缺哪一半**。数字口径以 `evidence/stage12/*.json`
为准，本文件不重复数字。

---

## 1. Art.12(2)(a)(b)(c) 内建风险字段（profile = `art12-2`）

### 1.1 条文与实现的对应

| 条文 | 用途枚举 `purpose` | 该用途被要求记录的字段 |
| --- | --- | --- |
| Art.12(2)(a) 识别风险并采取缓解措施 | `risk_identification` | `purpose / event_type / severity / risk_flag`（+ 可选 `monitor_tag`） |
| Art.12(2)(b) 上市后监测 | `post_market_monitoring` | 同上 |
| Art.12(2)(c) 部署方评估 | `deployer_evaluation` | 同上 |

`severity` 取值 `info / low / medium / high / critical`（有序，可直接按最低档筛）。

### 1.2 向后兼容怎么保证

- **默认口径不动**：不声明 profile 时条目键集合仍是 `action / args / hash / n / observation /
  prev / ts` 七个，`entry_core` 与 0.9.0 逐字节一致，历史轨迹哈希不变。
- **字段进链，不是旁挂**：`profile="art12-2"` 下五字段进入 `entry_core`，改任一字段不重算哈希
  必在该步断链（`verify_chain` 报 `first_break`）。
- **写入即强制**：缺 `purpose` / `event_type` / `severity` / `risk_flag` 分别抛
  `E_ART12_2_PURPOSE_MISSING` / `..._EVENT_TYPE_MISSING` / `..._SEVERITY_MISSING` /
  `..._RISK_FLAG_MISSING`；非法取值抛 `E_ART12_2_PURPOSE_INVALID` /
  `E_ART12_2_SEVERITY_INVALID`。不存在"给了空值也被静默接受"的路径。

### 1.3 能直接筛取什么

- `select_entries(body, purpose=...)`：按用途筛（审计方问"监管报送用了哪些记录"）。
- `select_entries(body, min_severity="high")`：按最低严重度筛。
- `select_entries(body, risk_flag=True)`：按是否被标记为风险事件筛。
- `risk_summary(body)`：`total / risk_flagged / unclassified / by_severity / by_purpose`。

### 1.4 边界（必须与能力一起声明）

- 字段是**记录口径**，不含判定口径：什么算 `high` 由部署方在策略层定义，库只保证
  "写了就进链、缺了就拒写、能按值筛出来"。库不替部署方做严重度评级。
- `monitor_tag` 只是自由标签，不做命名空间校验。
- 档位是**整条轨迹**的声明，同一轨迹内不允许混用档位（混用会让 `body_digest` 口径不一致）。

---

## 2. 外部时间戳（RFC 3161，`swordholder/timestamp.py`）

### 2.1 解决了什么

链式哈希 + Ed25519 签名只能证明"记录内部没被改"和"谁用某把私钥签的"，证明不了**时间**：
持私钥的人今天补签一份，验签方无从分辨。RFC 3161 把 digest 交给独立第三方 TSA，由 TSA
签一份 `TSTInfo`（含 digest、序列号、发放时刻）。此后任何人可离线验证：
**"这个 digest 在 genTime 之前就已存在"**。要伪造得攻破 TSA 私钥。

实现只做三件事，**零第三方依赖**（DER 编解码自写）：

1. `build_request` 生成 `TimeStampReq`（version / messageImprint / nonce / certReq）；
2. `parse_response` 解析 `TimeStampResp`（状态码、失败原因、token）；
3. `verify_token` 校验 token：messageImprint 一致、nonce 回环、CMS 签名（signedAttrs 的 DER
   重算）、`messageDigest` 属性、`signingCertificateV2` 的 ESSCertIDv2 与签名证书绑定、
   证书有效期；给了 `trusted_roots` 时再做证书链签发关系校验。

凭证层：`seal_trace(..., timestamp_url=..., timestamp_roots=...)` 先签名再取戳，把戳记录
原子写回同一凭证文件；`check_external_timestamp(path)` 离线复核；
`verify_sealed_trace(..., require_external_timestamp=True)` 在缺戳或戳不成立时返回
`INVALID`（`E_TRACE_TSA_ABSENT` / `E_TRACE_TSA_INVALID`）。

### 2.2 实测（本条必须写清"做到了什么"）

- 真实向公开 TSA 取戳成功（`https://freetsa.org/tsr`），`gen_time` 为实测值而非伪造；
  离线复核 `imprint_match / cms_signature / chain_trusted / ess_cert_binding` 全为真。
- 未打戳的凭证在 `require_external_timestamp=True` 下被拒，`reason` 为 `E_TRACE_TSA_ABSENT`。
- 反例（**这一半没做到**）：持钥者改写第 7 步 → 重算整链 → 重签 → 重打一枚新戳，
  校验仍判 `VALID`。原因不是实现有 bug，而是**没有任何第三方留存首枚戳值**，也没有 WORM 副本：
  外部时间戳只承诺"该 digest 在该时刻存在"，不承诺"这是唯一的一份"。

### 2.3 缺口（未闭合，如实登记）

| 缺口 | 含义 | 关闭条件 |
| --- | --- | --- |
| G4a 无透明日志 / 无戳值公开登记 | 首枚戳无人见证，整册重做不可发现 | 接入 append-only 透明日志或第三方存证机构留存首戳 |
| G4b 无 WORM 存储 | 凭证仍在被记录方磁盘，可整文件删除/替换 | 写入不可改写介质或第三方托管 |
| G3 tamper-proof 仍未达成 | tamper-evident（可发现改动）≠ tamper-proof（无法产生改动） | 需硬件根信任 + 外部见证，非软件层可闭合 |

**结论口径**：外部时间戳把 P11 从 FAIL 推进到 PARTIAL——"外部存在性证明"有了，
"抗内部整册重做"没有。此条不得写成 PASS，也不得用"架构上支持""后续可扩展"措辞。

### 2.4 可插拔桩与失败语义

- 无网络 / TSA 拒绝 / 校签失败时一律抛 `TimestampError`，**绝不返回看起来成功的记录**；
  凭证按"无戳"落盘，`check_external_timestamp` 报 `present=false, ok=false, reason=E_TSA_ABSENT`。
- 探针取戳带 3 次重试（TSA 侧偶发 5xx / 序列号冲突属正常运维噪声），三次都失败才降级为桩，
  并把每次尝试的错误原文写进证据（`tsa_stamp_attempts`），供审计方判断是"没网"还是"被拒"。
