# 第八阶段：步级篡改定位（0.7.5）

> 本文只讲**机制、边界与复算方式**。实测数据与前后对照见 evidence/stage8/s8_locate.json 与对外报告。
> 本阶段不涉及任何商业、定价或询价内容。

## 1. 问题

第七阶段同机对照暴露一个真实短板：**能检出，但指不出是哪一步**。

- 弱篡改（改了值但不重算哈希）：链自己就断了，`first_break` 直接给出步号。
- 强篡改（改值后把该步及之后全部哈希、连 `head` 一起重算）：
  0.7.4 只能报 `E_TRACE_HEAD_MISMATCH`，`localization` 为空。
- 对照中 in-toto 在 7 类篡改里 5 类能点名具体 step，差距由此而来。

## 2. 根因

0.7.4 的凭证里对被签轨迹的**唯一外部承诺**是四元组：

```
(trace_id, step_count, head, digest)
head = H(step_{n-1} ‖ H(step_{n-2} ‖ … H(step_0 ‖ GENESIS)))
```

`head` 是整链的单向压缩：它证明「某条轨迹曾存在且长这样」，但**不保留任何中间态**。
攻击者改第 t 步并重算 t..n-1、再改 `head` 之后，`body'` 本身是一条合法的链
（`verify_chain` 返回 ok），凭证只能说明「head 与 body' 不等」，无法说明「从哪一步开始不等」。

这不是实现疏漏，是信息论层面的缺失：给定被签的 `head` 与任意一条自洽的 `body'`，
可以构造出「改第 t 步」的等价样本，t 取任意值都成立。**没有步级承诺，就不可能给出步号。**

> 曾经的一个误判：把「`verify_sealed_trace` 在链自洽时不回填 `first_break`」当作根因。
> 那是症状——`body'` 自洽时 `first_break` 必然是 `null`。改返回值不解决问题。

## 3. 修复：把「步级承诺」放进被签 payload

### 3.1 锚点定义

凭证 payload 新增 `anchors`：

```json
{"v":1, "stride":1, "trunc":16, "count":50,
 "points":[{"i":0,"h":"50fb7093ea9f8f6e"}, {"i":1,"h":"..."}]}
```

- `h` = 第 `i` 步**累计哈希**的前 `trunc` 个十六进制字符（默认 16 hex = 64 bit）；
- 落位 `stride = ceil(n / max_anchors)`，`ANCHOR_MAX = 64`，故 ≤64 步时步距为 1（逐步可定位）；
- `anchor_points()` **强制包含最后一步**，否则尾部截断会落进盲区。

### 3.2 夹逼

链式哈希的性质：改动第 t 步 → t 及之后全部累计哈希变样。于是第一个失配锚点
`i_k` 满足 `t ∈ (i_{k-1}, i_k]`；步距 1 时退化为单点。

```
mode="chain"  → 链自己断了，first_break 就是步号（弱篡改）
mode="anchor" → 链自洽但凭证不符，用锚点夹逼出 segment=[lo,hi]
mode="none"   → 凭证是 0.7.4 风格纯头部凭证，无步级承诺，不假装能定位
```

### 3.3 校验顺序未改变

仍是三段：① 链自洽 ② 凭证签名可信 ③ 头/摘要与轨迹一致。
锚点只在「链自洽且签名可信」之后参与定位，因此**不会**把不可信来源的判断当前提。

新增两个错误码：

| 错误码 | 触发条件 | 作用 |
|---|---|---|
| `E_TRACE_ANCHOR_MISMATCH` | 头与摘要都对上，但锚点逐点比对不符 | 防御性拦截（截断参数被改 / 哈希碰撞） |
| `E_TRACE_ANCHORS_ABSENT` | `require_anchors=True` 且凭证无锚点 | 阻断「拿旧版弱凭证降级验证」 |

### 3.4 兼容

- 默认策略下 0.7.4 旧凭证仍判 VALID，只把 `localization.mode` 标成 `none`（能力如实降级，不伪装）；
- `seal_trace(anchor_stride=0)` 可显式退回 0.7.4 纯头部凭证（体积敏感场景）；
- 锚点随 payload 一起被 Ed25519 签名，攻击者改锚点即签名失效。

### 3.5 未牺牲的性质

| 性质 | 本阶段如何守住 |
|---|---|
| 零误报 | 1..80 步 × 3 配置逐一盖章验签，`false_positives = 0`；单测覆盖 1..48 步 |
| 弱篡改仍走链定位 | 仍返回 `mode="chain"` 与精确 `first_break`，不被锚点逻辑改写结论 |
| 盖章拒绝不自洽轨迹 | `seal_trace` 前置校验不变 |
| challenge 绑定 | 锚点不改变 challenge 校验路径 |
| 凭证不含逐字全文 | 锚点只存 16 hex 前缀，不存条目内容 |
| 离线 | 无新增网络依赖 |

## 4. 仍然无法步级定位的情形（设计上做不到，不硬凑）

| 情形 | 为什么不行 | 可接受的替代检测 |
|---|---|---|
| 私钥持有者重签自洽版本（含锚点） | 新旧凭证都合法，定位需要一个「不可被同一主体改写」的参照 | 双人/门限签名；把 `head` 登记到只追加日志或 witness 后再对账 |
| 盖章之前历史就是伪造的 | 凭证只承诺「签发时轨迹长这样」，不承诺「过程真发生过」 | 采集端逐步签名（per-step actor key）、外部时间戳 |
| 分叉点恰在第 0 步 | 「只改第 0 步并整链重算」与「整条根本是另一条轨迹」在锚点向量上完全等价 | 输出 `span_unbounded=true` 明示跨度不可收窄；用 `trace_id` + challenge 做身份层拦截 |
| 步距 > 1（N>64 默认） | 锚点数是体积与精度的折中，`stride=k` 时为宽 k 的区间 | `anchor_stride=1` 换精确单步（体积线性增长，N=1000 约 80 KB） |

## 5. 复算

```powershell
# 依赖：已激活的 .venv，且已安装本仓库
.\.venv\Scripts\python.exe -m pytest tests\test_trace_ledger.py -q

# 对照实测台：三配置 × 10 类篡改 × N=3/20/50，21 reps
.\.venv\Scripts\python.exe scripts\stage8\locate_bench.py evidence\stage8\s8_locate.json
```

输出 JSON 关键字段：`summary`（检出/定位/范围精确）、`cases`（逐例 `verdict / reason / loc_mode / segment / span_unbounded`）、
`false_positive_sweep`、`downgrade_blocked`、`cost`、`large_n`、`inconsistent_anchors`、`challenge_binding`。

## 6. 版本

- `swordholder/__init__.py`、`pyproject.toml` → `0.7.5`
- `trace_ledger.py` 新增 `ANCHOR_MAX / ANCHOR_TRUNC / anchor_stride / anchor_points / build_anchors / locate_step`，
  `seal_trace` 新增 `anchor_stride / anchor_max / anchor_trunc`，`verify_sealed_trace` 新增 `require_anchors`
  并固定返回 `localization`。

## 7. 与 in-toto 定位能力的口径对照（诚实记账）

统计口径必须写清，否则 30/30 与 in-toto 的 5/7 不可比：

| 维度 | 我方 0.7.5 | in-toto 3.1.0 |
|---|---|---|
| 被篡改对象 | 轨迹 body（不重新盖章，用原凭证验） | link / layout 文件（不重签） |
| 检出率 | 30/30（10 类 × N=3/20/50） | 7/7（第七阶段同机实测） |
| 点名到步 | **30/30 给出 span，其中 24/30 上界也收到同一步** | 5/7；2 类不点名（`product_file_modified` 只报 inspection 退出码、`layout_unsigned` 只点名 owner keyid） |
| 定位产物 | 结构化 `segment=[lo,hi]` + `loc_mode` | 报错文本里出现 step 名 |
| 需验文件数 | 2（seal + trace） | N+2（layout + N 个 link + 公钥） |

额外区分：`cross_trace_credential`（拿 A 轨迹的凭证验 B 轨迹）在 3 种配置下都返回
`segment=[0,0]` + `span_unbounded=true`。这一条**本身不具定位信息量**（任何两条不同轨迹的分叉点都在第 0 步），
若把它视为「应报 INVALID 但定位无意义」的一类，则有效定位为 **27/27**（弱 3、强 21、截尾 3），
其中上界封死 24/27。两种口径都写在这里，不做择一粉饰。

## 8. in-toto 侧同任务体积复测（本轮补测，替代第七阶段旧口径）

第七阶段的 70 965 B 是「每步带命令流 + 多产物」的任务形态，与本阶段 `N 步挂同一产物` 不可直接相除。
本轮机内复测（in-toto 3.1.0，`--use-dsse`，layout 由 owner key 签，link 由 alice key 签，
不含公钥文件与产物本体）：

| N | 文件数 | 美化字节 | 紧凑字节 | 我方紧凑 | 比值（紧凑） |
|---|---|---|---|---|---|
| 1 | 2 | 1 855 | 1 622 | 879 | 1.8× |
| 5 | 6 | 6 911 | 5 938 | 1 003 | 5.9× |
| 20 | 21 | 25 871 | 22 123 | 1 480 | 14.9× |
| 50 | 51 | 63 791 | 54 493 | 2 440 | 22.3× |

我方 2 文件恒定，in-toto 为 N+1 文件线性增长；体积优势随 N 放大，但**这是「无步级索引」换来的**——
0.7.4 的 943 B 只有头部承诺，本版用 2.6× 体积换回步级定位，属刻意取舍。
