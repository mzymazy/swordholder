# 第五阶段：与 Sigstore/Rekor、in-toto/SLSA、SCITT、JACS 的逐项正面对比

本文件的每个「我们」列的数字都来自 `scripts/stage5_diff_bench.py` 的实跑结果
（`evidence/stage5_diff/bench.json`，2026-11-08，Python 3.11.8 / cryptography 50.0.2 / Windows 10.0.26200），
每个「对手」列的说法都登记在 `evidence/stage5_diff/competitor_facts.json` 里并附原文与 URL。
凡是我们没有同口径实测的，本文件一律写「未测」，不用对方文档的形容词充数。

复算方式：

```bash
python scripts/stage5_diff_bench.py --reps 31 --intoto-path .tmp_s5_site
```

---

## 0. 先给结论（差异度到底剩什么）

| 原先的自我宣称 | 实测判定 | 依据 |
|---|---|---|
| 「我们能离线验签」 | **不构成差异**。Sigstore 新 bundle 原生支持离线验签，in-toto 只需公钥，JACS 自称同样离线 | bench `offline`：30/30 VALID 且 socket 调用 0 次；对手见 src-sigstore-offline / src-intoto-site / src-jacs-compare |
| 「我们不依赖外部日志」 | **对 SCITT、对 Sigstore 的 keyless 链成立；对 JACS 不成立**（JACS 自称 Central infrastructure: Not required） | bench `offline.verify_inputs`=2 文件/970 B；src-jacs-compare |
| 「我们能定位到具体哪一步被改」 | **成立，且是我们唯一能拿数字硬碰的差异**：50 步轨迹全位置篡改 50/50 精确给出步号 | bench `localize` 9/9 检出、7/7 精确；`coverage` 50/50 精确 |
| 「用一条凭证覆盖整条轨迹」 | **成立且可量化**：50 步 = 1 个签名 955 B，in-toto 逐步骤 = 50 个签名 24,750 B（25.9 倍体积差） | bench `scaling` |
| 「拒绝时给结构化代码、不抛异常」 | 我们 7 类畸形输入 0 未捕获异常；**对手未做同口径实验** | bench `refusals`；对手列入未测 |

一句话：**差异度不能靠「离线」撑，只能靠「步级定位 + 单凭证体积/耗时随步数近乎恒定」撑。**
前者是语义层面的（对手的元数据单位是"某产物在某构建步骤的签名"，不是"某动作序列里的第 k 步"），
后者是同机实测的数量级差。

---

## 1. 离线验签：我们做到了，但它不是差异

**怎么测的（不是"看代码觉得没联网"）：**
子进程里先用 `sys.addaudithook` 在 `socket.connect / getaddrinfo / gethostbyname / socket.bind / socket.sendto / urllib.Request`
这些事件上设拦截（触发即抛异常并计数），然后再 `import swordholder` 并验签 30 份凭证 + 1 份轨迹凭证。

| 指标 | 实测值 |
|---|---|
| 凭证验签 VALID | **30 / 30** |
| 轨迹凭证验签 | **VALID**（不是 VALID_UNTRUSTED_KEY） |
| 被拦截的网络调用次数 | **0** |
| 验签进程中是否加载 `ssl` / `http` / `urllib.request` / `asyncio` | **全部未加载** |
| 是否加载 requests/urllib3/httpx/aiohttp | **全部未加载** |

**为什么这一条在 S5 之前是站不住的：** `swordholder/rules.py` 原来在模块顶层 `import urllib.request`，
`import swordholder` 就会把 `http.client` 与 `ssl` 拉进进程。也就是说"验签时不发网络请求"成立，
但"验签不需要网络栈"不成立——导入期已经把网络栈装进来了。S5 把它改成函数内惰性导入
（`rules.llm_available` / `rules.llm_enrich`），上面"网络模块全部未加载"这一行才是现在的结果。
这条修复本身也算 S5 的产出：**它是被实测逼出来的，不是设计时就想到的。**

**对手状态（引用原文，不代其下结论）：**
- Sigstore：`cosign verify-blob --bundle` 的新 bundle 格式"supports offline verification, and includes additional information (like signed timestamps and attestations) in a single file"。
- in-toto：JACS 的对比表把 in-toto 的离线验签标为 `Yes (with keys)`；in-toto 的验证本来就是对本地 link 文件验签。
- SCITT：Receipt 是 COSE 对象，数学验证可本地做；但 Signed Statement 要"transparent"必须注册到 Transparency Service 并拿到 Receipt。
- JACS：自称 `Offline verification: Yes`。

**判定：不构成差异。** 我们能说的是"离线验签在最严格的口径下可复现"（导入期零网络模块 + 运行时零网络调用），
这对工程可信度有用，但不能写进"别人做不到"。

---

## 2. 无外部日志/CA 依赖：分层看，只对一半对手成立

验证一条凭证到底需要什么，是可以用**字节数**数出来的：

| 验证输入 | 实测 |
|---|---|
| 文件数 | **2**（凭证 + 本地信任锚） |
| 总字节 | **970 B** = 凭证 761 B + 信任锚 209 B |
| 轨迹凭证字节 | 954 B（12 步） |
| 公钥 PEM（参考） | 113 B |

没有日志服务、没有时间戳服务（RFC 3161）、没有 OCSP、没有 Fulcio 式的在线 CA。
签发侧同理：`core.keygen` 本地生成 Ed25519 私钥，`core.seal` 直接签，无外部往返。

对手口径对照（只登记其自述）：

| 对手 | 签发期依赖 | 验证期依赖 | 相对我们的结论 |
|---|---|---|---|
| Sigstore（keyless） | Fulcio（OIDC 短证书）+ Rekor（透明日志） | 新 bundle 可离线，但信任根来自 Fulcio/Rekor 生态 | 差异**成立**：我们不引入在线 CA/日志 |
| SCITT | Transparency Service（注册才能拿到 Receipt） | Receipt 可本地验，但无 TS 即无"透明"属性 | 差异**成立** |
| in-toto | 无中央服务，公钥分发自理 | 公钥 + link 文件 | 差异**不成立**（都不需要外部服务） |
| JACS | 自述 Not required | 自述无需联系任何服务器 | 差异**不成立** |

**判定：** 这条只能对 Sigstore keyless 与 SCITT 讲；对 in-toto 和 JACS 讲就是重复别人已有的性质。
S4 文档里"无外部日志依赖"的写法按此收紧。

---

## 3. 步级定位：唯一能拿数字硬碰的差异面

### 3.1 九类篡改，逐个给出第一个断点的步号

对 20 步轨迹做 9 类篡改，判据同时看两件事：**是否判 INVALID**，以及 **`first_break` 是否等于注入位置**（0 基）。

| 篡改类型 | 注入步 | 期望断点 | 实际断点 | 判定 | 拒绝码 |
|---|---|---|---|---|---|
| 改某步 observation | 7 | 7 | 7 | 检出+定位 | E_TRACE_BREAK |
| 改某步并把该步哈希重算 | 5 | 6 | 6 | 检出+定位（断点前移到下一步） | E_TRACE_BREAK |
| 插入重复步 | 4 | 5 | 5 | 检出+定位（错位落在下一步 prev） | E_TRACE_BREAK |
| 删除一步 | 6 | 6 | 6 | 检出+定位 | E_TRACE_BREAK |
| 交换相邻两步 | 9 | 9 | 9 | 检出+定位 | E_TRACE_BREAK |
| 改步号 n | 11 | 11 | 11 | 检出+定位 | E_TRACE_BREAK |
| 改 prev 指向创世 | 13 | 13 | 13 | 检出+定位 | E_TRACE_BREAK |
| 截断尾部 3 步 | 17 | — | None | 检出（E_TRACE_HEAD_MISMATCH，属凭证层） | E_TRACE_HEAD_MISMATCH |
| 整链重算成自洽（伪造者手法） | 3 | — | None | 检出（链自洽但头变了） | E_TRACE_HEAD_MISMATCH |

汇总：**检出 9/9（1.00），需要步号的 7 例步号全中（7/7）**，0 未捕获异常。

> **第八阶段更正（0.7.5，2026-11-08）**：上表末尾两类（截断尾部、整链重算成自洽）当时记为「检出但无步号」，
> 其口径是 0.7.4 的：凭证只承诺 `(trace_id, step_count, head, digest)`，`head` 不保留中间态，
> 因此「改某步 + 重算后续哈希 + 改 head」之后在信息上无法定出步号。0.7.5 把**步级锚点**签进凭证，
> 这两类现在也能给步区间（≤64 步时精确到单步）。机制与边界见
> [stage8-step-localization.md](stage8-step-localization.md)，同用例前后对照见 `evidence/stage8/s8_locate.json`。
> 结论口径更新为：**弱篡改走链定位、强篡改走锚点夹逼，30 例(10 类 × N=3/20/50)定位 30/30，
> 其中 24 例改动跨度精确到单步，6 例属「分叉点在第 0 步」——只能定位分叉点、跨度不可收窄**。

### 3.2 50 步全位置扫描：每一处都能指到步号

对 50 步轨迹的**每一个**步号（0..49）逐个改值：

| 指标 | 实测 |
|---|---|
| 检出 | **50 / 50** |
| `first_break` 精确等于注入步号 | **50 / 50** |
| 凭证字节（50 步） | 946 B |
| 凭证字节（1 步，同长度 trace_id） | 945 B |
| 每多覆盖一步的边际体积 | **0.0204 B**（即与步数无关，差值仅为 step_count 位数噪声） |

### 3.3 对手为什么在这一列给不出同样的数

- **in-toto**：元数据单位是每步一个 link（由该步 functionary 签）。它能回答"第 k 步的 link 缺失/签名不对"，
  但这是**把 N 个独立签名收集起来做集合核对**，不是"一条链里第 k 个环节断裂"的定位；
  体积与签名次数随步数线性增长（见第 4 节实测 495 B/步）。
- **Sigstore/Rekor**：证明的是"某个条目已进入某棵 Merkle 树"（inclusion proof），语义锚在**单个产物/事件**上，
  没有"动作序列第 k 步"这个概念。
- **SCITT**：证明的是"signed statement 被 TS 登记过"，同样不含序列内定位。
- **SLSA**：分级要求（levels），约束构建平台可信度，不是签名工具，更不提供运行时动作定位。
- **JACS**：其对比表列了 8 项能力（含 M-of-N 群签、证据归一化、派生链、后量子 ML-DSA-87），
  **没有列步级定位**；但该页也声明"can include unreleased changes"，故不能当作它做不到的证据。

**判定：差异成立。** 这是把"我们能定位"从形容词变成"9 类 7/7、50 位置 50/50"的唯一一条，
并且它对应一个真实的运维收益：拿到 `first_break=7` 就能直接去查第 7 步的动作参数，不必重放整条轨迹。

---

## 4. 单凭证 vs 逐步骤签名：同机对照实验

同一个 N 步轨迹，两种做法：

- 我们：整条轨迹一条凭证（1 个 Ed25519 签名覆盖链头 + 摘要 + 步数）。
- in-toto 3.1.0（装在本机 `.tmp_s5_site`，Python 3.11 实测）：每步一个 `Link` metablock、每步一次 Ed25519 签名。

| N | 我们：签名数 | 我们：凭证字节 | 我们：签发 ms | 我们：验证 ms | in-toto：签名数 | in-toto：字节 | in-toto：签发 ms | in-toto：验证 ms |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 951 | 0.41 | 0.83 | 1 | 495 | 0.10 | 0.15 |
| 5 | 1 | 951 | 0.43 | 0.83 | 5 | 2,475 | 0.45 | 0.72 |
| 20 | 1 | 955 | 0.46 | 0.89 | 20 | 9,900 | 1.73 | 2.89 |
| 50 | 1 | 955 | 0.56 | 0.99 | 50 | 24,750 | 4.38 | 7.22 |

（中位数，reps=31；in-toto 因单次太快，按 reps=10 采样）

推导出的比值：

| 指标（N=50） | 我们 | in-toto | 比值 |
|---|---|---|---|
| 凭证体积 | 955 B | 24,750 B | **25.9× 更小** |
| 签发耗时 | 0.56 ms | 4.38 ms | **7.8× 更快** |
| 验证耗时 | 0.99 ms | 7.22 ms | **7.3× 更快** |
| 签名次数 | 1 | 50 | 50× 更少 |

**必须同时写出来的反向事实：**
1. **N=1 时我们更慢**（验证 0.83 ms vs 0.15 ms）——0.7 ms 左右是我们的固定开销（schema 校验 + 结构检查）。
   交叉点在 **N≈6**：按实测斜率（我们 ≈0.83+0.003×N，in-toto ≈0.145×N）解出 0.83/(0.145-0.003)≈5.9。
   单步场景（只签一条告警）我们不占优，这一点不藏。
2. in-toto 的 24,750 B 是**只算 link 元数据**，不含 layout、公钥与签名者证书；真实场景还会更大。
3. 我们没有测 `in_toto_verify`（layout 级端到端校验，含 artifact 规则与 functionary 授权），
   那才是用户真正会跑的入口。所以"7.3×"只对 link 级验签成立，不能外推到 layout 全流程。

---

## 5. 拒绝行为：结构化代码，0 异常逃逸

7 类输入全部收敛为 `verdict=INVALID` + 稳定拒绝码，**未捕获异常 0**：

| 输入 | 结果 |
|---|---|
| payload 被改（签名域内） | INVALID / E_PAYLOAD_TAMPERED |
| payload 变成字符串（类型混淆） | INVALID / E_PAYLOAD_TAMPERED |
| signature.value 改成 "AAAA"（非 64 字节 b64） | INVALID / E_SCHEMA_INVALID |
| signature 整块换成字符串 | INVALID / E_MALFORMED_SEAL |
| 改 seal_header.payload_sha256 | INVALID / E_PAYLOAD_TAMPERED |
| seal_header.seal_version=9.9 | INVALID / E_UNSUPPORTED_SEAL_VERSION |
| 凭证文件不存在 | INVALID / **E_SEAL_NOT_FOUND**（S5 新增，见下） |

**S5 修掉的第二个真问题：** 文件不存在这条最常见的失败路径，原来返回 `{"ok": false, "error": ...}`，
与其余分支的 `verdict` 形态不一致——调用方按 `res["verdict"] == "INVALID"` 判失败时会 **KeyError**，
也就是"最该 fail-closed 的路径反而绕过了统一契约"。现在统一成 `E_SEAL_NOT_FOUND`。

对手这几列无法对比：我们没有对 Sigstore/cosign、in-toto、JACS 做同口径畸形输入注入实验，
登记为"未测"，不写成"对手做不到"。

---

## 6. 信任分离：不是差异，是我们自己的 fail-closed 证据

| 场景 | 结果 |
|---|---|
| 信任锚里换成陌生公钥 | **VALID_UNTRUSTED_KEY** |
| 不提供信任锚 | **VALID_UNTRUSTED_KEY** |
| 是否出现过裸 VALID | **否** |

这条不当作差异（Sigstore 的 `--certificate-identity` / in-toto 的显式公钥同样要求调用方给出信任依据），
只作为"宣称与实现对齐"的证据。

---

## 7. 对手未测清单（写清楚，不用文档形容词补）

| 对手 | 未测内容 | 原因 |
|---|---|---|
| Sigstore / Rekor | 同机验签耗时、inclusion proof 校验耗时、bundle 体积 | 未安装 sigstore 客户端；本轮只做我们与 in-toto 的同机对照 |
| in-toto | layout 级 `in_toto_verify` 端到端耗时 | 需要构造完整 layout + 步骤命令 + 制品，超出本轮范围 |
| SCITT | TS 部署行为 | 无可用实现 |
| JACS | 任何量化指标 | 其对比页只有能力勾选，无数字；且自称可能含未发布变更 |

---

## 8. 结论：差异度从 2.6 提到哪一步，凭什么

- **成立且可量化（可写进对外材料）**：步级定位（9 类 7/7、50 位置 50/50）+ 单凭证覆盖（N=50 时体积 25.9× 更小、验证 7.3× 更快、签名数 50× 更少，交叉点 N≈6）。
- **成立但只对部分对手**：无外部日志/CA 依赖（对 Sigstore keyless、SCITT 成立；对 in-toto、JACS 不成立）。
- **不构成差异（必须改口径）**：离线验签本身；"不依赖外部设施"对 JACS 不成立。
- **顺带修掉两个真问题**：导入期加载网络栈、文件不存在的非 verdict 返回。两者都是被实测逼出来的。

差异度的上限也清楚：我们没有第三方独立实现来复现这些数字，也没有在真实客户环境里跑过 50 步轨迹以外的规模；
`JACS` 这类"自述离线 + 去中心化 + agent-native"的对手一旦发布可复现实现，"离线/无设施"这条就彻底归零，
只剩步级定位与体积这两条。
