# 三方同机对照实测：Swordholder / in-toto / cosign

本文记录 Swordholder 0.7.4 与 in-toto 3.1.0、cosign v2.6.1 在同一台机器、同一份 trace 数据上的对照实测。所有数字来自仓库内 `scripts/stage7/` 的脚本，原始输出在 `evidence/stage7/`。目标不是证明"我们更好"，而是给出可复算的取舍边界。

## 1. 环境与版本

| 项 | 值 |
|---|---|
| OS | Windows 11 26200 |
| Python | 3.11.8 |
| Swordholder | 0.7.4（cryptography 50.0.2） |
| in-toto | 3.1.0（securesystemslib 1.6.0） |
| cosign | v2.6.1，GitCommit `634fabe54f9fbbab55d821a83ba93b2d25bdba5f`，go1.25.1，windows/amd64 |

in-toto 装进独立 venv（`pip install in-toto`，轮子 75 kB）；cosign 为 GitHub Releases 单文件二进制（217,388,926 B，sha256 `049026dae3246d6ea8201512ec3efce3aab0c7f1d338d52e26c525dd02b418a0`）。

in-toto 全流程使用 PKCS8 PEM 无口令 Ed25519 密钥（私钥 119 B / 公钥 113 B）；cosign 使用 `cosign generate-key-pair` 的加密格式（`cosign.key` 653 B / `cosign.pub` 178 B）。

## 2. 体积与签名次数

| 步数 | Swordholder 凭证 | in-toto 全量（layout+links+pubkeys） | in-toto 仅 links | cosign 单签 | 体积比 in-toto/ours | 签名次数 ours / in-toto |
|---|---|---|---|---|---|---|
| 1 | 951 B | 2,609 B | 759 B | 96 B | 2.74× | 1 / 2 |
| 5 | 951 B | 8,189 B | 3,859 B | 96 B | 8.61× | 1 / 6 |
| 20 | 955 B | 29,115 B | 15,484 B | 96 B | 30.49× | 1 / 21 |
| 50 | 955 B | 70,965 B | 38,734 B | 96 B | 74.31× | 1 / 51 |

把轨迹本体计入后的全口径（Swordholder = seal + trace；cosign = trace + 96 B 签名）：

| 步数 | Swordholder 总占用 | cosign 总占用 | 比值 |
|---|---|---|---|
| 1 | 1,445 B | 590 B | 2.45× |
| 5 | 2,707 B | 1,852 B | 1.46× |
| 20 | 7,468 B | 6,609 B | 1.13× |
| 50 | 16,998 B | 16,139 B | 1.05× |

即：轨迹越长，Swordholder 与 cosign 的总占用越收敛（大头都是轨迹本体）；in-toto 同口径 N=50 为 87,008 B，是 Swordholder 的 5.1×。

## 3. 耗时（已扣除进程启动基线）

CLI 启动基线：`in-toto-verify` 194.31 ms、`in-toto-run` 194.33 ms、`in-toto-sign` 165.60 ms、`cosign` 44.44 ms。

| 步数 | ours 签名 ms | in-toto 签名 ms（steps+layout） | cosign 签名 ms | ours 验签 ms | in-toto 验签 ms（net / 墙钟） | in-toto 仅 link 进程内验签 ms | cosign 验签 ms（离线 net / 在线） |
|---|---|---|---|---|---|---|---|
| 1 | 0.4977 | 37.24 | 95.99 | 0.9063 | 37.17 / 237.41 | 0.0731 | 5.95 / 2147.99 |
| 5 | 0.5165 | 194.61 | 91.69 | 0.9146 | 46.49 / 246.73 | 0.3401 | 7.23 / 2167.53 |
| 20 | 0.5531 | 690.29 | 91.96 | 0.9394 | 43.22 / 243.46 | 1.3681 | 6.76 / 2160.94 |
| 50 | 0.6475 | 1,712.27 | 90.55 | 1.032 | 63.93 / 264.17 | 3.4216 | 7.07 / 2183.21 |

Swordholder 签名/验签随步数增长极缓（1.30× / 1.14×，N=1→50）；in-toto 签名增长 46.0×。验签：相对 in-toto layout 级净耗时快 41×–62×；相对 in-toto 仅 link 进程内口径（对其最有利）快 3.3×；相对 cosign 离线口径快 6.6×–7.0×。

验签需要的文件数：ours 固定 2 个（seal + trace，约 1,160 B，不随 N 增长）；in-toto 为 N+2（N=50 时 52 个）；cosign 为 3 个。

## 4. in-toto layout 级全流程

```
in-toto-run -n stepNN -k alice.key -m artifacts/s0N-1.txt -p artifacts/s0N.txt -- <cmd>
in-toto-sign -f root.layout -k owner.key
in-toto-verify --layout root.layout --verification-keys owner.pub --link-dir links
```

3 步流水线 `verify_rc = 0`，即 layout 签名、有效期、每步 link 数量阈值、link 由授权 functionary 签名、materials/products 规则、inspection 执行与 artifact 规则全部通过。layout 是授权关系的载体（每步 pubkeys / threshold / expected_command / 产物流向），并随 layout 一并签名——这一点是 cosign 所没有的。

### 规则写法两个坑（会静默失效）

1. `MATCH` 必须写在 `expected_materials`；写进 `expected_products` 时 products 无该路径，规则空转。
2. `MATCH` 是消费式规则，哈希不符时不消费、**不抛错**；必须再跟 `DISALLOW *` 才会转为 `RuleVerificationError`。

## 5. 篡改定位

| 工具 | 案例 | 检出 | 点名到具体步 |
|---|---|---|---|
| Swordholder | 4 | 4（100%） | 2（weak 模式定位；strong 模式只判 INVALID） |
| in-toto | 7 | 7（100%） | 5（`product_file_modified` 靠 inspection 退出码、`layout_unsigned` 点名 keyid） |
| cosign 整条单 blob | 1 | 1（100%） | 0 |
| cosign 每步一签变体 | 1 | 1（100%） | 1（3 步中定位到 step=1，需 3 签 3 验） |

in-toto 点名细节：`link_product_hash_modified` / `link_signature_corrupted` → step01（`ThresholdVerificationError`）；`link_command_changed` → step02；`link_deleted` → step01（`LinkNotFoundError`）；`link_renamed_keyid` → step00。

### 重签攻击（内部人伪造）

| 攻击 | 规则状态 | 结果 |
|---|---|---|
| H1：只改 link 内登记哈希（产物不动）并用该步授权 key 重签 | 缺 `DISALLOW *` | **`verify_rc = 0`，未被检出** |
| H1 同上 | 已补 `DISALLOW *` | `rc=1`，`RuleVerificationError: 'DISALLOW *' matched ['artifacts/s01.txt']`，点名 step01/step02 |
| H2：改产物内容并同步改 link 哈希后重签 | 已补齐 | `rc=1`，同上 |

结论：每步一签提供的是**授权边界**，不是对内部人的自动免疫；拦住重签的是 layout 里的产物流向规则，规则必须写全。

## 6. 离线验签

用 `sitecustomize.py` 进程级拦截 `socket.socket.connect` / `socket.create_connection` / `socket.getaddrinfo`。

| 工具 | 形态 | rc | 网络命中 | 耗时 |
|---|---|---|---|---|
| Swordholder | `verify_sealed_trace` | 0 | 0 | ~0.9 ms（verdict=VALID） |
| in-toto | `in-toto-verify` layout 级 | 0 | 0 | 243.29 ms |
| cosign | key-based，死代理 | 0 / 0 | 有尝试（TUF） | 49.04 / 49.44 ms，stderr 含 `Skipping tlog verification is an insecure practice` |
| cosign | `verify-bundle` 默认 | 1 | — | `signature not found in transparency log` |
| cosign | `verify-bundle --insecure-ignore-tlog=true` | 0 | — | 2,625.88 ms |
| cosign | keyless 无 OIDC | 1 | — | 51.88 ms |
| cosign | 默认 `sign-blob`（试上传 Rekor） | 1 | — | `upload to tlog: user declined the prompt` |

三者都能断网验签，但性质不同：Swordholder 与 in-toto 是设计上不需要网络；cosign 是设计上需要网络、失败后降级（`tuf_attempted_every_run = true`）。

## 7. 外部依赖

| 依赖 | Swordholder | in-toto | cosign |
|---|---|---|---|
| 透明日志 | 无 | 无 | 默认写 Rekor，验签需查 |
| CA / 身份颁发 | 无 | 无 | keyless 需 Fulcio + OIDC |
| 在线根信任刷新 | 无 | 无 | 每次验签尝试 TUF |
| 授权清单位置 | 凭证内 key_id + 链头，策略在 `trusted.json` | layout 内，随 layout 签名 | 无此概念 |
| 单点失效面 | 私钥泄露可重签整条轨迹 | threshold=1 时泄露可合法重签该步（依赖规则拦截） | 私钥泄露可重签该 blob；keyless 依赖 OIDC 账号 |

## 8. 已知局限（负结果）

1. in-toto 规则写不全时静默放行（缺 `DISALLOW *` 时 H1 通过）。
2. in-toto 有 2 类篡改不点名步骤。
3. cosign 整条轨迹单 blob 无法定位步骤。
4. cosign bundle 默认依赖 Rekor，离线须放弃 tlog 校验。
5. cosign keyless 离线不可用。
6. cosign 每次验签都尝试 TUF 刷新。
7. **Swordholder strong 模式只判 INVALID，不定位到步**（4/4 检出、2/4 定位），定位能力弱于 in-toto 的 5/7。
8. 未做密钥格式互通（本机无 `openssl`，cosign 私有加密格式未与 PKCS8 PEM 互通验证）。
9. 仅 Windows 11 单机实测，Linux/macOS 未取得数字。
10. layout 级仅单 functionary、threshold=1，未测多角色门限与 sublayout 递归（意味着 74× 体积比是保守值）。

## 9. 复算

`scripts/stage7/` 下脚本依序执行即可复现本文全部表格：

```
python scripts/stage7/s7_ours_rerun.py
python scripts/stage7/s7_intoto_layout.py
python scripts/stage7/s7_cosign_v2.py
python scripts/stage7/s7_cosign_probe.py
python scripts/stage7/s7_intoto_offline.py
python scripts/stage7/s7_intoto_resign.py
python scripts/stage7/s7_compare.py
```

依赖两个外部位置：in-toto 的独立 venv（`pip install in-toto`）与 cosign v2.6.1 二进制。版本不符合 §1 时数字不可直接对比。
