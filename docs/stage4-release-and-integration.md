> 本文件记录第四阶段"交付成熟度"部分的实际产出与实测数据。所有数字来自本机执行结果，
> 复算命令在各节给出。**尚未完成的诚实声明**：包未发布到 PyPI（本阶段 GitHub/PyPI 网络不可达），
> 无外部使用者，无 CI 流水线，无第三方复现记录。

# 第四阶段（上）：发行物与最小接入路径

## 1. 为什么先补这块

第三阶段复评给出 `composite = 63.8`，缺口集中在两项：**交付成熟度 2.30**、**变现清晰度 2.10**。
两项换算是同一句话：**没有别人能接手的东西，也没有人愿意付钱的价格**。

第三阶段结束时的事实是：322 项测试全绿、MCP/CLI/HTTP 三入口齐全，但——
没有可安装发行物、没有交给陌生人的接入文档、没有一句"这东西多少钱"。

本轮把前两件做实，第三件在 `docs/stage4-pricing-and-value.md`。

## 2. 发行物

| 项 | 值 |
|---|---|
| wheel | `dist/swordholder-0.7.1-py3-none-any.whl`，145,361 字节，36 个条目 |
| sdist | `dist/swordholder-0.7.1.tar.gz`，239,042 字节（含 `examples/`、`docs/`、`evidence/stage4_pricing/`） |
| wheel SHA256 | `5d4637b4a7df45420fce51ceac490427e997860f3d465c03fcbc13f03a21b3cf` |
| 校验清单 | `dist/SHA256SUMS`（wheel + sdist 两行） |
| 版本权威源 | `pyproject.toml` version = `0.7.1` = wheel `METADATA` = `swordholder.__version__` = `swordholder --version` |
| 运行时依赖 | `cryptography>=42.0.0`、`pyyaml>=6.0.1,<7`、`jsonschema>=4.18`（三项，与 `pyproject.toml` 一致） |

打包方式有一个坑值得记下来：`.venv` 内没有 `wheel` 模块（`importlib.util.find_spec("wheel") is None`），
`python -m pip wheel . --no-build-isolation` 直接报 `invalid command 'bdist_wheel'`。
可行路径是借 Marvis 内置 runtime 的 setuptools/wheel，`PYTHONPATH` 指向其 `site-packages`，
再用 `.venv` 解释器执行 `python -m build --wheel --no-isolation --outdir dist`。

这个坑已固化成 `scripts/build_release.py`（`dist/` 在 `.gitignore` 里，clone 的人必须自己构建）：

```bash
python scripts/build_release.py --check     # 探测哪些解释器有 setuptools+wheel
python scripts/build_release.py             # 自动挑解释器 → 构建 → 写 SHA256SUMS
# 命令行路径带空格时（如 Program Files）用环境变量更稳：
set SWORDHOLDER_BUILD_PYTHON=<python.exe>
```

脚本行为：探测 `setuptools` 与 `wheel` → 选第一个可用解释器 → 注入其 `site-packages` 到 `PYTHONPATH`
→ `python -m build --wheel --sdist --no-isolation` → 校验两个产物存在 → 写 `SHA256SUMS`
→ 打印 JSON（含每个产物的字节数与 SHA256）。找不到可用解释器时给出三条具体修复路径并以退出码 2 结束。
实测：`--check` 正确判定 `.venv` 缺 `wheel`（`setuptools=True wheel=False`）；指定内置 runtime 后
一次构建成功，产物即上表数值。


## 3. 最小接入示例（`examples/minimal_integration.py`）

设计目标不是"演示能跑"，而是**让陌生人能在不读源码的情况下判断这东西是否可用**：

- 只 import 公开 API：`swordholder.core`（keygen/seal/verify）、`swordholder.trust`；
- 一条命令跑完 13 项检查，输出机器可读 JSON（`checks[].passed`、`timing`、`payload_sha256`）；
- 退出码语义固定：`0` 全过 / `1` 有失败 / `2` 环境缺依赖；
- 用到非空目录时自动开 `run_<时间戳>` 子目录，**不删除用户任何文件**。

实测（`.tmp_min/minimal_check.json`，本机、单进程）：

| 组 | 结果 |
|---|---|
| 密钥与信任锚（A1/A2） | 通过 |
| 签发（A3） | 通过 |
| 正常验签（A4） | 通过 |
| 篡改（A5 payload / A6 字段 / A7 签名字节） | 3/3 拒绝 |
| 类型混淆（A8 整数 / A8b 非法 base64） | `E_MALFORMED_SEAL` / `E_SCHEMA_INVALID`，均非崩溃 |
| 重放（A9 跨会话 / A10 不比对 challenge） | `E_CHALLENGE_MISMATCH` / `OK`（如实暴露"不比对就没有重放防护"） |
| 确定性（A11/A12） | 摘要 `SAME`、nonce `DIFFERENT` |
| **合计** | **13/13 通过** |

性能（30 次迭代，本机，含文件读写）：`seal` 中位 0.538–0.551 ms（p95 0.583–0.614）、`verify` 中位 4.718–4.911 ms（p95 5.227–5.376）。
区间来自两次独立运行（源码树 / 隔离安装），波动 <5%，不改变单位经济结论。
`payload_sha256 = c666b8967af14eb5af185d1913caed0c71d8af714ad1ecb172e3b8dc5f8d8a47`。

## 4. 发行物验收（`scripts/verify_release.py`）

这一步回答的是第三阶段报告里那句"仍缺的是别人能不能复算"。它在**隔离目录**里复算，不看源码树：

| 编号 | 检查 | 实测 |
|---|---|---|
| R1 | wheel SHA256 与 `dist/SHA256SUMS` 一致 | 通过 |
| R2 | wheel `METADATA` 版本 = `pyproject.toml` 版本 | `0.7.1` = `0.7.1` |
| R3 | 包数据齐全（2 个 schema + 2 个 policy yaml） | 通过 |
| R4 | 样例告警随包分发 | 7 个 |
| R5 | `pip install --target ... --no-deps --no-index` 离线安装 | 通过 |
| R6 | 隔离目录可 import，且 `__file__` 指向隔离目录 | 通过（`Temp\swordholder-release-*\site\swordholder\__init__.py`） |
| R7 | 隔离安装环境跑最小示例 | **13/13 通过** |
| **合计** | | **7/7 PASS** |

两个值得注意的结果：

1. **确定性跨环境保持**：隔离安装环境跑出的 `payload_sha256` 与源码树跑出的完全一致
   （`c666b896...`）。这不是巧合，是 `payload` 规范化 + 固定密钥的结果，也说明示例本身不依赖执行路径。
2. **性能跨环境稳定**：隔离安装下 `seal` 0.551 ms、`verify` 4.718 ms，源码树下 0.538/4.911 ms，
   同量级（差 <5%）。发行物没有引入可观测的额外开销。

## 5. 负结果与边界（不美化）

| 编号 | 事实 | 影响 |
|---|---|---|
| N-S4-01 | **包没发到 PyPI**：`pip install swordholder` 仍会 `No matching distribution found`；本阶段 GitHub `:443` 与代理均不可达，PyPI 上传也无法验证 | 发行物"可安装"仅限本地 wheel / `pip install .`；对陌生人的摩擦仍未降到一条 `pip install` |
| N-S4-02 | **无 CI**：所有验收靠人肉触发脚本，`verify_release.py` 本身没有回归保护 | 下一次改动若打坏包数据，没人会收到红灯 |
| N-S4-03 | **无外部使用者 / 无第三方复现**：13 项检查、7 项发行物检查都是我们自己在同一台机器上跑的 | "可被外部复算"目前是**可复算的方法**，不是**已被复算的事实** |
| N-S4-04 | **示例覆盖的是接入链路，不是判定质量** | 13 项全过不代表结论判得对；S2 已证伪规则层质量，这里不重复 |
| N-S4-05 | **A10 暴露的弱点**：不比对 `challenge` 时凭证仍能验为 `OK`，重放防护完全依赖调用方传 challenge | 接入方漏传即失去防重放，示例已把这条钉成显式检查，但代码层未强制 |
| N-S4-06 | **无并发/多写者验收** | 示例单进程顺序执行；`seals.db` 与目录写入在多写者下的行为仍未知（沿用 N-S3-06） |

## 6. 复算

```bash
# 发行物（含构建解释器探测；dist/ 不入库）
python scripts/build_release.py --check                                  # 先看哪个解释器能构建
python scripts/build_release.py                                          # 构建 + 写 SHA256SUMS
python scripts/verify_release.py --out release_check.json                # 7/7 PASS

# 最小接入
python examples/minimal_integration.py --out minimal_check.json          # 13/13 passed

# 全量测试
.venv\Scripts\python.exe -m pytest -q                                    # 324 passed
```
