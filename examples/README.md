# 最小接入（3 步，不读源码）

本目录给的是"把 Swordholder 当依赖用"的最短路径，不是演示程序。全部命令在本仓库根执行。

## 0. 装

```bash
pip install dist/swordholder-0.7.1-py3-none-any.whl     # 离线可装，--no-index 也能过
```

包没有发布到 PyPI（本阶段无网络发布条件），所以请用 `dist/` 里的 wheel，或 `pip install .`。

## 1. 跑最小接入示例

```bash
python examples/minimal_integration.py --out minimal_check.json
```

它只用公开 API（`swordholder.core` / `swordholder.trust`），跑 13 项接入检查，输出 JSON：

| 组 | 检查 | 期望 |
|---|---|---|
| 密钥与信任锚 | A1 生成密钥对 / A2 登记信任锚 | `KEYPAIR_CREATED` / `TRUST_ADDED` |
| 签发 | A3 对一条结论盖章 | `SEALED` |
| 正常验签 | A4 原样验签 | `VALID` |
| 篡改 | A5 改 payload / A6 改 payload 字段 / A7 改签名字节 | 全部 `INVALID` |
| 类型混淆 | A8 签名块置为整数 / A8b 签名块置为非法 base64 | `E_MALFORMED_SEAL` / `E_SCHEMA_INVALID`（结构化拒绝码，不是崩溃） |
| 重放 | A9 拿 A 的凭证验 B 的 challenge / A10 不比对 challenge | 前者 `E_CHALLENGE_MISMATCH`，后者 `OK`（说明重放防护来自 challenge 绑定） |
| 确定性 | A11 同 payload 两次盖章摘要一致 / A12 每次盖章 nonce 不同 | `SAME` / `DIFFERENT` |
| 性能 | `/timing` | seal 中位 ≈0.49 ms、verify 中位 ≈4.9 ms（本机单进程，30 次迭代） |

退出码：`0` 全过 / `1` 有失败 / `2` 环境缺依赖。

## 2. 验收发行物（外部视角）

```bash
python scripts/verify_release.py --out release_check.json
```

它做的是"别人拿到 wheel 会不会用不了"这件事，而不是在源码树上再跑一遍测试：

1. 校验 wheel 的 SHA256 与 `dist/SHA256SUMS` 一致；
2. 校验 wheel 内 `METADATA` 的版本 = `pyproject.toml` 版本（防版本漂移）；
3. 校验包数据齐全（`alert.schema.json` / `seal.schema.json` / `policy/*.yaml`）；
4. 校验样例告警随包分发；
5. `pip install <wheel> --target <隔离目录> --no-deps --no-index` 离线安装；
6. 在隔离目录里 `import swordholder`，确认版本与安装来源都指向隔离目录；
7. 用隔离目录的 `PYTHONPATH` 跑第 1 步的示例，要求 13/13 通过。

7 项全过才 `PASS`（退出码 0）。这一步的意义：源码树能过测试 ≠ 装起来的包能用，包数据漏打、
entry point 写错、版本号漂移这三类问题只有装进隔离目录才会暴露。

## 3. 在你自己的代码里用

```python
from swordholder import core

keys = core.keygen("./keys")                          # Ed25519 密钥对
pub = keys["public_key_hex"]

seal = core.seal({"verdict": "escalate", "reason": "..."},
                 key_path="./keys/private.pem",
                 challenge="session-abc")             # 绑定本次会话
ok = core.verify("./demo.seal.json", "./trusted_keys.json")
# -> {"verdict": "VALID"|"VALID_UNTRUSTED_KEY"|"INVALID", "reason": "...", "trust": "trusted"|"untrusted"}
```

三条使用约定（都是实测出来的，不是设计口号）：

- **判定对错由人负责**：凭证证明"当时这么判、之后没改"，不证明"判对了"。
- **以 `seal_header.subject` 为准**：凭证最外层的未知字段不在签名域内，验签会给
  `W_OUTER_FIELDS_UNSIGNED` 告警，但**告警不等于拦截**。
- **信任锚要自己维护**：签名有效 ≠ 签发方可信。对方不在你的 `trusted_keys.json` 里时只会得到
  `VALID_UNTRUSTED_KEY`，不要把它当通过。
