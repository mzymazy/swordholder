# Swordholder MCP Server

给任何支持 MCP 的 Agent（Claude Code / Claude Desktop / Cursor / 自研编排器）加一层**可验签的处置凭证**能力。

解决的是一个具体问题：安全 Agent 做出的告警分诊结论、处置动作、通报结论，默认都是"自说自话"的一段文本——事后无法证明它没有被改过、是谁出的、依据是什么。本 MCP Server 让 Agent 在给出结论的同时盖一个章，任何人（包括甲方、审计、监管）用公钥就能独立验签。

## 工具清单

| 工具 | 作用 | 关键返回 |
|---|---|---|
| `keygen` | 本机生成 ed25519 密钥对，私钥不覆盖、不外传 | `public_key_hex` |
| `seal_record` | 对任意 JSON 记录（告警分诊结论 / 处置单 / 通报）签名封装 | `.seal.json` 路径、`seal_id`、`payload_sha256` |
| `verify_seal` | 重算摘要 + 验签 + 比对信任锚 | `VALID` / `VALID_UNTRUSTED_KEY` / `INVALID` + 原因码 |
| `verify_proof` | 验证仓库原生安全凭证（deterrence proof） | `VALID` / `INVALID` |
| `list_trusted_keys` | 列出信任锚与公钥指纹 | 公钥指纹列表 |

验签失败原因码是可机读的：`E_PAYLOAD_TAMPERED`（记录被改）、`E_BAD_SIGNATURE`（签名对不上）、`E_UNTRUSTED_KEY`（签发方不在信任锚内）、`E_MALFORMED_SEAL`（结构损坏）。

## 运行

```bash
pip install cryptography pyyaml
python mcp_server/server.py          # stdio 传输，由客户端拉起，一般无需手工执行
python mcp_server/selftest.py        # 自测：10 项，全绿才算可用
```

## 接入 Claude Desktop

`claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "swordholder": {
      "command": "python",
      "args": ["<仓库绝对路径>/mcp_server/server.py"]
    }
  }
}
```

接入 Cursor：`.cursor/mcp.json` 同结构，键名改为 `mcpServers` 即可。

## 一次典型调用链

```
Agent: seal_record(payload={alert_id, verdict, actions, confidence},
                   private_key_path=~/keys/swordholder_ed25519_private.pem,
                   subject="ALRT-2026-1023-001")
  → {"ok": true, "seal_path": ".../triage.seal.json", "payload_sha256": "9f3c..."}

审计方（另一台机器、无源码）: verify_seal(seal_path="triage.seal.json")
  → {"verdict": "VALID", "trust": "trusted", "subject": "ALRT-2026-1023-001"}
```

把 seal 文件改一个字（哪怕只是把 `verdict` 由 `true_positive` 改成 `false_positive`），第二次验签立刻变成 `INVALID / E_PAYLOAD_TAMPERED`——这是 `selftest.py` 里真实跑过的断言，不是描述。

## 边界（诚实声明）

- 本 Server 证明的是**"这份记录自签发起未被篡改，且由持有该私钥的一方签发"**，不证明结论本身在业务上正确。结论质量取决于签发方，这正是"准入"要解决的问题，而不是"验签"能解决的问题。
- `keygen` 生成的私钥只落在本机，未做 HSM / KMS 托管；生产场景应改为外部签名服务。
- `seal_record` 的信任建立依赖信任锚登记（`trusted_keys.json`），未登记的公钥只会得到 `VALID_UNTRUSTED_KEY`。

## 许可

Apache-2.0，与本仓库一致。
