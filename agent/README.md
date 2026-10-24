# Agent / Skill

两个可直接运行的部分，服务于同一个目标：**Agent 的判断要能被验签**。

- `agent/` — 最小分诊 Agent。规则引擎离线可跑，LLM 仅做增强（本机 Ollama，可选）。
- `skill/` — 可被 Claude Code / Claude Desktop 直接加载的 skill 文件，规定分诊口径与盖章纪律。

## 跑一遍

```bash
pip install -r requirements.txt
python agent/demo.py          # 3 条样例如警 → 分诊 → 盖章 → 验签 → 篡改检出
python agent/demo.py --llm    # 叠加本地 Ollama（默认 qwen3:8b，可用 SWORDHOLDER_MODEL 覆盖）
```

输出在 `agent/.demo_out/`：每条样例的 `.triage.json`（分诊记录）、`.seal.json`（凭证）、`demo_report.md`（汇总）。

## 设计取舍

| 取舍 | 原因 |
|---|---|
| 规则优先、LLM 可选 | 现场演示不能依赖外部 Key 与网络；LLM 挂掉时结论仍可用 |
| LLM 不改 verdict/severity | 定性口径必须可复现，模型只补成因假设与处置建议 |
| 分诊记录与凭证分离 | 记录可被人读，凭证用于证明记录没被改，职责不混 |
| 私钥只在本机 `keys/` | `keys/`、`*.pem`、`*.seal.json` 均已 gitignore |

## 边界

样例为构造数据，用于演示链路，不是真实客户数据。规则层是**基线**，不是完整检测能力；真实部署应接 EDR/SIEM 的富化字段。
