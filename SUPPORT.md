---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_dea25a99da9811f1a0ca525400de85a5
    ReservedCode1: QcS5JM/d1xd4KHQk7jejKGN7BJPYStICG6VwOXZBUEeIu/+23c9JUFZ7bwuIlXvK/qHFO6WhAG5Qk11xZJo7uXori6kdOJmz4SaEclr8hox4tEmwjNwX9Z4oQNmKEvFK6HCAy91ELf0vRQwypYryAqJUzJcGusSfPOzXRZxaL3Hc47Lw4mJsYqvZOiQ=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_dea25a99da9811f1a0ca525400de85a5
    ReservedCode2: QcS5JM/d1xd4KHQk7jejKGN7BJPYStICG6VwOXZBUEeIu/+23c9JUFZ7bwuIlXvK/qHFO6WhAG5Qk11xZJo7uXori6kdOJmz4SaEclr8hox4tEmwjNwX9Z4oQNmKEvFK6HCAy91ELf0vRQwypYryAqJUzJcGusSfPOzXRZxaL3Hc47Lw4mJsYqvZOiQ=
---

# 支持渠道（SUPPORT）

先看这三处，多数问题已在里面：

- 安装与验收命令：`README.md`「安装（30 秒）」
- 已知局限与失败族：`README.md`「已知局限」
- 复现要求与依赖：`deliverable/README-oss.md`「复现要求」

---

## 按问题类型分渠道

| 问题类型 | 渠道 | 预期响应 |
|---|---|---|
| 安装失败、命令报错、平台差异 | GitHub Issue（附版本、命令、完整输出） | 7 个工作日内首次回应 |
| 验签结果与预期不一致 | GitHub Issue（**不要附私钥**，附公钥与凭证 JSON） | 7 个工作日内 |
| 安全漏洞（伪造凭证、篡改证据、绕过验证） | GitHub Private vulnerability reporting，**勿开公开 issue** | 确认后 7 个工作日内（见 `SECURITY.md`） |
| 想接入自己的模型/后端 | GitHub Issue，标签 `integration` | 14 个工作日内给出可行性判断 |
| 赛事、评审、媒体、商业合作 | Issue 或邮件，说明用途与是否公开引用 | 14 个工作日内 |
| 治理与流程异议 | Issue，标签 `governance`（走 `GOVERNANCE.md` §3 L3 流程） | 按公示期 |

## 提问前请自检

```bash
swordholder --version
pytest -q --collect-only 2>&1 | tail -3
python scripts/worldclass_probe.py --assert
```

三项输出一并贴上，能省掉一轮往返。

## 不提供的支持

- 代为签发凭证：私钥只在你自己机器上，本项目不托管任何私钥
- 代为背书未复现的结论
- 商业 SLA 与定制开发（当前无此服务）

## 响应能力的诚实说明

本项目为个人维护，无 24×7 值班。响应时限按上表执行，超出时限未回复可在原 issue 中 `@` 维护者升级。
*（内容由AI生成，仅供参考）*
