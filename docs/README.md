---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_a8b1e34ec99f11f1acd7525400cd780f
    ReservedCode1: s4WujlQr1NHOA6F1CucXfN9G7H1S9gz1BTzMNU/Zhob0VJJ+Z5iXdCmcyX5W29KM9Kxsmi9mUvEudwpI+rMZnB6enIVKoEeUJXQLmUjlrwM15YCjDoHnHJ77P//kSeHoZF9Bog+yJsfumazD+3r7bfXoth9TfcKMihYTi5E+SbLzv1FrM1pAzAT7wQk=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_a8b1e34ec99f11f1acd7525400cd780f
    ReservedCode2: s4WujlQr1NHOA6F1CucXfN9G7H1S9gz1BTzMNU/Zhob0VJJ+Z5iXdCmcyX5W29KM9Kxsmi9mUvEudwpI+rMZnB6enIVKoEeUJXQLmUjlrwM15YCjDoHnHJ77P//kSeHoZF9Bog+yJsfumazD+3r7bfXoth9TfcKMihYTi5E+SbLzv1FrM1pAzAT7wQk=
---

# 文档索引（docs/）

本目录放的是**支撑仓库可读性与可复现性的说明文档**（不含证据数据本身；证据在 `../evidence/`、`../proofs/`、`../artifacts_v2*/`）。

## 按角色选阅读路径

**我是评委 / 快速判断项目成色（10 分钟）**

1. [`../README.md`](../README.md) — 先看 TL;DR 一张表（定位 / 价值 / 实测结论 / 30 秒验证 / 门槛）
2. [`../deliverable/README-reviewer.md`](../deliverable/README-reviewer.md) — 评审版：背景 → 方法 → 四态实证 → 攻击面矩阵 → 复现命令 → 局限
3. [`architecture.md`](architecture.md) — 一张架构图看懂实证链怎么闭环
4. [`screenshots.md`](screenshots.md) — 真实运行截图（附复现命令，可自己重跑）

**我是外部开发者 / 想跑起来（30 分钟）**

1. [`../README.md#2-quick-start30-秒离线闭环`](../README.md#2-quick-start30-秒离线闭环) — 一键脚本，纯离线，无需 GPU
2. [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — 环境与提交前的自检清单
3. [`proof-issuance.md`](proof-issuance.md) — 想自己造一份凭证、理解 VALID / INVALID 的判定条件
4. [`architecture.md`](architecture.md) — 想改某一环时，该动哪些文件

**我是安全 / 合规审查者**

1. [`../SECURITY.md`](../SECURITY.md) — 漏洞报告、敏感内容红线、私钥泄露应急
2. [`../PRIVATE_KEY.md`](../PRIVATE_KEY.md) — 私钥为什么不入库、如何自签自验
3. [`proof-issuance.md`](proof-issuance.md) — 凭证字段、判定流程与全部 INVALID 错误码
4. [`../CHANGELOG.md`](../CHANGELOG.md) — 口径变更史（含 semantic-v2.1 → v2.2 的逐题重判记录）

## 文档清单

| 文档 | 一句话说明 |
|---|---|
| [architecture.md](architecture.md) | 架构与数据流：公理注入 → 评测 → 工件 → 聚合 → 出证 → 验证 → CI，逐环给出文件与命令 |
| [proof-issuance.md](proof-issuance.md) | 威慑凭证的结构、验证流程、错误码表，以及"自签 → 被拒 → 自验通过"的实操四步 |
| [screenshots.md](screenshots.md) | README 中每张运行截图的来源命令、运行环境与预期关键行 |
| [images/](images/) | 架构图与关键界面截图（PNG，供 README 与文档引用） |

## 相关根目录文档

| 文档 | 说明 |
|---|---|
| [../README.md](../README.md) | 项目主文档（首屏定位 + 30 秒闭环 + 评测结果 + 门槛 + 治理） |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | 贡献流程 + **改证据/改口径/改凭证的硬规则** |
| [../CHANGELOG.md](../CHANGELOG.md) | 版本与口径变更史 |
| [../SECURITY.md](../SECURITY.md) | 安全政策与应急流程 |
| [../PRIVATE_KEY.md](../PRIVATE_KEY.md) | 私钥不入库说明与生成/使用指引 |
| [../deliverable/README-reviewer.md](../deliverable/README-reviewer.md) | 参赛评审版材料（口径已冻结，不改动） |
| [../deliverable/README-oss.md](../deliverable/README-oss.md) | 开源治理版材料（口径已冻结，不改动） |

> 约定：**叙述性文档可以改，证据与口径不能悄悄改**。任何结论都要能落到 `evidence/*.json`、`proofs/*.yaml`、`artifacts_v2*/` 上并可复算；规则见 [../CONTRIBUTING.md §3](../CONTRIBUTING.md#3-改证据--改凭证--改口径的硬规则重要)。
*（内容由AI生成，仅供参考）*
