# AIGC 标识头：字段含义、为何「看起来冗长」以及不可精简的原因

本文件解释仓库里 23 份对外 Markdown 文件头部那段 YAML front matter（`AIGC:` 段）的来历与维护规则。
它是元说明文档，本身不带 AIGC 头；面向分发/评审的文档才需要带。

## 1. 这段头是什么

示例（摘自 `05_合规声明/作者原创工作说明与AIGC标注.md`）：

```yaml
---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_e9c77876c70411f19b82525400de85a5
    ReservedCode1: urM3KqvfaBqB5Wr9jIfiEFH54qoYFasO8kk73sncJtJLjaWdQjlnWZU5GNEdaf7cjE6mYh...
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_e9c77876c70411f19b82525400de85a5
    ReservedCode2: urM3KqvfaBqB5Wr9jIfiEFH54qoYFasO8kk73sncJtJLjaWdQjlnWZU5GNEdaf7cjE6mYh...
---
```

| 字段 | 含义 | 本仓库取值特征 |
| --- | --- | --- |
| `Label` | 是否含 AI 生成合成内容，`"1"` 表示含 | 全部为 `"1"` |
| `ContentProducer` | 内容制作方标识 | 统一为 `001191440300708461136T1XGW3` |
| `ProduceID` | 单篇内容的制作编号 | 形如 `<32 位十六进制>_<32 位十六进制>`，逐文件唯一 |
| `ReservedCode1` | 制作侧隐式标识（不透明水印） | base64，解码后固定 140 字节 |
| `ContentPropagator` | 内容传播方标识 | 与 `ContentProducer` 相同 |
| `PropagateID` | 传播编号 | 与 `ProduceID` 相同 |
| `ReservedCode2` | 传播侧隐式标识（不透明水印） | 与 `ReservedCode1` 同值 |

口径来源与 AI 辅助范围见 `05_合规声明/作者原创工作说明与AIGC标注.md` 第三节。

## 2. 为什么保留「又长又重复」的写法

`ReservedCode1/2` 是**二进制水印的 base64 文本**，不是可读信息，也不是可以概括的摘要。
以下三种"美化"做法都会造成实质损坏，因此被明确禁止：

1. **删除 `ReservedCode1/2`**：等于丢弃隐式标识本身，合规要素缺失。
2. **任意折行或以 `\` 续行**：YAML 纯量会把换行折叠成空格，base64 被破坏，解码即失败。
3. **用 YAML 锚点/别名（`&rc` / `*rc`）去重**：规范解析器能还原值，但只做正则会话的
   外部解析工具会把 `*rc` 当成字面值，读不到水印——兼容性代价高于几行版面的收益。

同理，`ProduceID` 与 `PropagateID` 相等、`ReservedCode1` 与 `ReservedCode2` 相等是
「自产自传播」场景下的正常取值，不是复制粘贴错误。

## 3. 校验方式

`scripts/check_aigc_headers.py` 做只读校验，已接入 CI（`.github/workflows/verify.yml`
的 `AIGC 标识头一致性守卫` 步骤），任一条件不满足即 CI 红：

- 带 AIGC 头的 Markdown 不少于 20 份（防批量丢失）；
- 七个字段齐全且非空；
- `Label` 为 `"1"`；
- `ProduceID` / `PropagateID` 匹配 `[0-9a-f]{32}_[0-9a-f]{32}`；
- `ReservedCode1/2` 可 base64 解码且长度为 140 字节；
- `ContentProducer` 与 `ContentPropagator` 一致。

本地自检：

```bash
python scripts/check_aigc_headers.py          # 人类可读
python scripts/check_aigc_headers.py --json   # 机器可读摘要
```

## 4. 新增对外文档时怎么做

- 从已有的对外文档复制整段头，**只替换 `ProduceID` / `PropagateID` 与两个 `ReservedCode`**
  （需由原生成工具重新导出，不要手工拼接）；
- 文末保留「内容由AI生成」提示行；
- 提交前跑一次 `scripts/check_aigc_headers.py`。

> 注意：`ReservedCode` 无法手工生成或修复，一旦丢失只能由原导出工具重新导出。
> 这也是它必须原样入库、并配 CI 守卫的根本原因。
