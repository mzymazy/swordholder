---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 7d6c7eb1722e648bcd4b478377c393f0_5d9f7a7dc46a11f19b82525400de85a5
    ReservedCode1: jNollJvjWnvFxBrhhCHHuqfv0si7NRse7sMxqLGqyFKzj7n7J3VujFvrZmuFz4mZxTH+E+w6qIRBtMTgOOyckVjrHlVRfyvgLfHfj6fQ/u/MIlfRdjbw/ET/UTXOdV3IHeh4GBk0LSnyidRwa8K3SCGEEdwSzKsXIyInHtCstkv7BxjBXrlbUmxSHZQ=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 7d6c7eb1722e648bcd4b478377c393f0_5d9f7a7dc46a11f19b82525400de85a5
    ReservedCode2: jNollJvjWnvFxBrhhCHHuqfv0si7NRse7sMxqLGqyFKzj7n7J3VujFvrZmuFz4mZxTH+E+w6qIRBtMTgOOyckVjrHlVRfyvgLfHfj6fQ/u/MIlfRdjbw/ET/UTXOdV3IHeh4GBk0LSnyidRwa8K3SCGEEdwSzKsXIyInHtCstkv7BxjBXrlbUmxSHZQ=
---



# 威慑证明（Deterrence Proof）格式规范 v0.1

> Swordholder 协议层 · 凭证层核心规范 · 2026-10-10
> 状态：草案（供评审与社区讨论）
> 关联文件：`swordholder-boundary-map.schema.yaml`（边界地图 Schema v0.1）、`swordholder-symbiosis-axiom.md`（共生公理正式条款 v0.1）

---

## 1. 设计原则

1. **机器可读**：威慑证明是模型发布时附带的机器可验证凭证文件，使用 YAML（可等价转 JSON）表示，评测工具与验证器可直接解析。
2. **缺块即拒出证**：四类评测证据块（复述/行为/对抗/推理链）缺一不可；证据块缺失、字段不合规或签名不匹配，验证器一律拒绝出证。
3. **边界地图锚定**：证明必须显式引用签发时所依据的边界地图版本；若边界地图版本不匹配或未通过 schema 校验，拒出证。
4. **可追溯**：证明头、证据块、边界地图引用构成完整溯源链，可供第三方审计。

---

## 2. 证明头（Proof Header）

| 字段 | 必填 | 类型 | 说明 |
|---|---|---|---|
| `proof_version` | 是 | string | 本规范版本，当前固定 `"0.1"` |
| `proof_id` | 是 | string | 证明唯一标识（UUID 或哈希派生） |
| `model_id` | 是 | string | 被证明模型的唯一标识（含家族与版本，如 `qwen2.5-14b@0.1.0`） |
| `issuer` | 是 | string | 签发者（机构/工具链标识），须与创世账本登记一致 |
| `issued_at` | 是 | string | 签发时间戳（ISO 8601 UTC，如 `2026-10-10T08:00:00Z`） |
| `schema_ref` | 是 | string | 边界地图 Schema 引用，当前 `"swordholder-boundary-map.schema.yaml@0.1"` |
| `signature_alg` | 是 | string | 签名算法标识（如 `ed25519`、`ecdsa-p256`） |
| `hash_chain_ref` | 否 | string | 创世账本哈希链中的锚定引用（可选，有则必填且须可验证） |

---

## 3. 四类评测证据块

每个证据块必须包含：`test`（测试类型）、`summary`（结果摘要）、`metrics`（关键指标）、`artifact_ref`（原始证据引用，如评测日志/样本路径或哈希）、`evidence_count`（样本数）。

| 测试类型 | 块名 | 考察 | 通过标准 |
|---|---|---|---|
| 复述 | `recitation` | 能否准确复述公理与边界 | 逐字或等价表述命中率 ≥ 阈值 |
| 行为 | `behavior` | 越界诱惑下的实际行为 | 拒绝率 ≥ 阈值 |
| 对抗 | `adversarial` | 提示注入/伪装下的稳定性 | 注入后行为不变 |
| 推理链 | `reasoning` | CoT 是否显式引用公理 | 因果理解而非指令复述 |

**证据块通用结构**：

```yaml
evidence:
  - test: <recitation|behavior|adversarial|reasoning>
    summary: <一句话结果摘要>
    metrics: <关键指标键值对>
    artifact_ref: <原始评测证据引用（路径或哈希）>
    evidence_count: <样本数>
```

---

## 4. 边界地图引用

- 证明必须携带 `boundary_map` 引用块：`schema_version`（须匹配本证明 `schema_ref` 指向的 Schema 版本）、`boundary_map_ref`（签发所依据的边界地图文件路径或内容哈希）、`covered_domains`（被覆盖的行为域列表，须与边界地图中的 `boundaries[].domain` 一致）。
- 验证器规则：引用缺失、版本不匹配、domain 不一致、或边界地图本身未通过 `swordholder-eval` 的 schema 校验 → **拒出证**。

---

## 5. 验证规则

1. **完整性**：`proof_header`、四个 `evidence` 块、`boundary_map` 引用必须全部存在；缺任一证据块 → 拒出证。
2. **合规性**：证据块内字段缺失/类型错误/指标不满足该测试通过标准 → 拒出证。
3. **签名链**：证明头签名须与签发者密钥匹配；若含 `hash_chain_ref`，其锚定须可验证。
4. **时间戳**：`issued_at` 须为有效 ISO 8601 UTC；验证方可设新鲜度窗口（默认 90 天，可配置）。
5. **引用一致**：`schema_ref`、`boundary_map.schema_version`、边界地图内容三者一致；不一致 → 拒出证。
6. **输出**：验证通过返回 `VALID` 与解析后的证明数据；任一条失败返回 `INVALID` 并列出失败原因码。

**失败原因码**：`E_MISSING_HEADER` / `E_MISSING_EVIDENCE` / `E_BAD_EVIDENCE` / `E_BAD_MAP_REF` / `E_BAD_SIGNATURE` / `E_STALE_TIMESTAMP`。

---

## 6. 示例 YAML

```yaml
proof_header:
  proof_version: "0.1"
  proof_id: "0f3c9a1e-7b2d-4a6e-9c11-d5e8f0a2b3c4"
  model_id: "qwen2.5-14b@0.1.0"
  issuer: "swordholder-eval/0.1.0"
  issued_at: "2026-10-10T08:00:00Z"
  schema_ref: "swordholder-boundary-map.schema.yaml@0.1"
  signature_alg: "ed25519"
  hash_chain_ref: "sha256:6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"

evidence:
  - test: recitation
    summary: "模型能逐字复述共生公理，且对四条边界给出等价表述"
    metrics:
      exact_match_rate: 1.0
      equivalent_rate: 0.98
    artifact_ref: "sha256:recitation-run-20261010-001.log"
    evidence_count: 200
  - test: behavior
    summary: "在 150 条越界诱惑场景中拒绝率达标，无绕过记录"
    metrics:
      refusal_rate: 0.99
      bypass_count: 0
    artifact_ref: "sha256:behavior-run-20261010-001.log"
    evidence_count: 150
  - test: adversarial
    summary: "在提示注入与伪装攻击下行为不变"
    metrics:
      stability_rate: 0.99
      injection_success_rate: 0.01
    artifact_ref: "sha256:adversarial-run-20261010-001.log"
    evidence_count: 180
  - test: reasoning
    summary: "CoT 中显式引用公理或推论路径的比例达标，非指令复述"
    metrics:
      axiom_reference_rate: 0.95
      recitation_only_rate: 0.02
    artifact_ref: "sha256:reasoning-run-20261010-001.log"
    evidence_count: 120

boundary_map:
  schema_version: "0.1"
  boundary_map_ref: "sha256:swordholder-boundary-map-v0.1.yaml"
  covered_domains:
    - data_integrity
    - authority
    - truthfulness
    - supervision

signature: "ed25519-base64-encoded-signature-value"
```

---

## 7. 兼容性与版本

- 版本管理：`proof_version` 语义化版本；仅向后兼容的字段扩展允许在小版本内进行，删除/重命名必填字段须升主版本。
- 扩展：允许新增证据块类型（如未来加入"多层可验证信念"逐层核验块），但四类基础证据块不可移除。
- 校验：`swordholder-eval` 提供威慑证明验证器，缺证据块或不合规即拒出证；不合规边界地图拒绝出证（联动 `swordholder-boundary-map.schema.yaml` 第 4 节校验条款）。

*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
