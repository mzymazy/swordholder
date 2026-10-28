---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: dbc1c155fc9201133fd4bf5993fb4878_aad42382c99f11f1acd7525400cd780f
    ReservedCode1: DbTETTh99OBVdVv6wHNE5bPIdFz1gOkeWmUWQpdTj4jsQdAsm0sFLNoS9DjTB1L7zpdMC7w/uH88aoNMkK32RP2hWJYxiOsUjORsL56sHZShvOYBU3kgmndPhizBX+znvN6sagW3t1tnOHzcuprP47kTquLlcpG8+9h4ZsYWHl3K22f+N1iw2fiID38=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: dbc1c155fc9201133fd4bf5993fb4878_aad42382c99f11f1acd7525400cd780f
    ReservedCode2: DbTETTh99OBVdVv6wHNE5bPIdFz1gOkeWmUWQpdTj4jsQdAsm0sFLNoS9DjTB1L7zpdMC7w/uH88aoNMkK32RP2hWJYxiOsUjORsL56sHZShvOYBU3kgmndPhizBX+znvN6sagW3t1tnOHzcuprP47kTquLlcpG8+9h4ZsYWHl3K22f+N1iw2fiID38=
---

# 运行截图与其复现命令

README 与文档中引用的图片都来自**本机真实运行输出**，不是示意图。为便于阅读，截图按终端风格重绘，并做了两项**已披露的最小处理**：

1. 把本机绝对路径归一为 `<repo>/…`（例如 `O:\…\swordholder_mvp\evidence\x.json` → `<repo>/evidence/x.json`）；
2. 超长输出只保留首尾若干行，中间以 `……（此处省略 N 行）……` 标注。

**除此之外未修改任何字符**：数字、文件名、判定结论均为原始输出。

---

## 1. `verify-proof-valid.png` — 4 份凭证全部 VALID

![4 份凭证校验](images/verify-proof-valid.png)

复现：

```bash
for p in proofs/deterrence_proof_*_ed25519.yaml; do
    python verify_proof.py "$p" --trusted-keys trusted_keys.json --max-age-days 365
done
```

关键行：

```
[verify_proof v0.5] deterrence_proof_baseline_ed25519.yaml -> VALID
[verify_proof v0.5] deterrence_proof_combined_ed25519.yaml -> VALID
[verify_proof v0.5] deterrence_proof_injected_ed25519.yaml -> VALID
[verify_proof v0.5] deterrence_proof_lora_ed25519.yaml -> VALID
```

## 2. `verifier-adversarial-17.png` — 验证器对抗自测 17/17

![验证器对抗自测](images/verifier-adversarial-17.png)

复现：`python evidence/adversarial_verifier_test.py`

覆盖的 17 类攻击：合法凭证、伪造签名（默认/显式 demo 两种口径）、篡改证据块、篡改工件引用、换钥、算法降级、过期、无信任锚、重复顶层键（三种写法）、绑定缺失/结果哈希不符/数量不符、时间戳格式非法、未来时间。关键行：

```
[adversarial_verifier_test v0.5] 17/17 passed -> <repo>/evidence/adversarial_verifier_test_v05.json
```

## 3. `binding-audit-482.png` — 记录 ↔ 工件绑定 482/482

![绑定审计](images/binding-audit-482.png)

复现：`python evidence/verify_artifact_binding.py`

关键行（截图保留了首 4 行与末尾统计，中间逐文件明细以省略标注）：

```
records_total=1191 with_response=482 bound=482 (T1=482 T2=482 T3=482) not_bound=0 structured_only=709
all_bound_scope_A=True  all_content_consistent=True
已写出 evidence/artifact_binding_audit.json
```

含义：482 条承载原始响应的逐题记录，**T1 响应文本哈希 / T2 工件字节哈希 / T3 工件文本以响应原文结尾**三重核验全部成立；709 条聚合统计记录不含逐题响应，如实单列为 `structured_only`，不计入绑定分母。

## 4. `quickstart-oneshot.png` — 一键脚本一次跑通

![一键闭环](images/quickstart-oneshot.png)

复现：`powershell -ExecutionPolicy Bypass -File scripts\quickstart.ps1 -SkipInstall`（Linux/macOS：`bash scripts/quickstart.sh --skip-install`）

四步输出：仓库根与 Python 版本 → 依赖安装（可跳过）→ 4/4 凭证 `VALID` → 17/17 对抗断言 → 482/482 绑定审计，末尾汇总：

```
30 秒离线闭环全部通过：4/4 凭证 VALID、17/17 验证器断言、482/482 记录绑定。
```

## 5. `architecture.png` — 架构总览

![架构总览](images/architecture.png)

架构（非截图）图，逐环说明见 [architecture.md](architecture.md)。

---

## 运行环境（上述输出均在下列环境产生）

| 项 | 值 |
|---|---|
| 操作系统 | Windows 11 |
| Python | 3.11.8 |
| 终端 | PowerShell 5.1 |
| 依赖 | `requirements.txt`（requests / cryptography / pyyaml） |
| 是否需要模型 | **否**（上述四张截图均无需 GPU、Ollama 或权重） |
*（内容由AI生成，仅供参考）*
