# 第二阶段：外部效度实测（公开数据集复算）

对 `swordholder/rules.py`（`rules-v1`）在公开安全遥测上做一次可复算的效果评测。
目的不是证明有效，而是把"外部效度"从零补到可被第三方重跑。

## 数据来源与构造

| 项 | 值 |
|---|---|
| 数据集 | splunk/attack_data（MITRE ATT&CK 官方遥测集，Apache-2.0），LFS 走 `media.githubusercontent.com` |
| 技术覆盖 | 14 个 Technique 目录（T1003.001/003、T1047、T1055、T1059.001/003/005、T1071.001、T1105、T1112、T1136.001、T1218.011、T1547.001、T1569.002） |
| 原始文件 | 92 个 `.log`（sysmon / windows-security / system / powershell / auditd / suricata / carbon_black） |
| 原始事件 | 29,888 条（XML WinEventLog 6,631；纯文本 23,257） |
| 评测语料 | 21,064 条告警 = 1,064 条锚定攻击事件 + 20,000 条背景事件（自 28,824 条非锚定事件分层抽样） |

告警构造：一条原始事件 → `alert.normalize(..., fmt="generic")` → `rules.rule_triage()`。
`m1` 只给原始事件名与 channel；`m2` 额外把技术标签写进标题。两者用于检验"判定是否依赖上游命名/标签"。

标签口径（写在 `corpus/alerts_corpus.jsonl` 的 `meta.label`，仅评测侧可见，不进产品输入）：
源自 Technique 目录、且所在文件的确由该技术生成的记录记为 `attack`，其余同目录遥测与其余技术文件记为 `background`。

## 复现

```bash
python scripts/s2_build_corpus.py     # 下载/解析遥测 -> corpus/
python scripts/s2_eval.py             # 指标 -> stage2_metrics.json
python scripts/s2_ablation.py         # 消融 -> stage2_ablations.json
```

## 结果（正结果与负结果一并给出）

见 `metrics.json` 与仓库内报告 `docs/stage2-external-validity.md`。
核心：外部语料上 `true_positive = 0`、`fallback = 20,988/21,064 (99.63%)`、
唯一被触发的定性分支来自**文件名** `suricata_c2`，而非告警证据。
