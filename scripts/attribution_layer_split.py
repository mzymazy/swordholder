"""归因分层：把「流程增益」与「不变量拦截」放进同一张表。

要解决的问题
------------
`paired_attribution.py` 已经能回答"同一轨迹只换 facts 口径，结论翻不翻"。但它输出的
`counterfactual_blocked = 12` 只有一个数，读者无法判断这 12 条到底是：

  a) 证据层自己拒收了（流程增益），还是
  b) 证据层撤销凭证后，由不变量 I1/I2 按策略拦下的（不变量拦截）。

两者口径完全不同：前者是"新加的一道工序"，后者是"原有防线在拿到干净 facts 后生效"。
混成一个数，对外就只能说"证明了证据层有用"，这是把工程结构说成了防护能力。

本脚本从 paired_attribution 的产出里把三层拆开并列表：

  1. 证据层撤证（withheld / E_NO_ATTESTATION）——推动项，不是结论；
  2. 不变量拦截（layer=invariant，按 I/S 编号计数）——真正的拒收落点；
  3. 结构·阈值层退回（layer=schema）——模型输出不合规，不算防线功劳。

另外回答一个必须回答的问题：撤证的 19 条里，只有 12 条被拦住，剩下的去哪了。
逐条给出归类（原判不是 false_positive / 判了但没挂授权单），不给"其余若干"这种含糊账。

用法
----
python scripts/attribution_layer_split.py \
    --paired evidence/poison_v2/paired_attribution_b2_4models_36.json \
    --out evidence/poison_v2/attribution_layer_split_b2_4models_36
"""

from __future__ import annotations

import argparse
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(ROOT, "swordholder", "policy", "default-soc-triage.yaml")

SCOPE_NOTES = [
    "本表是判定层分列，不是端到端防护效果；不含模型看到拒收后的再规划。",
    "证据层撤证数与不变量拦截数不可相加：撤证是前置动作，拦截是结论落点，同一批单元上它们是因果链的两端。",
    "结构·阈值层退回不是防线功劳，模型输出不合规被退回，与「拦住了攻击」无关，必须单列。",
    "按引擎分格 n≤9，只可作线索，不可用于模型排序。",
]


def _pick(units: list[dict]) -> list[dict]:
    return [u for u in units if "error" not in u]


def _layer_table(units: list[dict], key: str) -> dict:
    out = {"admit": 0, "schema": 0, "invariant": 0}
    rules: dict[str, int] = {}
    unlabeled = 0
    rkey = key.replace("layer_", "rule_")
    for u in units:
        layer = str(u.get(key) or "schema")
        out[layer if layer in out else "schema"] += 1
        r = u.get(rkey)
        if r:
            rules[str(r)] = rules.get(str(r), 0) + 1
        elif layer == "invariant":
            # 记了"被不变量拦住"却拿不出编号：统计退化成文本匹配，无法审计
            unlabeled += 1
    return {"layers": out, "rules": dict(sorted(rules.items())), "unlabeled_invariant": unlabeled}


def _withdrawn_outcome(units: list[dict]) -> dict:
    """撤证之后去哪了：逐条归类，不留"其余"。"""
    buckets = {
        "blocked_by_invariant": [],
        "no_effect_not_false_positive": [],
        "no_effect_false_positive_without_ref": [],
        "no_effect_other": [],
    }
    for u in units:
        if not u.get("seal_stats", {}).get("withheld"):
            continue
        tag = f"{u.get('engine')}/{u.get('mode')}/s{u.get('seed')}"
        if u.get("layer_a") == "invariant":
            buckets["blocked_by_invariant"].append(tag)
            continue
        verdict = str(u.get("original_verdict") or "")
        if verdict != "false_positive":
            buckets["no_effect_not_false_positive"].append(tag)
        elif not u.get("has_authorization_ref"):
            buckets["no_effect_false_positive_without_ref"].append(tag)
        else:
            buckets["no_effect_other"].append(tag)
    return {k: {"n": len(v), "units": sorted(v)} for k, v in buckets.items()}


def build(paired: dict) -> dict:
    units = paired.get("units") or []
    good = _pick(units)
    v = _layer_table(good, "layer_v")
    a = _layer_table(good, "layer_a")
    issued = [u for u in good if u.get("seal_stats", {}).get("issued")]
    return {
        "source_paired": paired.get("data_source"),
        "n_units": len(units),
        "n_paired": len(good),
        "n_excluded": len(units) - len(good),
        "table": {
            "value_only": v,
            "attested": a,
        },
        "attestation": {
            "units_withdrawn": sum(1 for u in good if u.get("seal_stats", {}).get("withheld")),
            "withheld_calls": paired.get("overall", {}).get("seal_withheld_total"),
            "units_e_no_attestation": paired.get("overall", {}).get("units_e_no_attestation"),
            "units_issued": len(issued),
            "issued_calls": paired.get("overall", {}).get("seal_issued_total"),
            # 真工单签发成功即必须放行：这是"不误拦"的离线检查点
            "true_ticket_units_admitted": sum(1 for u in issued if u.get("admit_a")),
        },
        "withdrawn_outcome": _withdrawn_outcome(good),
        "by_mode": {m: {"value_only": _layer_table([u for u in good if u.get("mode") == m], "layer_v"),
                        "attested": _layer_table([u for u in good if u.get("mode") == m], "layer_a")}
                    for m in sorted({u.get("mode") for u in good if u.get("mode")})},
        "scope_notes": SCOPE_NOTES,
    }


def render_md(rep: dict) -> str:
    v = rep["table"]["value_only"]
    a = rep["table"]["attested"]
    at = rep["attestation"]
    wo = rep["withdrawn_outcome"]
    rules = sorted(set(v["rules"]) | set(a["rules"])) or ["—"]
    lines = [
        "# 归因分层：流程增益 vs 不变量拦截（同一轨迹重放）",
        "",
        f"数据源：`{', '.join(rep.get('source_paired') or [])}`；"
        f"轨迹 {rep['n_units']} 条，可配对 {rep['n_paired']} 条，排除 {rep['n_excluded']} 条。",
        "",
        "## 1. 拒收落点（两口径并列表）",
        "",
        "| 层级 | value_only 口径 | attested 口径 | 说明 |",
        "| --- | --- | --- | --- |",
        f"| 放行 | {v['layers']['admit']} | {a['layers']['admit']} | 判定通过、结论成立 |",
        f"| 结构·阈值层退回 | {v['layers']['schema']} | {a['layers']['schema']} | 模型输出不合规被退回，非防线功劳 |",
    ]
    for r in rules:
        if r == "—":
            lines.append("| 不变量拦截 | 0 | 0 | — |")
            break
        lines.append(f"| 不变量 {r} 拦截 | {v['rules'].get(r, 0)} | {a['rules'].get(r, 0)} | "
                     f"策略包 `{os.path.basename(POLICY)}` 中 {r} 命中即拒收 |")
    lines += [
        "",
        "## 2. 证据层做了什么",
        "",
        "| 指标 | 数值 | 含义 |",
        "| --- | --- | --- |",
        f"| 撤证单元数 | {at['units_withdrawn']} | 伪造工单拿不到凭证，被踢出 facts |",
        f"| 撤证调用数 | {at['withheld_calls']} | 同一单元可能多次 lookup_ticket |",
        f"| E_NO_ATTESTATION 单元数 | {at['units_e_no_attestation']} | 审计里实际出现的拒收码 |",
        f"| 真工单签发单元数 | {at['units_issued']} | 真实数据源返回过 → 签发 |",
        f"| 签发后仍放行 | {at['true_ticket_units_admitted']} | 不误拦检查：签发成功即必须放行 |",
        "",
        "## 3. 撤证去哪了（不留“其余若干”）",
        "",
        "| 去向 | 条数 | 说明 |",
        "| --- | --- | --- |",
        f"| 落到不变量拦截 | {wo['blocked_by_invariant']['n']} | 撤证后值不在 facts → I1 命中 |",
        f"| 原判非误报，撤证无影响 | {wo['no_effect_not_false_positive']['n']} | 判 true_positive/suspicious，本就无需授权单 |",
        f"| 原判误报但未挂授权单 | {wo['no_effect_false_positive_without_ref']['n']} | 撤证前后都不满足 I1 前置，结论不变 |",
        f"| 其他 | {wo['no_effect_other']['n']} | 需人工复核，非零即视为口径缺口 |",
        "",
        "## 4. 按模式",
        "",
        "| 模式 | value_only 放行/退回/拦截 | attested 放行/退回/拦截 |",
        "| --- | --- | --- |",
    ]
    for m, d in rep["by_mode"].items():
        lv, la = d["value_only"]["layers"], d["attested"]["layers"]
        lines.append(f"| {m} | {lv['admit']}/{lv['schema']}/{lv['invariant']} | "
                     f"{la['admit']}/{la['schema']}/{la['invariant']} |")
    lines += ["", "## 5. 口径纪律", ""]
    lines += [f"- {n}" for n in rep["scope_notes"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paired", default=os.path.join(
        ROOT, "evidence", "poison_v2", "paired_attribution_b2_4models_36.json"))
    ap.add_argument("--out", default=os.path.join(
        ROOT, "evidence", "poison_v2", "attribution_layer_split_b2_4models_36"))
    a = ap.parse_args()

    with open(a.paired, encoding="utf-8") as f:
        paired = json.load(f)
    rep = build(paired)

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out + ".json", "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    with open(a.out + ".md", "w", encoding="utf-8") as f:
        f.write(render_md(rep))

    v, at = rep["table"]["value_only"], rep["table"]["attested"]
    print(json.dumps({"paired": rep["n_paired"],
                      "value_only": v, "attested": at,
                      "attestation": rep["attestation"],
                      "withdrawn_outcome": {k: x["n"] for k, x in rep["withdrawn_outcome"].items()}},
                     ensure_ascii=False, indent=2))
    print(f"写入：{a.out}.json / .md")
    # 口径缺口：出现"其他"去向或结构层退回混入拦截，直接失败
    bad = []
    if rep["withdrawn_outcome"]["no_effect_other"]["n"]:
        bad.append("撤证去向存在未归类单元")
    if rep["table"]["attested"]["unlabeled_invariant"] or rep["table"]["value_only"]["unlabeled_invariant"]:
        bad.append("存在无编号的不变量拦截（统计已退化为文本匹配）")
    if v["layers"]["invariant"] and not v["rules"]:
        bad.append("value 口径出现无编号的 invariant 拒收")
    if bad:
        print("\n[FAIL] " + "；".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
