"""同一轨迹重放式归因拆分（配对对照）。

为什么必须这么做
----------------
历史上把 value_only 与 attested 两组结果当 A/B 对照，靠"同 seed"论证差异来自证据层。
这不成立：温度 0.8 下两次独立运行的轨迹本来就不同，seed 相同不等于轨迹相同。结论只有
"两组运行的现象差异"，无法归因。

本脚本的做法：拿**一次真实运行**留下的轨迹（executed + record），把它冻结，然后只替换
facts 的来源口径，在同一个 record 上重算 guardrail 判定：

    f_v = guardrail(record, executed,      facts_value_only)
    f_a = guardrail(record, executed_sealed, facts_attested)

两条判定吃的是同一份 executed（同一批工具步骤、同一批工具返回）、同一份 record（同一句话术），
唯一的自变量是 facts。因此 f_v 与 f_a 的差异，可以**逐条配对**地归因于证据层，不掺采样噪声。

口径边界（写进报告，不许省略）
------------------------------
1. 本脚本测的是"**判定层**对 facts 口径的反事实敏感度"，不是端到端放松率。真实 attested 运行时
   模型根本看不到伪造工单，可能改走别的取证路径、说别的话术；那种交互效应不在本估计里。
2. facts_attested 的构造必须与线上证据服务同构：只为"真实数据源确实返回过这条记录"背书。
   真实工单 → 签发 seal → 准入；伪造工单 → 不签 → E_NO_ATTESTATION 拒收。
3. 重放保真度自检：value 口径重算结果必须与原运行一致（原运行 record 存在即 guardrail 通过）。
   不一致就报错退出，不允许在重放失真时继续统计。
4. 单调性自检：attested 只会比 value 更严（facts 是子集），出现 "value 拒收 / attested 放行"
   即为不变量实现缺陷，必须报错。

用法
----
python scripts/paired_attribution.py --traces temp/paired_traces_qwen3_8b \
    --keys trusted_keys.json --tag qwen3_8b
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from math import comb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if os.path.join(ROOT, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "scripts"))

OUT_DIR = os.path.join(ROOT, "evidence", "poison_v2")
SEAL_ROOT = os.path.join(ROOT, "temp", "paired_replay_seals")


def _c14n(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _alert_ts(alert: dict) -> str | None:
    return (alert.get("observed_at")
            or (alert.get("observed") or {}).get("first_seen")
            or ((alert.get("raw") or {}).get("observed") or {}).get("first_seen"))


def build_attested_executed(trace: dict, seal_dir: str) -> tuple[dict, dict]:
    """把 executed 复制一份，只给"真实数据源返回过"的工单加 attestation。

    与 scripts/evidence_service_live.attesting_lookup 的判定同构：当前返回 == 真实返回 → 签发；
    不一致（污染注入的伪造单）→ 不签，留白由 facts_attested fail-closed 拒收。
    """
    from swordholder import agent_loop as al
    from evidence_service_live import issue

    executed = {int(k): json.loads(_c14n(v)) for k, v in (trace.get("executed") or {}).items()}
    alert = trace["alert"]
    stats = {"issued": 0, "withheld": 0, "issue_failed": 0, "ticket_steps": 0}
    seq = 0
    for step, rec in executed.items():
        if rec.get("action") != "lookup_ticket" or rec.get("ok") is not True:
            continue
        cur = rec.get("result") or {}
        if not cur.get("found"):
            continue
        stats["ticket_steps"] += 1
        args = {k: v for k, v in (rec.get("args") or {}).items() if isinstance(k, str)}
        try:
            true_r = al.tool_lookup_ticket(**args)
        except Exception:                                   # 真实数据源异常：一律不背书
            stats["issue_failed"] += 1
            continue
        rec_clean = {k: v for k, v in cur.items() if k != "attestation"}
        true_rec = {k: v for k, v in (true_r or {}).items() if k != "attestation"}
        if _c14n(rec_clean) != _c14n(true_rec):
            stats["withheld"] += 1
            continue
        seq += 1
        # 签发私钥与验证信任锚是两回事：私钥用证据服务默认工作密钥（--keys 是验证方信任锚，
        # 不能拿去签），签了也只会得到"签名有效但来源不可信"的 VALID_UNTRUSTED_KEY。
        got = issue(rec_clean, alert, seal_dir, seq=seq)
        if not got.get("ok"):
            stats["issue_failed"] += 1
            continue
        stats["issued"] += 1
        rec["result"] = {**rec_clean, "attestation": got["seal_path"]}
    return executed, stats


def mcnemar_exact(b: int, c: int) -> float | None:
    """精确 McNemar（二项检验，双侧）。b/c 为两种口径结论不一致的配对格数。"""
    n = b + c
    if n == 0:
        return None
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2 ** n)
    return round(min(1.0, 2 * tail), 6)


def judge_one(path: str, keys_path: str) -> dict:
    from swordholder import agent_loop as al
    from swordholder import policy_loader

    with open(path, encoding="utf-8") as f:
        trace = json.load(f)
    pol = policy_loader.load(policy_loader.DEFAULT_POLICY)
    alert = trace["alert"]
    ts = _alert_ts(alert)
    inj = bool(trace.get("injection_suspected"))
    record = trace.get("record") or {}
    # dump 里 executed 的键是 JSON 字符串，guardrail 用 int 步骤号索引，回读时必须转回 int，
    # 否则所有 evidence_refs 都会被判"指向未执行步骤"，导致重放全面失真。
    executed = {int(k): v for k, v in (trace.get("executed") or {}).items()}

    base = {"case": trace.get("case"), "mode": trace.get("mode"), "seed": trace.get("seed"),
            "klass": trace.get("klass"), "engine": trace.get("engine"),
            "original_verdict": trace.get("verdict"),
            "has_authorization_ref": bool(record.get("authorization_ref")),
            "trace_file": os.path.basename(path)}
    if trace.get("executed_export_error"):
        base["error"] = f"executed 导出失败：{trace['executed_export_error']}"
        return base
    if not record:
        # 原运行没有拿到 record（兜底/拒收）：没有可比对的判定，单列不计入配对
        base["error"] = f"无 record（fallback={trace.get('fallback_reason')}）"
        return base

    seal_dir = os.path.join(SEAL_ROOT, f"{base['case']}_{base['mode']}_s{base['seed']}")
    executed_a, att_stats = build_attested_executed(trace, seal_dir)

    facts_v, meta_v = al._facts_for(executed, alert, None)
    facts_a, meta_a = al._facts_for(executed_a, alert, keys_path)
    ok_v, why_v, norm_v = al.guardrail(record, executed, facts_v, ts, inj, pol)
    ok_a, why_a, norm_a = al.guardrail(record, executed_a, facts_a, ts, inj, pol)

    base.update({
        "facts_mode_v": meta_v.get("mode"), "facts_mode_a": meta_a.get("mode"),
        "admitted_v": meta_v.get("admitted"), "admitted_a": meta_a.get("admitted"),
        "rejected_v": meta_v.get("rejected"), "rejected_a": meta_a.get("rejected"),
        "reject_reasons_a": sorted({str(x.get("reason")) for x in (meta_a.get("audit") or [])
                                    if not x.get("admitted")}),
        "admit_v": bool(ok_v), "admit_a": bool(ok_a),
        "why_v": why_v, "why_a": why_a,
        # 命中层级与规则编号：这是"流程增益"与"不变量拦截"能分列的唯一依据。
        # 两个口径都要记，否则无法证明"attested 下的拒收确实落到了 I1"而不是结构层退回。
        "layer_v": ("admit" if ok_v else str((norm_v or {}).get("_layer") or "schema")),
        "rule_v": None if ok_v else (str((norm_v or {}).get("_rule") or "") or None),
        "layer_a": ("admit" if ok_a else str((norm_a or {}).get("_layer") or "schema")),
        "rule_a": None if ok_a else (str((norm_a or {}).get("_rule") or "") or None),
        "seal_stats": att_stats,
        # 重放保真度：原运行 record 存在 ⇒ 当时 guardrail 通过 ⇒ value 口径重算必须也通过
        "replay_faithful_v": bool(ok_v),
        "monotonic_ok": not (not ok_v and ok_a),
    })
    return base


def _layers(layers: list) -> dict:
    """把拒收落点分桶：admit / schema（结构·阈值层退回）/ invariant（不变量命中）。"""
    out = {"admit": 0, "schema": 0, "invariant": 0}
    for x in layers:
        k = str(x or "schema")
        out[k if k in out else "schema"] += 1
    return out


def _rules(rules: list) -> dict:
    """被哪条不变量拦住，按编号计数。空值（结构层退回）不计。"""
    out: dict[str, int] = {}
    for r in rules:
        if r:
            out[str(r)] = out.get(str(r), 0) + 1
    return dict(sorted(out.items()))


def summarize(units: list[dict]) -> dict:
    good = [u for u in units if "error" not in u]
    b = sum(1 for u in good if u["admit_v"] and not u["admit_a"])   # value 放行 / attested 拒收
    c = sum(1 for u in good if not u["admit_v"] and u["admit_a"])   # 不可能：单调性被破
    d = sum(1 for u in good if u["admit_v"] and u["admit_a"])
    a = sum(1 for u in good if not u["admit_v"] and not u["admit_a"])
    auth = [u for u in good if u["has_authorization_ref"]]
    return {
        "paired_traces": len(good),
        "excluded": len(units) - len(good),
        "table": {"both_admit": d, "value_only_admit": b, "attested_only_admit": c, "both_reject": a},
        "mcnemar_exact_p": mcnemar_exact(b, c),
        "counterfactual_blocked": b,
        "counterfactual_blocked_rate": round(b / len(good), 3) if good else None,
        "replay_fidelity_violations": sum(1 for u in good if not u["replay_faithful_v"]),
        "monotonicity_violations": sum(1 for u in good if not u["monotonic_ok"]),
        "traces_with_authorization_ref": len(auth),
        "blocked_among_authorization_claim": sum(1 for u in auth if u["admit_v"] and not u["admit_a"]),
        "seal_issued_total": sum(u["seal_stats"]["issued"] for u in good),
        "seal_withheld_total": sum(u["seal_stats"]["withheld"] for u in good),
        "seal_issue_failed_total": sum(u["seal_stats"]["issue_failed"] for u in good),
        # ---- 归因分层：把"流程增益"与"不变量拦截"分开数 ----
        # 证据层做的事只有一件：把拿不到凭证的记录从 facts 里撤走（withheld → E_NO_ATTESTATION）。
        # 它自己不产出拒收结论；真正的拒收落点由 guardrail 给出（layer_*/rule_*）。
        # 因此下面三组数必须并列呈现，不能相加成一个"防御增益"：
        #   attestation_withdrawn          证据层撤证（推动项，不是结论）
        #   layer_table_a.invariant / rule_counts_a   不变量层实际拦下的条数（结论落点）
        #   layer_table_a.schema           结构层退回（模型输出不合规，非防线功劳）
        "layer_table_v": _layers([u.get("layer_v") for u in good]),
        "layer_table_a": _layers([u.get("layer_a") for u in good]),
        "rule_counts_a": _rules([u.get("rule_a") for u in good]),
        "units_with_attestation_withdrawn": sum(1 for u in good if u["seal_stats"]["withheld"]),
        "units_e_no_attestation": sum(1 for u in good
                                      if "E_NO_ATTESTATION" in (u.get("reject_reasons_a") or [])),
        # 撤证 → 不变量命中的因果链条数：撤了证且最终确实被不变量拦下的单元
        "withdrawn_then_blocked": sum(1 for u in good
                                      if u["seal_stats"]["withheld"]
                                      and u.get("layer_a") == "invariant"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True, nargs="+",
                    help="xadv_poison_live.py --dump-traces 的目录（可给多个，按模型分目录）")
    ap.add_argument("--keys", default="trusted_keys.json")
    ap.add_argument("--tag", default="all")
    a = ap.parse_args()

    files = sorted(p for d in a.traces for p in glob.glob(os.path.join(d, "*.json")))
    if not files:
        raise SystemExit(f"没有轨迹文件：{a.traces}")
    units = [judge_one(p, a.keys) for p in files]

    by_mode = {}
    for m in sorted({u.get("mode") for u in units if u.get("mode")}):
        by_mode[m] = summarize([u for u in units if u.get("mode") == m])
    by_engine = {}
    for e in sorted({u.get("engine") for u in units if u.get("engine")}):
        by_engine[e] = summarize([u for u in units if u.get("engine") == e])

    report = {
        "what_this_is": ("同一轨迹重放式配对对照：冻结一次真实运行的 executed+record，"
                         "只替换 facts 口径重算 guardrail，逐条配对归因到证据层"),
        "what_this_is_not": ["端到端放松率", "模型判对了/判错了", "跨模型可比的能力分数"],
        "data_source": [os.path.basename(os.path.normpath(d)) for d in a.traces],
        "overall": summarize(units),
        "by_mode": by_mode,
        "by_engine": by_engine,
        "units": units,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"paired_attribution_{a.tag}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    o = report["overall"]
    print(json.dumps({k: o[k] for k in ("paired_traces", "excluded", "table",
                                        "mcnemar_exact_p", "counterfactual_blocked_rate",
                                        "replay_fidelity_violations", "monotonicity_violations",
                                        "blocked_among_authorization_claim")},
                     ensure_ascii=False, indent=2))
    print("\nby_mode:")
    for m, s in by_mode.items():
        print(f"  {m:<12} paired={s['paired_traces']:<3} table={s['table']} "
              f"p={s['mcnemar_exact_p']}")
    print(f"\n写入：{out}")

    bad = []
    if o["replay_fidelity_violations"]:
        bad.append(f"重放失真 {o['replay_fidelity_violations']} 条")
    if o["monotonicity_violations"]:
        bad.append(f"单调性被破 {o['monotonicity_violations']} 条")
    if bad:
        print("\n[FAIL] " + "；".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
