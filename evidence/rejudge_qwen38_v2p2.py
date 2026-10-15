# -*- coding: utf-8 -*-
"""
qwen3.8-27B 两态重判：semantic-v2.1 → semantic-v2.2
====================================================
用升级后的判定器（双条件执行意图 + recitation 严格双条件）对
xmodel_qwen38_baseline.json / xmodel_qwen38_injected.json 中已存响应
重新判定（不重新调用模型），输出 per-case 变化与汇总。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import eval_swordholder_v2 as v2

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
HERE = r"O:\接单\参赛\swordholder_mvp"
EXPECT_MAP = {sc["id"]: sc.get("expect", "") for kind in v2.SCENARIOS for sc in v2.SCENARIOS[kind]}


def rejudge_file(fname):
    p = os.path.join(HERE, "evidence", fname)
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    rows = []
    for c in data["cases"]:
        expect = EXPECT_MAP.get(c["id"], "")
        verdict = v2.JUDGERS_V2[c["kind"]](c.get("response", ""), expect)
        new_passed = bool(verdict["passed"])
        old_passed = bool(c.get("passed"))
        old_sem = c.get("judge", {}).get("semantic_metric", {})
        rows.append({
            "id": c["id"], "kind": c["kind"],
            "old_passed": old_passed, "new_passed": new_passed,
            "changed": old_passed != new_passed,
            "old_semantic": old_sem,
            "new_semantic": verdict.get("semantic", {}),
        })
        if old_passed != new_passed:
            print(f"  [CHANGED] {c['id']:8s} {c['kind']:11s} v2.1={old_passed} -> v2.2={new_passed}")
    total = len(rows)
    changed = [r for r in rows if r["changed"]]
    agg = {"total": total, "changed_count": len(changed),
           "old_pass": sum(1 for r in rows if r["old_passed"]),
           "new_pass": sum(1 for r in rows if r["new_passed"]),
           "changed_ids": [r["id"] for r in changed]}
    print(f"[{fname}] total={total} v2.1_pass={agg['old_pass']} v2.2_pass={agg['new_pass']} changed={agg['changed_count']} ids={agg['changed_ids']}")
    return {"file": fname, "judge_version": v2.JUDGE_VERSION, **agg, "rows": rows}


def main():
    out = {"judge_version": v2.JUDGE_VERSION, "expect_map_used": True,
           "results": [rejudge_file("xmodel_qwen38_baseline.json"),
                       rejudge_file("xmodel_qwen38_injected.json")]}
    out_path = os.path.join(HERE, "evidence", "judge_rejudge_qwen38_v2p2.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[done] -> {out_path}")


if __name__ == "__main__":
    main()
