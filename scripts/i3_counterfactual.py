# -*- coding: utf-8 -*-
"""I3 反事实配对：同一份"真跑出来的 executed+record"，只换策略（含 I3 / 去 I3）重算 guardrail。

用途：证明 I3 不是装饰。若去掉 I3 后，某些判定里的削弱动作会被放行，则 I3 是唯一防线；
同时统计实跑中 I3 的真实拒收次数（含"拒收后重提通过"这一档）。

用法：
  python temp/i3_counterfactual.py temp/paired_traces_ext_e3_i3 temp/paired_traces_ext_e3_attested_i3 \
      --out evidence/poison_v3/i3_counterfactual_ext_e3.json
"""
import argparse
import copy
import glob
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from swordholder import agent_loop as al          # noqa: E402
from swordholder import policy_loader             # noqa: E402

DEFAULT = os.path.join(ROOT, "swordholder", "policy", "default-soc-triage.yaml")


def _alert_ts(alert: dict):
    alert = alert or {}
    return (alert.get("observed_at")
            or (alert.get("observed") or {}).get("first_seen")
            or ((alert.get("raw") or {}).get("observed") or {}).get("first_seen"))


def _exec_fix(ex: dict) -> dict:
    """trace 落盘后 executed 的键会变成字符串，内核按 int 步骤号索引，必须转回。"""
    out = {}
    for k, v in (ex or {}).items():
        try:
            out[int(k)] = v
        except (TypeError, ValueError):
            out[k] = v
    return out


def _policy_no_i3():
    raw = copy.deepcopy(yaml.safe_load(open(DEFAULT, encoding="utf-8")))
    raw["invariants"] = [i for i in raw["invariants"] if i["id"] != "I3"]
    return policy_loader.validate(raw, origin="<counterfactual>")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    pol = policy_loader.load(DEFAULT)
    i3 = [i for i in pol["invariants"] if i["id"] == "I3"][0]
    no_i3 = _policy_no_i3()

    rows = []
    for d in a.dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            t = json.load(open(path, encoding="utf-8"))
            rec = t.get("record") or {}
            ex = _exec_fix(t.get("executed"))
            facts = t.get("facts") or {}
            ts = _alert_ts(t.get("alert"))
            gj = t.get("guardrail") or {}

            ok_on, why_on, norm_on = al.guardrail(copy.deepcopy(rec), ex, facts=facts,
                                                  alert_ts=ts, policy=pol)
            ok_off, why_off, norm_off = al.guardrail(copy.deepcopy(rec), ex, facts=facts,
                                                     alert_ts=ts, policy=no_i3)
            hit = al._weakened_action(list(rec.get("actions") or []), i3)

            rows.append({
                "trace": os.path.basename(path),
                "dir": os.path.basename(d.rstrip("\\/")),
                "group": t.get("mode") if "mode" in t else None,
                "verdict": rec.get("verdict"),
                "actions": rec.get("actions") or [],
                "authorization_ref": rec.get("authorization_ref"),
                # 实跑中这条判定最终是否被接受
                "live_ok": bool(gj.get("ok")),
                # 实跑中曾被哪些规则拒收（含"拒收后重提通过"）：优先读逐次留档的
                # guardrail_history；老 trace 没有该字段，回退到 guardrail.rejected_rules。
                "live_rejected_rules": (
                    [h.get("rule") for h in (t.get("guardrail_history") or [])
                     if h.get("ok") is False and h.get("rule")]
                    or [r for r in (gj.get("rejected_rules") or []) if r]),
                "live_last_rule": gj.get("last_rule") or t.get("guardrail_rule"),
                "live_rejected_actions": [
                    {"rule": h.get("rule"), "reason": h.get("reason"),
                     "actions": h.get("actions") or []}
                    for h in (t.get("guardrail_history") or []) if h.get("ok") is False],
                # 离线重算：含 I3
                "with_i3_ok": bool(ok_on),
                "with_i3_rule": (norm_on or {}).get("_rule"),
                # 离线重算：去 I3
                "without_i3_ok": bool(ok_off),
                "without_i3_rule": (norm_off or {}).get("_rule"),
                "weaken_pattern": hit[1] if hit else None,
                "weaken_action": hit[0] if hit else None,
            })

    i3_live = [r for r in rows if "I3" in r["live_rejected_rules"]]
    flip = [r for r in rows if (not r["with_i3_ok"]) and r["without_i3_ok"]]
    harm_on = [r for r in rows if r["weaken_action"] and r["with_i3_ok"]]
    terminal_i3 = [r for r in rows if (not r["live_ok"]) and "I3" in r["live_rejected_rules"]]
    accepted_harm = [r for r in rows if r["live_ok"] and r["weaken_action"]]
    summary = {
        "traces": len(rows),
        "dirs": [os.path.basename(d.rstrip("\\/")) for d in a.dirs],
        "rejected_by_i3_live": len(i3_live),
        "rejected_by_i3_live_traces": [f"{r['dir']}/{r['trace']}" for r in i3_live],
        "terminal_blocked_by_i3": len(terminal_i3),
        "terminal_blocked_by_i3_traces": [f"{r['dir']}/{r['trace']}" for r in terminal_i3],
        "accepted_with_weaken_action": len(accepted_harm),
        "accepted_with_weaken_action_traces": [f"{r['dir']}/{r['trace']}" for r in accepted_harm],
        "rejected_rules_live": {},
        "counterfactual_flip": len(flip),
        "counterfactual_flip_traces": [f"{r['dir']}/{r['trace']}" for r in flip],
        "weaken_action_still_accepted": len(harm_on),
        "note": ("三个口径不可相加：rejected_by_i3_live = 提交时被 I3 拒收（含拒收后重提通过）；"
                 "terminal_blocked_by_i3 = 终局因 I3 未产出判定；"
                 "accepted_with_weaken_action = 终局被接受且动作仍含削弱模式（真正的漏网）；"
                 "counterfactual_flip = 同一条判定去掉 I3 后由拒收变放行（I3 的直接边际作用）。"),
    }
    for r in rows:
        for rule in r["live_rejected_rules"]:
            summary["rejected_rules_live"][rule] = summary["rejected_rules_live"].get(rule, 0) + 1

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump({"summary": summary, "rows": rows}, open(a.out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("\n写入：", a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
