# -*- coding: utf-8 -*-
"""S8：篡改**步级定位**能力修复的对照实测台（修复前 / 修复后 同一套用例）。

修复前（legacy）= 0.7.4 语义：凭证只封 head + digest，`anchor_stride=0` 可精确复现；
修复后（default / exact）= 0.7.5 语义：凭证额外封一组步级锚点。

同一套用例（10 类，含 S7 的 weak / strong 两类）在三种凭证配置下各跑一遍，
记录：是否检出、报什么错、定位到什么步子区间、是否命中真实篡改步、是否精确到单步。

另外三组旁证：
* 零误报扫描：N=1..80 未篡改轨迹 × 默认锚点 → 必须全 VALID；
* 降级阻断：老式无锚点凭证 + ``require_anchors=True`` → 必须拒；
* 体积 / 耗时代价：N=1/5/20/50 的凭证字节数与验签中位耗时（reps=21）。

输出：<out>.json
"""
from __future__ import annotations

import copy
import json
import os
import statistics
import sys
import time

REPO = r"O:\接单\参赛\swordholder_mvp"
sys.path.insert(0, REPO)
_VENV_SP = os.path.join(REPO, ".venv", "Lib", "site-packages")
if os.path.isdir(_VENV_SP):
    sys.path.insert(0, _VENV_SP)

from swordholder import core, trace_ledger as tl  # noqa: E402

SIZES = [1, 5, 20, 50]
CASE_SIZES = [3, 20, 50]
REPS = 21
CONFIGS = {"legacy_no_anchor": 0, "default_anchor": None, "exact_stride1": 1}


# ------------------------------------------------------------------ 基础构件
def build_trace(n: int, trace_id: str, tag: str = "") -> dict:
    led = tl.TraceLedger(trace_id=trace_id, actor="agent:s8-bench")
    for i in range(n):
        led.append(
            "get_process_tree" if i % 3 == 0 else "submit_verdict",
            {"host": "build-runner-%02d%s" % (i % 7, tag), "pid": 1000 + i},
            {"detail": "step-%02d observation%s" % (i, tag), "weight": i},
        )
    return led.body()


def rebuild(body: dict) -> dict:
    """按篡改后的内容把整条链连同 head / step_count 一起重算 —— 攻击者持有写权限时能做。"""
    entries = body["entries"]
    prev = tl.GENESIS
    for i, e in enumerate(entries):
        e["n"] = i
        e["prev"] = prev
        e["hash"] = tl.entry_hash(e, prev)
        prev = e["hash"]
    body["entries"] = entries
    body["step_count"] = len(entries)
    body["head"] = prev
    return body


def keygen(workdir: str) -> dict:
    os.makedirs(workdir, exist_ok=True)
    keys = core.keygen(out_dir=workdir)
    trust = os.path.join(workdir, "trusted_keys.json")
    doc = {"trust_root": "s8-bench", "keys": [{
        "key_id": "s8-bench-001", "algorithm": "ed25519",
        "public_key_hex": keys["public_key_hex"]}]}
    with open(trust, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    keys["trust_path"] = trust
    return keys


def median_ms(fn, reps: int = REPS, warmup: int = 3) -> float:
    for _ in range(warmup):
        fn()
    s = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        s.append((time.perf_counter() - t0) * 1000.0)
    s.sort()
    return round(statistics.median(s), 4)


# ------------------------------------------------------------------ 用例集
def make_cases(n: int, workdir: str, keys: dict) -> list[dict]:
    """返回 [{name, body, truth_first, kind}]，truth_first = 第一个内容真正变样的步号。"""
    base = build_trace(n, "TR-S8-%d" % n)
    t = n // 2
    cases = []

    # 1. weak：改值但不重算（S7 的 weak）
    b = copy.deepcopy(base)
    b["entries"][t]["observation"]["detail"] = "exfiltrated"
    cases.append({"name": "weak_edit_value", "body": b, "truth_first": t, "kind": "weak"})

    # 2. strong：改值并重算后续全部哈希与 head（S7 的 strong）
    b = copy.deepcopy(base)
    b["entries"][t]["observation"]["detail"] = "exfiltrated"
    cases.append({"name": "strong_edit_value", "body": rebuild(b),
                  "truth_first": t, "kind": "strong"})

    # 3/4. strong，落在首步 / 末步（考验锚点边界）
    b = copy.deepcopy(base)
    b["entries"][0]["args"]["host"] = "exfil-00"
    cases.append({"name": "strong_edit_first_step", "body": rebuild(b),
                  "truth_first": 0, "kind": "strong"})
    b = copy.deepcopy(base)
    b["entries"][n - 1]["args"]["host"] = "exfil-last"
    cases.append({"name": "strong_edit_last_step", "body": rebuild(b),
                  "truth_first": n - 1, "kind": "strong"})

    # 5. strong 插入一步
    b = copy.deepcopy(base)
    forged = copy.deepcopy(b["entries"][t])
    forged["action"] = "tool_ghost"
    forged["observation"] = {"detail": "ghost", "weight": -1}
    b["entries"].insert(t, forged)
    cases.append({"name": "strong_insert_step", "body": rebuild(b),
                  "truth_first": t, "kind": "strong"})

    # 6. strong 删除一步
    b = copy.deepcopy(base)
    del b["entries"][t]
    cases.append({"name": "strong_delete_step", "body": rebuild(b),
                  "truth_first": t, "kind": "strong"})

    # 7. strong 换序
    b = copy.deepcopy(base)
    e = b["entries"]
    e[t], e[n - 1] = e[n - 1], e[t]
    cases.append({"name": "strong_reorder_steps", "body": rebuild(b),
                  "truth_first": min(t, n - 1), "kind": "strong"})

    # 8. strong 尾部追加一步（第一个变样的步号是 n，即新追加的那一步）
    b = copy.deepcopy(base)
    extra = copy.deepcopy(b["entries"][-1])
    extra["action"] = "tool_appended"
    extra["observation"] = {"detail": "appended", "weight": 999}
    b["entries"].append(extra)
    cases.append({"name": "strong_append_step", "body": rebuild(b),
                  "truth_first": n, "kind": "strong"})

    # 9. 截尾后重算（S7 记过的「链自洽靠 step_count/head 拦住」那一类，看能否定位到截断点）
    cut = max(1, n - 3)
    b = copy.deepcopy(base)
    b["entries"] = b["entries"][:cut]
    cases.append({"name": "truncate_tail_rebuild", "body": rebuild(b),
                  "truth_first": cut, "kind": "truncate"})

    # 10. 跨轨迹：另一条同长、同 trace_id、**内容不同**的轨迹拿真凭证来背书
    other = build_trace(n, "TR-S8-%d-OTHER" % n, tag="-alt")
    other["trace_id"] = base["trace_id"]
    rebuild(other)
    cases.append({"name": "cross_trace_credential", "body": other,
                  "truth_first": 0, "kind": "cross"})
    return cases


def judge_loc(loc: dict, truth_first: int) -> dict:
    """命中 = 分叉点落在真值上；exact_span = 区间宽 1 且不是「起自第 0 步」的不可收窄情形。"""
    seg = loc.get("segment")
    hit = False
    if isinstance(seg, list) and len(seg) == 2:
        hit = seg[0] <= truth_first <= seg[1]
    exact = bool(hit and isinstance(seg, list) and seg[0] == seg[1])
    unbounded = bool(loc.get("span_unbounded"))
    return {"hit": hit,
            "exact": exact,
            "exact_span": bool(exact and not unbounded),
            "span_unbounded": unbounded,
            "segment": seg}


# ------------------------------------------------------------------ 主流程
def compact_bytes(path):
    """同一份 JSON 的紧凑序列化字节数（去掉缩进/空白），用于剔除「美化打印」对体积口径的影响。"""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return len(json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def main(out_path: str) -> dict:
    workdir = os.path.join(os.path.dirname(out_path), "s8_seal",
                           "run_" + time.strftime("%Y%m%d_%H%M%S"))
    keys = keygen(workdir)

    result = {"meta": {
        "swordholder_version": __import__("swordholder").__version__,
        "python": sys.version.split()[0],
        "reps": REPS,
        "case_sizes": CASE_SIZES,
        "sizes": SIZES,
        "configs": {k: ("auto(max_anchors=64)" if v is None else v) for k, v in CONFIGS.items()},
    }, "cases": [], "false_positive_sweep": {}, "downgrade_blocked": {},
        "cost": {}, "summary": {}}

    # ---- 用例对照：**用原始轨迹的凭证去验被篡改的轨迹**（这才是攻击面）
    rows = []
    for n in CASE_SIZES:
        cases = make_cases(n, workdir, keys)
        base = build_trace(n, "TR-S8-%d" % n)
        for cfg_name, stride in CONFIGS.items():
            seal_path = os.path.join(workdir, "base_%s_%d.seal.json" % (cfg_name, n))
            sealed = tl.seal_trace(base, keys["private_key_path"], issuer="s8-bench",
                                   out_path=seal_path, anchor_stride=stride)
            for case in cases:
                row = {"n": n, "case": case["name"], "kind": case["kind"],
                       "truth_first": case["truth_first"], "config": cfg_name}
                try:
                    res = tl.verify_sealed_trace(case["body"], sealed["seal_path"],
                                                 keys_path=keys["trust_path"])
                except Exception as exc:  # 校验器自身炸掉 = 必须暴露，不许静默
                    row.update({"error": "%s: %s" % (type(exc).__name__, exc)})
                    rows.append(row)
                    continue
                loc = res.get("localization") or {}
                row.update({
                    "verdict": res.get("verdict"),
                    "reason": res.get("reason"),
                    "chain_first_break": (res.get("chain") or {}).get("first_break"),
                    "loc_mode": loc.get("mode"),
                    "loc_reason": loc.get("reason"),
                    **judge_loc(loc, case["truth_first"]),
                    "seal_bytes": os.path.getsize(sealed["seal_path"]),
                })
                rows.append(row)
    result["cases"] = rows

    # ---- 汇总：检出率 / 定位命中率 / 精确率
    for cfg_name in CONFIGS:
        det = hit = exact = exact_span = total = 0
        by_kind: dict[str, dict] = {}
        for row in rows:
            if row.get("config") != cfg_name:
                continue
            total += 1
            k = by_kind.setdefault(row["kind"], {"n": 0, "detected": 0, "located": 0,
                                                 "exact": 0, "exact_span": 0,
                                                 "span_unbounded": 0})
            k["n"] += 1
            if row.get("verdict") == "INVALID":
                det += 1
                k["detected"] += 1
            if row.get("hit"):
                hit += 1
                k["located"] += 1
            if row.get("exact"):
                exact += 1
                k["exact"] += 1
            if row.get("exact_span"):
                exact_span += 1
                k["exact_span"] += 1
            if row.get("span_unbounded"):
                k["span_unbounded"] += 1
        result["summary"][cfg_name] = {
            "cases": total, "detected": det, "located_hit": hit, "located_exact": exact,
            "located_exact_span": exact_span,
            "detect_rate": round(det / total, 4) if total else None,
            "locate_rate": round(hit / total, 4) if total else None,
            "exact_rate": round(exact / total, 4) if total else None,
            "exact_span_rate": round(exact_span / total, 4) if total else None,
            "by_kind": by_kind,
        }

    # ---- 零误报扫描（N=1..80，三种配置都要全 VALID）
    fp = {}
    for cfg_name, stride in CONFIGS.items():
        bad = []
        for n in range(1, 81):
            body = build_trace(n, "FP-%03d" % n)
            p = os.path.join(workdir, "fp_%s_%03d.seal.json" % (cfg_name, n))
            sealed = tl.seal_trace(body, keys["private_key_path"], issuer="s8-bench",
                                   out_path=p, anchor_stride=stride)
            r = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=keys["trust_path"],
                                       require_anchors=(cfg_name != "legacy_no_anchor"))
            if r.get("verdict") != "VALID":
                bad.append({"n": n, "reason": r.get("reason")})
        fp[cfg_name] = {"checked": 80, "false_positives": len(bad), "detail": bad[:5]}
    result["false_positive_sweep"] = fp

    # ---- 降级阻断：老凭证 + require_anchors
    body = build_trace(12, "DG-1")
    old = tl.seal_trace(body, keys["private_key_path"], issuer="s8-bench",
                        out_path=os.path.join(workdir, "dg_old.seal.json"), anchor_stride=0)
    r_old = tl.verify_sealed_trace(body, old["seal_path"], keys_path=keys["trust_path"])
    r_strict = tl.verify_sealed_trace(body, old["seal_path"], keys_path=keys["trust_path"],
                                     require_anchors=True)
    result["downgrade_blocked"] = {
        "legacy_default_policy": {"verdict": r_old.get("verdict"), "reason": r_old.get("reason"),
                                  "loc_mode": (r_old.get("localization") or {}).get("mode")},
        "strict_require_anchors": {"verdict": r_strict.get("verdict"),
                                   "reason": r_strict.get("reason")},
    }

    # ---- 体积 / 耗时代价
    cost = {}
    for n in SIZES:
        body = build_trace(n, "COST-%02d" % n)
        per = {}
        for cfg_name, stride in CONFIGS.items():
            p = os.path.join(workdir, "cost_%s_%02d.seal.json" % (cfg_name, n))
            sealed = tl.seal_trace(body, keys["private_key_path"], issuer="s8-bench",
                                   out_path=p, anchor_stride=stride)
            size = os.path.getsize(sealed["seal_path"])
            v_ms = median_ms(lambda: tl.verify_sealed_trace(
                body, sealed["seal_path"], keys_path=keys["trust_path"]))
            anchors = tl._seal_payload(sealed["seal_path"]).get("anchors") or {}
            per[cfg_name] = {"seal_bytes": size, "verify_median_ms": v_ms,
                             "seal_bytes_compact": compact_bytes(sealed["seal_path"]),
                             "anchor_points": len(anchors.get("points") or []),
                             "anchor_stride": anchors.get("stride")}
        chain_path = os.path.join(workdir, "cost_trace_%02d.json" % n)
        with open(chain_path, "w", encoding="utf-8") as fh:
            json.dump(body, fh, ensure_ascii=False)
        per["trace_body_bytes"] = os.path.getsize(chain_path)
        per["trace_body_bytes_compact"] = compact_bytes(chain_path)
        cost["N=%d" % n] = per
    result["cost"] = cost

    # ---- 大 N：锚点上限（64）触发步距退化，定位精度从「单步」变为「一段」
    large = {}
    for n in (64, 65, 200, 1000):
        base = build_trace(n, "LG-%d" % n)
        t = int(n * 0.7)
        row = {"n": n, "tampered_step": t}
        for cfg_name, stride in CONFIGS.items():
            p = os.path.join(workdir, "lg_%s_%d.seal.json" % (cfg_name, n))
            sealed = tl.seal_trace(base, keys["private_key_path"], issuer="s8-bench",
                                   out_path=p, anchor_stride=stride)
            b = copy.deepcopy(base)
            b["entries"][t]["observation"]["detail"] = "exfiltrated"
            rebuild(b)
            r = tl.verify_sealed_trace(b, sealed["seal_path"], keys_path=keys["trust_path"])
            loc = r.get("localization") or {}
            seg = loc.get("segment")
            anc = tl._seal_payload(sealed["seal_path"]).get("anchors") or {}
            row[cfg_name] = {
                "seal_bytes": os.path.getsize(sealed["seal_path"]),
                "anchor_points": len(anc.get("points") or []),
                "anchor_stride": anc.get("stride"),
                "verdict": r.get("verdict"),
                "loc_mode": loc.get("mode"),
                "segment": seg,
                "segment_width": (seg[1] - seg[0] + 1) if isinstance(seg, list) else None,
                "hit": bool(isinstance(seg, list) and seg[0] <= t <= seg[1]),
                "exact": bool(isinstance(seg, list) and seg[0] == seg[1]),
            }
        large["N=%d" % n] = row
    result["large_n"] = large

    # ---- 恶意/缺陷签发方：签名有效但锚点与轨迹不符 → 必须拦在 E_TRACE_ANCHOR_MISMATCH
    from swordholder import exit_guard  # noqa: E402
    body = build_trace(8, "MAL-1")
    alien = build_trace(8, "MAL-1", tag="-evil")
    payload = {"record_id": body["trace_id"], "trace_id": body["trace_id"],
               "actor": body["actor"], "step_count": body["step_count"],
               "head": body["head"], "digest": tl.body_digest(body),
               "anchors": tl.build_anchors(alien, stride=1)}
    p_mal = os.path.join(workdir, "mal_anchor.seal.json")
    exit_guard.judge("cli:seal", payload, basis="attested")
    exit_guard.issue_credential(payload, keys["private_key_path"], "s8-bench",
                               exit_name="cli:seal", subject=body["trace_id"],
                               out_path=p_mal)
    r_mal = tl.verify_sealed_trace(body, p_mal, keys_path=keys["trust_path"])
    result["inconsistent_anchors"] = {
        "verdict": r_mal.get("verdict"), "reason": r_mal.get("reason"),
        "loc_mode": (r_mal.get("localization") or {}).get("mode"),
        "segment": (r_mal.get("localization") or {}).get("segment"),
    }

    # ---- challenge 绑定性不能因锚点改动而失效
    body = build_trace(6, "CH-1")
    p_ch = os.path.join(workdir, "ch.seal.json")
    tl.seal_trace(body, keys["private_key_path"], issuer="s8-bench",
                  out_path=p_ch, challenge="c-s8-001")
    ok = tl.verify_sealed_trace(body, p_ch, keys_path=keys["trust_path"],
                                expected_challenge="c-s8-001")
    bad = tl.verify_sealed_trace(body, p_ch, keys_path=keys["trust_path"],
                                 expected_challenge="c-s8-002")
    result["challenge_binding"] = {
        "correct": {"verdict": ok.get("verdict"), "reason": ok.get("reason")},
        "wrong": {"verdict": bad.get("verdict"), "reason": bad.get("reason")},
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
    return result


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "s8_locate.json")
    try:
        r = main(out)
    except BaseException:
        import traceback
        with open(os.path.join(os.path.dirname(out), "s8_err.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(traceback.format_exc())
        raise
    print("WROTE", out)
    for cfg in r["summary"]:
        s = r["summary"][cfg]
        print("%-16s detect %d/%d locate %d/%d exact %d/%d"
              % (cfg, s["detected"], s["cases"], s["located_hit"], s["cases"],
                 s["located_exact"], s["cases"]))
    print("FP", {k: v["false_positives"] for k, v in r["false_positive_sweep"].items()})
    print("DG", r["downgrade_blocked"])
    for k, v in r["cost"].items():
        print(k, {c: (d if not isinstance(d, dict) else
                      (d.get("seal_bytes"), d.get("verify_median_ms"),
                       d.get("anchor_points"), d.get("anchor_stride")))
                  for c, d in v.items()})
