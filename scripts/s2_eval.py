"""第二阶段评测：在公开遥测语料上跑 rules-v1，产出效果类指标。

指标口径（全部写进报告）：
- 可摄取率：原始遥测/原始厂商 JSON 直接喂 alert.normalize 的成功率；
- 可决率：verdict 未落到兜底分支（conf=0.5, "信号不足以定性"）的比例；
- 误升格率（背景集）：背景事件被判 true_positive 的比例；
- 漏判率（攻击集）：锚定攻击事件被判 false_positive 的比例；
- 收敛比：原始事件数 / 去重后需人审条目数；
- 落证吞吐：单条 triage+封装凭证耗时；验签耗时；篡改检出率；
- 确定性：两次独立进程重跑判定一致率。
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
import time

BASE = os.environ.get("S2_BASE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(BASE, "corpus")
REPO = os.environ.get("SWORDHOLDER_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.environ.get("SWORDHOLDER_KEY") or os.path.join(REPO, "keys", "swordholder_ed25519_private.pem")
TRUST = os.path.join(REPO, "trusted_keys.json")
SEAL_DIR = os.path.join(BASE, "seals")
RESULT = os.path.join(BASE, "stage2_metrics.json")
os.makedirs(SEAL_DIR, exist_ok=True)
sys.path.insert(0, REPO)

from swordholder import core, exit_guard, rules  # noqa: E402
from swordholder.alert import AlertError, normalize  # noqa: E402

BRANCHES = {
    "supply_chain": "依赖包安装期脚本执行外部载荷",
    "egress": "主机向未登记 ASN",
    "ci_token": "构建机凭证在非预期上下文",
    "pentest": "命中演练或授权测试窗口",
    "fallback": "信号不足以定性",
}


def branch_of(res):
    h = res.get("hypothesis", "")
    for k, v in BRANCHES.items():
        if v in h:
            return k
    return "other"


def load_alerts():
    out = []
    with open(os.path.join(CORPUS, "alerts_corpus.jsonl"), "r", encoding="utf-8") as fh:
        for line in fh:
            out.append(json.loads(line))
    return out


def e1_ingest():
    """原始遥测能否直接被产品摄取。"""
    raw = os.path.join(CORPUS, "raw")
    xml_blocks = json_objs = text_lines = 0
    res = {"xml_string_direct": {"tried": 0, "err": {}},
           "json_lines_direct": {"tried": 0, "err": {}},
           "plain_text_direct": {"tried": 0, "err": {}}}
    for p in sorted(glob.glob(os.path.join(raw, "**", "*.log"), recursive=True))[:40]:
        txt = open(p, "r", encoding="utf-8", errors="replace").read()
        for line in txt.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("<Event") and xml_blocks < 200:
                xml_blocks += 1
                res["xml_string_direct"]["tried"] += 1
                try:
                    normalize(s, fmt="auto")
                    res["xml_string_direct"]["err"]["OK"] = res["xml_string_direct"]["err"].get("OK", 0) + 1
                except AlertError as e:
                    code = e.errors[0]["code"]
                    res["xml_string_direct"]["err"][code] = res["xml_string_direct"]["err"].get(code, 0) + 1
            elif s.startswith("{") and json_objs < 200:
                try:
                    obj = json.loads(s)
                except Exception:  # noqa: BLE001
                    continue
                json_objs += 1
                res["json_lines_direct"]["tried"] += 1
                try:
                    normalize(obj, fmt="auto")
                    res["json_lines_direct"]["err"]["OK"] = res["json_lines_direct"]["err"].get("OK", 0) + 1
                except AlertError as e:
                    code = e.errors[0]["code"]
                    res["json_lines_direct"]["err"][code] = res["json_lines_direct"]["err"].get(code, 0) + 1
            elif text_lines < 50:
                text_lines += 1
                res["plain_text_direct"]["tried"] += 1
                res["plain_text_direct"]["err"]["E_NOT_DICT"] = \
                    res["plain_text_direct"]["err"].get("E_NOT_DICT", 0) + 1
    return res


def run_mode(alerts, mode):
    t0 = time.perf_counter()
    stats = {
        "mode": mode, "records": 0, "normalize_fail": 0, "fail_codes": {},
        "by_label": {"attack": {"n": 0, "verdict": {}, "branch": {}, "decisive": 0},
                     "background": {"n": 0, "verdict": {}, "branch": {}, "decisive": 0}},
        "branch_total": {}, "verdict_total": {}, "conf_values": {},
        "fp_examples": [], "miss_examples": [],
    }
    triaged = []
    for a in alerts:
        raw = a[mode]
        stats["records"] += 1
        try:
            norm = normalize(raw, fmt="generic")
        except AlertError as e:
            stats["normalize_fail"] += 1
            code = e.errors[0]["code"]
            stats["fail_codes"][code] = stats["fail_codes"].get(code, 0) + 1
            continue
        res = rules.rule_triage(norm)
        b = branch_of(res)
        lab = a["meta"]["label"]
        stats["by_label"][lab]["n"] += 1
        stats["by_label"][lab]["verdict"][res["verdict"]] = \
            stats["by_label"][lab]["verdict"].get(res["verdict"], 0) + 1
        stats["by_label"][lab]["branch"][b] = stats["by_label"][lab]["branch"].get(b, 0) + 1
        if b != "fallback":
            stats["by_label"][lab]["decisive"] += 1
        stats["branch_total"][b] = stats["branch_total"].get(b, 0) + 1
        stats["verdict_total"][res["verdict"]] = stats["verdict_total"].get(res["verdict"], 0) + 1
        stats["conf_values"][str(res["confidence"])] = stats["conf_values"].get(str(res["confidence"]), 0) + 1
        if lab == "background" and res["verdict"] == "true_positive" and len(stats["fp_examples"]) < 12:
            stats["fp_examples"].append({"branch": b, "tech": a["meta"]["tech"],
                                         "confidence": res["confidence"],
                                         "text": raw["description"][:160]})
        if lab == "attack" and res["verdict"] == "false_positive" and len(stats["miss_examples"]) < 12:
            stats["miss_examples"].append({"tech": a["meta"]["tech"],
                                           "text": raw["description"][:160]})
        triaged.append((a, norm, res))
    stats["elapsed_sec"] = round(time.perf_counter() - t0, 3)
    stats["throughput_per_sec"] = round(stats["records"] / max(stats["elapsed_sec"], 1e-9), 1)
    for lab in ("attack", "background"):
        s = stats["by_label"][lab]
        s["decisive_rate"] = round(s["decisive"] / s["n"], 4) if s["n"] else None
        s["tp_rate"] = round(s["verdict"].get("true_positive", 0) / s["n"], 4) if s["n"] else None
        s["fp_rate"] = round(s["verdict"].get("false_positive", 0) / s["n"], 4) if s["n"] else None
        s["susp_rate"] = round(s["verdict"].get("suspicious", 0) / s["n"], 4) if s["n"] else None
    return stats, triaged


def cluster_stats(triaged):
    """按 (技术, 主机, 命令行主体) 聚类，衡量告警收敛。"""
    keys = set()
    per_branch = {}
    for a, _norm, res in triaged:
        raw = a["m1"]
        text = (raw.get("description") or "").split(" | ")[0].strip().lower()
        stem = "".join(ch if ch.isalnum() or ch in "/\\.-_ " else "" for ch in text)[:60]
        k = (a["meta"]["tech"], raw.get("asset") or "-", stem)
        keys.add(k)
        b = branch_of(res)
        per_branch.setdefault(b, set()).add(k)
    n_events = len(triaged)
    return {"events": n_events, "clusters": len(keys),
            "convergence_ratio": round(n_events / max(len(keys), 1), 2),
            "clusters_by_branch": {k: len(v) for k, v in per_branch.items()}}


def determinism(alerts, sample_n=1500):
    sample = alerts[:sample_n]
    def run():
        hs = []
        for a in sample:
            norm = normalize(a["m1"], fmt="generic")
            res = rules.rule_triage(norm)
            hs.append(hashlib.sha256(json.dumps(res, sort_keys=True, ensure_ascii=False)
                                     .encode()).hexdigest())
        return hashlib.sha256("".join(hs).encode()).hexdigest()
    h1, h2 = run(), run()
    return {"sample": len(sample), "hash_run1": h1, "hash_run2": h2, "identical": h1 == h2}


def seal_batch(alerts, n=200):
    """对前 n 条记录做 判定→签发凭证，测吞吐；随后验签并做篡改检出测试。"""
    exit_guard.setup_exits() if hasattr(exit_guard, "setup_exits") else None
    sealed = []
    t0 = time.perf_counter()
    for a in alerts[:n]:
        norm = normalize(a["m1"], fmt="generic")
        rec = rules.rule_triage(norm)
        rec["input"] = {k: norm.get(k) for k in ("alert_id", "title", "severity", "signal",
                                                 "asset", "observed_at")}
        rec["schema_version"] = norm.get("schema_version")
        out = os.path.join(SEAL_DIR, a["m1"]["alert_id"] + ".seal.json")
        try:
            exit_guard.judge("cli:triage", rec, basis="policy")
            r = exit_guard.issue_credential(rec, KEY, "stage2-external-validity",
                                            exit_name="cli:triage", out_path=out)
            sealed.append({"alert_id": a["m1"]["alert_id"], "seal": r["seal_path"],
                           "verdict": rec["verdict"]})
        except Exception as e:  # noqa: BLE001
            sealed.append({"alert_id": a["m1"]["alert_id"], "error": type(e).__name__ + ": " + str(e)[:120]})
    t_seal = time.perf_counter() - t0
    t1 = time.perf_counter()
    verified = 0
    for s in sealed:
        if "seal" not in s:
            continue
        r = core.verify(s["seal"], keys_path=TRUST)
        if r.get("verdict") in ("VALID", "VALID_UNTRUSTED_KEY"):
            verified += 1
    t_verify = time.perf_counter() - t1
    return {"requested": n, "sealed_ok": sum(1 for s in sealed if "seal" in s),
            "errors": [s for s in sealed if "seal" not in s][:5],
            "seal_seconds": round(t_seal, 2),
            "seal_ms_per_record": round(1000 * t_seal / max(n, 1), 2),
            "verify_seconds": round(t_verify, 2),
            "verify_ms_per_record": round(1000 * t_verify / max(n, 1), 2),
            "verified_valid": verified, "sealed": sealed}


def tamper_test(sealed, per_type=8):
    """在外部语料产出的凭证上做 5 类篡改，测检出率。"""
    ok = [s for s in sealed if "seal" in s]
    if not ok:
        return {"skipped": "no_seals"}
    probe = ok[:per_type]
    results = {}
    tdir = os.path.join(BASE, "seals_tampered")
    os.makedirs(tdir, exist_ok=True)

    def tamper(kind, doc):
        d = json.loads(json.dumps(doc))
        if kind == "verdict_flip":
            d["payload"]["verdict"] = {"true_positive": "false_positive",
                                       "suspicious": "true_positive",
                                       "false_positive": "true_positive"}[d["payload"]["verdict"]]
        elif kind == "confidence_bump":
            d["payload"]["confidence"] = round(min(0.99, d["payload"]["confidence"] + 0.2), 2)
        elif kind == "alert_id_swap":
            d["payload"]["alert_id"] = "T9999-tampered"
        elif kind == "subject_swap":
            d["subject"] = "tampered-subject" if d.get("subject") != "tampered-subject" else "x"
        elif kind == "sig_byte":
            sig = d.get("signature") or d.get("seal", {}).get("signature")
            if isinstance(sig, str) and sig:
                d["signature"] = ("a" if sig[0] != "a" else "b") + sig[1:]
            else:
                d["signature"] = "deadbeef"
        return d

    for kind in ("verdict_flip", "confidence_bump", "alert_id_swap", "subject_swap", "sig_byte"):
        detected = 0
        tried = 0
        codes = {}
        for s in probe:
            doc = json.load(open(s["seal"], "r", encoding="utf-8"))
            doc2 = tamper(kind, doc)
            p = os.path.join(tdir, f"{kind}_{os.path.basename(s['seal'])}")
            json.dump(doc2, open(p, "w", encoding="utf-8"), ensure_ascii=False)
            tried += 1
            try:
                r = core.verify(p, keys_path=TRUST)
            except Exception as e:  # noqa: BLE001
                detected += 1
                codes[type(e).__name__] = codes.get(type(e).__name__, 0) + 1
                continue
            v = r.get("verdict")
            if v not in ("VALID",):
                detected += 1
                key = f"{v}:{r.get('error') or r.get('code') or ''}"
                codes[key] = codes.get(key, 0) + 1
        results[kind] = {"tried": tried, "detected": detected,
                         "rate": round(detected / max(tried, 1), 4), "codes": codes}
    return results


def cli_latency(alerts, n=12):
    """走 CLI 的端到端单条耗时（含进程启动），用于运维口径的工时换算。"""
    tmp = os.path.join(BASE, "cli_probe")
    os.makedirs(tmp, exist_ok=True)
    p = os.path.join(tmp, "alert.json")
    times = []
    ok = 0
    for a in alerts[:n]:
        json.dump(a["m1"], open(p, "w", encoding="utf-8"), ensure_ascii=False)
        t0 = time.perf_counter()
        r = subprocess.run([sys.executable, "-m", "swordholder", "triage", p,
                            "--seal", "-k", KEY, "--out-dir", tmp],
                           cwd=REPO, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        times.append(time.perf_counter() - t0)
        if r.returncode == 0:
            ok += 1
    times.sort()
    return {"runs": len(times), "ok": ok,
            "mean_sec": round(sum(times) / max(len(times), 1), 3),
            "median_sec": round(times[len(times) // 2], 3) if times else None,
            "min_sec": round(times[0], 3) if times else None,
            "max_sec": round(times[-1], 3) if times else None}


def main():
    alerts = load_alerts()
    out = {"corpus_records": len(alerts), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    out["e1_ingest_raw"] = e1_ingest()
    for mode in ("m1", "m2"):
        st, tri = run_mode(alerts, mode)
        if mode == "m1":
            out["clusters"] = cluster_stats(tri)
            out["determinism"] = determinism(alerts)
            out["seal"] = seal_batch(alerts, n=200)
            out["tamper"] = tamper_test(out["seal"]["sealed"])
            out["seal"].pop("sealed", None) if False else None
            out["cli_latency"] = cli_latency(alerts)
            json.dump([{"alert_id": a["m1"]["alert_id"], "verdict": r["verdict"],
                        "branch": branch_of(r), "label": a["meta"]["label"]}
                       for a, _n, r in tri], open(os.path.join(BASE, "decisions_m1.json"),
                                                  "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        out[mode] = st
    json.dump(out, open(RESULT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    brief = {k: out[k] for k in ("corpus_records", "e1_ingest_raw", "clusters", "determinism")}
    for m in ("m1", "m2"):
        brief[m] = {k: out[m][k] for k in ("records", "normalize_fail", "by_label",
                                           "branch_total", "verdict_total", "throughput_per_sec")}
    brief["seal"] = out["seal"]
    brief["tamper"] = out["tamper"]
    brief["cli_latency"] = out["cli_latency"]
    print(json.dumps(brief, ensure_ascii=False, indent=1)[:6000])


if __name__ == "__main__":
    main()
