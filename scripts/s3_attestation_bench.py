# -*- coding: utf-8 -*-
"""S3：可核验存证层的外部数据集基准（attestation-layer bench）。

S2 的结论是"规则层在公开遥测上不成立"，因此 S3 只测仍在成立的那一层：
**把一条结论封装成可被第三方离线验签的凭证**。本脚本回答四个可量化问题：

    Q1 从公开语料告警到凭证落盘，单条耗时与成功率是多少？
    Q2 凭证被改动后能否 100% 检出，且失败必须落在"结构化拒绝码"上而不是抛异常？
    Q3 凭证能否绑定到"这一次会话/这一条告警"，从而挡住跨告警重放？
    Q4 只有签名、没有信任锚时会不会被误判成"可信"？

已知边界（写进报告 limitations，不掩盖）：
    * 未签名的最外层附注可以任意添加（不影响已签内容与验签结论）；
    * 攻击者用自己私钥重签，签名本身是"真"的，只有信任锚能判它不可信；
    * 本基准不做时间戳/吊销之外的生命周期仿真，也**不评价**结论判断是否正确 ——
      凭证只保证"这条结论自签发起未被改动"，不保证"这条结论是对的"。

用法::

    set S2_BASE=<含 corpus 的目录> & .venv\\Scripts\\python.exe scripts\\s3_attestation_bench.py
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import alert as alert_mod  # noqa: E402
from swordholder import core, evidence_auth, exit_guard, rules  # noqa: E402
from swordholder.alert import AlertError  # noqa: E402

BASE = (os.environ.get("S2_BASE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))).strip()
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.environ.get("SWORDHOLDER_KEY") or os.path.join(REPO, "keys", "swordholder_ed25519_private.pem")
TRUST = os.path.join(REPO, "trusted_keys.json")
CORPUS = os.path.join(BASE, "corpus", "alerts_corpus.jsonl")
SEAL_DIR = os.path.join(BASE, "seals_s3")
TAMPER_DIR = os.path.join(BASE, "seals_s3_tampered")

KEEP = ("alert_id", "title", "severity", "signal", "asset", "tags", "observed_at", "source")


# ------------------------------------------------------------------ 取样
def load_corpus(limit_per_label: int) -> list[dict]:
    """按标签交替取样，保证攻击/背景两半都有，且顺序确定。"""
    pools = {"attack": [], "background": []}
    with open(CORPUS, "r", encoding="utf-8") as fh:
        for line in fh:
            a = json.loads(line)
            lab = a["meta"]["label"]
            if len(pools[lab]) < limit_per_label:
                pools[lab].append(a)
            if len(pools["attack"]) >= limit_per_label and len(pools["background"]) >= limit_per_label:
                break
    out = []
    for i in range(max(len(pools["attack"]), len(pools["background"]))):
        for lab in ("attack", "background"):
            if i < len(pools[lab]):
                out.append(pools[lab][i])
    return out


def build_records(limit_per_label: int) -> list[dict]:
    recs = []
    for a in load_corpus(limit_per_label):
        try:
            norm = alert_mod.normalize(a["m1"], fmt="generic")
        except AlertError:
            continue
        rec = rules.rule_triage(norm)
        rec["input"] = {k: norm.get(k) for k in KEEP}
        rec["schema_version"] = norm.get("schema_version")
        recs.append({"alert": norm, "record": rec, "label": a["meta"]["label"]})
    return recs


# ------------------------------------------------------------------ 签发 + 验证
def seal_all(recs: list[dict]) -> list[dict]:
    os.makedirs(SEAL_DIR, exist_ok=True)
    out = []
    t0 = time.perf_counter()
    for i, r in enumerate(recs):
        rec = r["record"]
        path = os.path.join(SEAL_DIR, "%s.seal.json" % rec["alert_id"])
        ctx = evidence_auth.context_for(r["alert"])
        try:
            exit_guard.judge("cli:triage", rec, basis="policy")
            res = exit_guard.issue_credential(rec, KEY, "stage3-attestation",
                                             exit_name="cli:triage", out_path=path, challenge=ctx)
            out.append({"alert_id": rec["alert_id"], "seal": res["seal_path"],
                        "challenge": ctx, "label": r["label"], "verdict": rec["verdict"]})
        except Exception as e:  # noqa: BLE001
            out.append({"alert_id": rec["alert_id"], "error": type(e).__name__ + ": " + str(e)[:120]})
    dt = time.perf_counter() - t0
    n = len(recs)
    return {"elapsed_sec": round(dt, 3), "attempted": n,
            "sealed_ok": sum(1 for s in out if "seal" in s),
            "errors": [s for s in out if "seal" not in s][:5],
            "ms_per_record": round(1000 * dt / max(n, 1), 3), "sealed": out}


def verify_all(sealed: list[dict]) -> dict:
    ok = [s for s in sealed if "seal" in s]
    t0 = time.perf_counter()
    good = 0
    bad = []
    for s in ok:
        r = core.verify(s["seal"], keys_path=TRUST, expected_challenge=s["challenge"])
        if r.get("verdict") == "VALID" and r.get("trust") == "trusted":
            good += 1
        else:
            bad.append({"alert_id": s["alert_id"], "verdict": r.get("verdict"),
                        "reason": r.get("reason"), "trust": r.get("trust")})
    dt = time.perf_counter() - t0
    return {"verified_valid": good, "total": len(ok), "failures": bad[:5],
            "elapsed_sec": round(dt, 3),
            "ms_per_record": round(1000 * dt / max(len(ok), 1), 3)}


# ------------------------------------------------------------------ 篡改算子
def _sig_block(d):
    return d.get("signature") if isinstance(d.get("signature"), dict) else {}


def t_payload_verdict(d):
    d["payload"]["verdict"] = {"true_positive": "false_positive", "suspicious": "true_positive",
                               "false_positive": "true_positive"}[d["payload"]["verdict"]]


def t_payload_confidence(d):
    d["payload"]["confidence"] = round(min(0.99, float(d["payload"]["confidence"]) + 0.2), 2)


def t_payload_alert_id(d):
    d["payload"]["alert_id"] = "T9999-tampered"


def t_payload_drop_key(d):
    d["payload"].pop("verdict", None)


def t_header_subject(d):
    d["seal_header"]["subject"] = "tampered-subject"


def t_header_issuer(d):
    d["seal_header"]["issuer"] = "evil-issuer"


def t_header_created_at(d):
    d["seal_header"]["created_at"] = "2020-01-01T00:00:00Z"


def t_sig_value_byte(d):
    s = _sig_block(d).get("value") or ""
    d["signature"]["value"] = ("a" if s[:1] != "a" else "b") + s[1:]


def t_sig_block_type(d):
    d["signature"] = "deadbeef"


def t_sig_not_base64(d):
    d["signature"]["value"] = "!!!not-base64!!!"


def t_outer_annotation(d):
    """已知边界：未签名的最外层附注，预期**检不出**（诚实记录）。"""
    d["subject"] = "tampered-subject"


TAMPERS = {
    "payload_verdict_flip": t_payload_verdict,
    "payload_confidence_bump": t_payload_confidence,
    "payload_alert_id_swap": t_payload_alert_id,
    "payload_verdict_removed": t_payload_drop_key,
    "header_subject_swap": t_header_subject,
    "header_issuer_swap": t_header_issuer,
    "header_created_at_swap": t_header_created_at,
    "signature_value_byte_flip": t_sig_value_byte,
    "signature_block_type_confusion": t_sig_block_type,
    "signature_value_not_base64": t_sig_not_base64,
    "outer_annotation_added": t_outer_annotation,
}


def tamper_test(sealed: list[dict], per_type: int = 8) -> dict:
    ok = sorted([s for s in sealed if "seal" in s], key=lambda s: s["alert_id"])[:per_type]
    os.makedirs(TAMPER_DIR, exist_ok=True)
    results = {}
    exceptions_total = 0
    for kind, fn in TAMPERS.items():
        detected = tried = warned = 0
        codes = {}
        uncaught = 0
        for s in ok:
            doc = json.load(open(s["seal"], "r", encoding="utf-8"))
            d = copy.deepcopy(doc)
            fn(d)
            p = os.path.join(TAMPER_DIR, "%s_%s.seal.json" % (kind, os.path.basename(s["seal"])))
            with open(p, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False)
            tried += 1
            try:
                r = core.verify(p, keys_path=TRUST, expected_challenge=s["challenge"])
            except Exception as e:  # noqa: BLE001
                uncaught += 1
                detected += 1            # 保守起见仍算"被发现"，但单独记账
                codes["EXCEPTION:" + type(e).__name__] = codes.get("EXCEPTION:" + type(e).__name__, 0) + 1
                continue
            v = r.get("verdict")
            if v != "VALID":
                detected += 1
                key = "%s:%s" % (v, r.get("reason") or "")
                codes[key] = codes.get(key, 0) + 1
            elif r.get("warnings"):
                warned += 1
                key = "WARN:%s" % r["warnings"][0].get("code")
                codes[key] = codes.get(key, 0) + 1
        exceptions_total += uncaught
        results[kind] = {"tried": tried, "detected": detected,
                         "rate": round(detected / max(tried, 1), 4),
                         "warned": warned,
                         "uncaught_exceptions": uncaught, "codes": codes}
    results["_summary"] = {"uncaught_exceptions": exceptions_total,
                           "all_structured": exceptions_total == 0,
                           "silent_passes": sum(v["tried"] - v["detected"] - v["warned"]
                                                for k, v in results.items() if k != "_summary")}
    return results


# ------------------------------------------------------------------ 重放与信任
def replay_test(sealed: list[dict], per_type: int = 8) -> dict:
    ok = sorted([s for s in sealed if "seal" in s], key=lambda s: s["alert_id"])
    pairs = [(ok[i], ok[(i + 1) % len(ok)]) for i in range(min(per_type, len(ok)))]
    blocked = 0
    codes = {}
    for a, b in pairs:
        r = core.verify(a["seal"], keys_path=TRUST, expected_challenge=b["challenge"])
        if r.get("verdict") != "VALID":
            blocked += 1
            key = "%s:%s" % (r.get("verdict"), r.get("reason"))
            codes[key] = codes.get(key, 0) + 1
    no_binding = 0
    for a, _b in pairs[:3]:
        doc = json.load(open(a["seal"], "r", encoding="utf-8"))
        stripped = copy.deepcopy(doc)
        stripped["seal_header"].pop("challenge", None)
        p = os.path.join(TAMPER_DIR, "replay_stripped_%s.seal.json" % a["alert_id"])
        with open(p, "w", encoding="utf-8") as f:
            json.dump(stripped, f, ensure_ascii=False)
        r = core.verify(p, keys_path=TRUST, expected_challenge=a["challenge"])
        if r.get("verdict") != "VALID":
            no_binding += 1
    return {"cross_alert_replay_tried": len(pairs), "cross_alert_replay_blocked": blocked,
            "block_rate": round(blocked / max(len(pairs), 1), 4), "codes": codes,
            "binding_stripped_tried": 3, "binding_stripped_rejected": no_binding}


def trust_test(sealed: list[dict], tmpdir: str) -> dict:
    ok = sorted([s for s in sealed if "seal" in s], key=lambda s: s["alert_id"])[:5]
    # (1) 无信任锚：签名有效但签发方未知 → 只能是 VALID_UNTRUSTED_KEY
    empty = os.path.join(tmpdir, "empty_trust.json")
    with open(empty, "w", encoding="utf-8") as f:
        json.dump({"keys": []}, f)
    untrusted = 0
    for s in ok:
        r = core.verify(s["seal"], keys_path=empty, expected_challenge=s["challenge"])
        if r.get("verdict") == "VALID_UNTRUSTED_KEY":
            untrusted += 1
    # (2) 攻击者用自己的私钥重签同一份 payload：签名是真的，但必须判不可信
    adir = os.path.join(tmpdir, "attacker_%d" % int(time.time() * 1000))
    att = core.keygen(adir)
    forged = []
    for s in ok[:3]:
        src = json.load(open(s["seal"], "r", encoding="utf-8"))
        p = os.path.join(tmpdir, "forged_%s.seal.json" % s["alert_id"])
        rec = src["payload"]
        exit_guard.judge("cli:triage", rec, basis="policy")
        exit_guard.issue_credential(rec, att["private_key_path"], "evil-issuer",
                                    exit_name="cli:triage", out_path=p, challenge=s["challenge"])
        r = core.verify(p, keys_path=TRUST, expected_challenge=s["challenge"])
        forged.append({"verdict": r.get("verdict"), "trust": r.get("trust"), "reason": r.get("reason")})
    return {"no_trust_anchor_tried": len(ok), "no_trust_anchor_untrusted": untrusted,
            "no_trust_anchor_never_bare_valid": untrusted == len(ok),
            "attacker_resigned": forged,
            "attacker_resigned_neutralized": all(x["verdict"] != "VALID" for x in forged)}


# ------------------------------------------------------------------ 可复现
def digest_of(seals_dir: str) -> str:
    h = hashlib.sha256()
    for name in sorted(os.listdir(seals_dir)):
        if not name.endswith(".seal.json"):
            continue
        doc = json.load(open(os.path.join(seals_dir, name), "r", encoding="utf-8"))
        h.update(name.encode("utf-8"))
        h.update((doc["seal_header"]["payload_sha256"]).encode("utf-8"))
        h.update(json.dumps(doc["payload"], ensure_ascii=False, sort_keys=True).encode("utf-8"))
    return h.hexdigest()


def determinism(seals_dir: str) -> dict:
    d1 = digest_of(seals_dir)
    code = ("import sys,json;sys.path.insert(0,%r);"
            "import s3_attestation_bench as b;print(b.digest_of(%r))") % (
        os.path.join(REPO, "scripts"), seals_dir)
    outs = []
    for _ in range(2):
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        outs.append((p.stdout or "").strip().splitlines()[-1:] or [""])
    o1, o2 = (outs[0][0], outs[1][0])
    return {"parent_digest": d1, "child_digest_1": o1, "child_digest_2": o2,
            "identical_across_processes": bool(o1) and o1 == o2 == d1}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-label", type=int, default=100)
    ap.add_argument("--per-tamper", type=int, default=8)
    ap.add_argument("--out", default=os.path.join(REPO, "evidence", "stage3_attestation", "bench.json"))
    args = ap.parse_args()

    tmpdir = os.path.join(BASE, "s3_tmp")
    os.makedirs(tmpdir, exist_ok=True)

    recs = build_records(args.per_label)
    print("records:", len(recs))
    sealed = seal_all(recs)
    print("sealed_ok=%s  ms/record=%.3f" % (sealed["sealed_ok"], sealed["ms_per_record"]))
    ver = verify_all(sealed["sealed"])
    print("verified_valid=%s/%s  ms/record=%.3f" % (ver["verified_valid"], ver["total"], ver["ms_per_record"]))
    tam = tamper_test(sealed["sealed"], args.per_tamper)
    rep = replay_test(sealed["sealed"], args.per_tamper)
    tr = trust_test(sealed["sealed"], tmpdir)
    det = determinism(SEAL_DIR)

    out = {
        "meta": {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "corpus": CORPUS, "records": len(recs),
                 "per_label": args.per_label, "per_tamper": args.per_tamper,
                 "note": "public ATT&CK-derived corpus; attestation layer only, verdict quality not evaluated"},
        "sealing": {k: v for k, v in sealed.items() if k != "sealed"},
        "verification": ver,
        "tamper": tam,
        "replay": rep,
        "trust_separation": tr,
        "determinism": det,
        "label_mix": {lab: sum(1 for r in recs if r["label"] == lab) for lab in ("attack", "background")},
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print("--- tamper ---")
    for k, v in tam.items():
        if k == "_summary":
            print(k, v)
            continue
        print("%-32s %d/%d rate=%.2f exc=%d %s" % (k, v["detected"], v["tried"], v["rate"],
                                                  v["uncaught_exceptions"], v["codes"]))
    print("--- replay ---", json.dumps(rep, ensure_ascii=False))
    print("--- trust ---", json.dumps(tr, ensure_ascii=False))
    print("--- determinism ---", json.dumps(det, ensure_ascii=False))
    print("saved ->", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
