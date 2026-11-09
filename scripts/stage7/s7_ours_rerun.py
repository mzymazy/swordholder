# -*- coding: utf-8 -*-
"""S7：我方（Swordholder）同机同数据重跑，作为 cosign / in-toto 的对照基线。

与 S5 判据保持一致（同一 build_trace、同一 N、同一 reps、同一计时方式），并额外：
* 导出每条轨迹的**原始字节**到 payloads/trace_<N>.json，供 cosign 对**完全相同的字节**签名；
* 在 N=3 / N=20 上做「篡改某一步 → 能否定位到具体步」的实测（读 chain.first_break）；
* 在审计钩子封死 socket 的子进程里做离线验签（统计被拦截的网络调用数）。

输出：<out>.json
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time

REPO = r"O:\接单\参赛\swordholder_mvp"
sys.path.insert(0, REPO)

from swordholder import core, trace_ledger  # noqa: E402

SIZES = [1, 5, 20, 50]
REPS = 21


def build_trace(n: int, trace_id: str) -> dict:
    led = trace_ledger.TraceLedger(trace_id=trace_id, actor="agent:s7-bench")
    for i in range(n):
        led.append(
            "get_process_tree" if i % 3 == 0 else "submit_verdict",
            {"host": "build-runner-%02d" % (i % 7), "pid": 1000 + i},
            {"detail": "step-%02d observation" % i, "weight": i},
        )
    return led.body()


def timed(fn, reps: int, warmup: int = 3) -> dict:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {"reps": reps,
            "median_ms": round(statistics.median(samples), 4),
            "min_ms": round(samples[0], 4)}


def keygen(workdir: str) -> dict:
    keys = core.keygen(out_dir=workdir)
    trust = os.path.join(workdir, "trusted_keys.json")
    doc = {"trust_root": "s7-bench", "keys": [{
        "key_id": "s7-bench-001", "algorithm": "ed25519",
        "public_key_hex": keys["public_key_hex"]}]}
    with open(trust, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    keys["trust_path"] = trust
    return keys


OFFLINE_PROBE = r'''
import json, sys
hits = {"n": 0, "events": []}
NET = ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
       "socket.bind", "socket.sendto", "urllib.Request")
def hook(event, args):
    if event in NET:
        hits["n"] += 1
        hits["events"].append(event)
        raise RuntimeError("network blocked: " + event)
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[1])
from swordholder import trace_ledger
spec = json.loads(sys.stdin.read())
body = json.load(open(spec["body"], encoding="utf-8"))
r = trace_ledger.verify_sealed_trace(body, spec["seal"], keys_path=spec["keys"])
print("__PROBE__" + json.dumps({"verdict": r.get("verdict"), "reason": r.get("reason"),
                                "net_hits": hits["n"], "events": hits["events"][:8]}))
'''


def offline_probe(workdir: str, body_path: str, seal_path: str, keys_path: str) -> dict:
    probe_py = os.path.join(workdir, "_offline_probe.py")
    with open(probe_py, "w", encoding="utf-8") as fh:
        fh.write(OFFLINE_PROBE)
    p = subprocess.run([sys.executable, probe_py, REPO], cwd=workdir,
                       input=json.dumps({"body": body_path, "seal": seal_path, "keys": keys_path}),
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = None
    for line in (p.stdout or "").splitlines():
        if line.startswith("__PROBE__"):
            out = json.loads(line[len("__PROBE__"):])
    return {"probe": out, "rc": p.returncode,
            "stdout_tail": (p.stdout or "")[-300:], "stderr_tail": (p.stderr or "")[-300:]}


def tamper_localization(workdir: str, keys: dict, n: int) -> list[dict]:
    """两种强度的篡改，分别记录能否定位到具体步。

    weak  = 直接改某步内容、**不**重算哈希（朴素改档）
    strong= 改内容后**重算该步及之后全部哈希与 head**（最强攻击：链自洽，只有凭证里的 head 挡得住）
    """
    body = build_trace(n, "S7-TAMPER-%d" % n)
    seal_path = os.path.join(workdir, "tamper_%d.seal.json" % n)
    trace_ledger.seal_trace(body, keys["private_key_path"], "s7-tamper", out_path=seal_path)
    target = n // 2
    out = []
    for mode in ("weak", "strong"):
        bad = json.loads(json.dumps(body))
        bad["entries"][target]["observation"]["detail"] = "TAMPERED BY S7(%s)" % mode
        if mode == "strong":
            prev = bad["entries"][target - 1]["hash"] if target > 0 else trace_ledger.GENESIS
            for idx in range(target, len(bad["entries"])):
                e = bad["entries"][idx]
                e["prev"] = prev
                want = trace_ledger.entry_hash(e, prev)
                e["hash"] = want
                prev = want
            bad["head"] = prev
        r = trace_ledger.verify_sealed_trace(bad, seal_path, keys_path=keys["trust_path"])
        chain = r.get("chain") or {}
        out.append({"steps": n, "mode": mode, "tampered_step": target,
                    "verdict": r.get("verdict"), "reason": r.get("reason"),
                    "chain_first_break": chain.get("first_break"),
                    "chain_reason": chain.get("reason"),
                    "localized_to_step": chain.get("first_break") == target})
    return out


def main() -> int:
    workdir = sys.argv[1]
    out = sys.argv[2]
    payload_dir = os.path.join(workdir, "payloads")
    os.makedirs(payload_dir, exist_ok=True)
    keys = keygen(workdir)

    rows = []
    for n in SIZES:
        body = build_trace(n, "S7-SCALE-%d" % n)
        body_path = os.path.join(payload_dir, "trace_%d.json" % n)
        with open(body_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(json.dumps(body, ensure_ascii=False))
        seal_path = os.path.join(workdir, "scale_%d.seal.json" % n)
        with open(body_path, encoding="utf-8") as fh:
            body = json.load(fh)
        trace_ledger.seal_trace(body, keys["private_key_path"], "s7-scale", out_path=seal_path)
        trace_bytes = os.path.getsize(body_path)
        seal_bytes = os.path.getsize(seal_path)
        seal_t = timed(lambda b=body: trace_ledger.seal_trace(
            b, keys["private_key_path"], "s7-scale",
            out_path=os.path.join(workdir, "scale_tmp.seal.json")), REPS)
        verify_t = timed(lambda b=body, p=seal_path: trace_ledger.verify_sealed_trace(
            b, p, keys_path=keys["trust_path"]), REPS)
        rows.append({
            "steps": n,
            "signature_count": 1,
            "trace_bytes": trace_bytes,
            "seal_bytes": seal_bytes,
            "credential_to_trace_ratio": round(seal_bytes / trace_bytes, 4),
            "sign_ms": seal_t["median_ms"],
            "sign_min_ms": seal_t["min_ms"],
            "verify_ms": verify_t["median_ms"],
            "verify_min_ms": verify_t["min_ms"],
            "verify_files_required": 2,
            "verify_inputs_bytes": seal_bytes + os.path.getsize(keys["trust_path"]),
        })

    off = offline_probe(workdir, os.path.join(payload_dir, "trace_20.json"),
                        os.path.join(workdir, "scale_20.seal.json"), keys["trust_path"])
    tamper = [tamper_localization(workdir, keys, 3), tamper_localization(workdir, keys, 20)]

    rep = {
        "tool": "swordholder",
        "version": __import__("swordholder").__version__,
        "python": sys.version.split()[0],
        "reps": REPS,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rows": rows,
        "offline": off,
        "tamper": tamper,
        "payload_dir": payload_dir,
        "trust_store_bytes": os.path.getsize(keys["trust_path"]),
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"version": rep["version"], "rows": rows,
                      "offline": off.get("probe"), "tamper": tamper}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
