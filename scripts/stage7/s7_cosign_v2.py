# -*- coding: utf-8 -*-
"""S7: cosign v2.6.1 实测（key-based，与我方同机同 payload 字节）。

关键口径（第一版脚本踩过的坑，这里已修正）
--------------------------------------------
* cosign 的 `verify-blob --signature ... --insecure-ignore-tlog=true` 在**联网**状态下每次
  都会向 tuf-repo-cdn.sigstore.dev 刷新 TUF 元数据 → 墙钟 2.1~3.0 s，其中密码学验签只占几 ms；
  在**死代理**状态下该刷新快速失败但被降级忽略 → 50 ms 且 rc=0（Verified OK）。
  所以「联网耗时」与「离线耗时」必须分开报，否则会把 TUF 网络往返算进签名算法成本。
* `verify-blob --bundle ... --offline=true` 走 bundle 的 verificationMaterial，需要 TUF
  trusted_root 才能确认公钥信任；死代理下 rc=1 "offline verification failed"。
* 默认 `sign-blob`（不加 --tlog-upload=false）会尝试把签名上传 Rekor，无网+非交互 → rc=1。

用法： python s7_cosign.py <ours_payload_dir> <workdir> <out.json>
"""
from __future__ import annotations

import hashlib
import json
import os
import statistics
import subprocess
import sys
import time

TMP = os.environ["TEMP"]
COSIGN = os.path.join(TMP, "s7_cosign", "cosign-windows-amd64.exe")
SIZES = [1, 5, 20, 50]
PASSWORD = "s7-bench-pass"
DEAD_PROXY = {"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
              "https_proxy": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
              "NO_PROXY": "", "no_proxy": ""}


def run(args, cwd, env_extra=None, timeout=300):
    env = dict(os.environ)
    env["COSIGN_PASSWORD"] = PASSWORD
    if env_extra:
        env.update(env_extra)
    t0 = time.perf_counter()
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout, env=env)
    return {"rc": p.returncode, "out": (p.stdout or "").strip(), "err": (p.stderr or "").strip(),
            "ms": round((time.perf_counter() - t0) * 1000.0, 2)}


def timed(fn, reps=5, warmup=1):
    for _ in range(warmup):
        fn()
    xs = sorted(fn()["ms"] for _ in range(reps))
    return {"reps": reps, "median_ms": round(statistics.median(xs), 2), "min_ms": xs[0],
            "max_ms": xs[-1]}


def main() -> int:
    payload_dir, workdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(workdir, exist_ok=True)
    for f in os.listdir(workdir):
        if f.endswith((".sig", ".bundle")) or f in ("cosign.key", "cosign.pub"):
            os.remove(os.path.join(workdir, f))
    rep = {"tool": "cosign", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    v = run([COSIGN, "version"], workdir)
    rep["version"] = v["out"]
    rep["binary"] = {"path": COSIGN, "bytes": os.path.getsize(COSIGN),
                     "sha256": hashlib.sha256(open(COSIGN, "rb").read()).hexdigest()}
    rep["cli_startup_baseline_ms"] = timed(lambda: run([COSIGN, "version"], workdir))["median_ms"]

    kg = run([COSIGN, "generate-key-pair"], workdir)
    rep["keygen"] = {"rc": kg["rc"], "err_tail": kg["err"][-200:],
                     "priv_bytes": os.path.getsize(os.path.join(workdir, "cosign.key"))
                     if os.path.exists(os.path.join(workdir, "cosign.key")) else None,
                     "pub_bytes": os.path.getsize(os.path.join(workdir, "cosign.pub"))
                     if os.path.exists(os.path.join(workdir, "cosign.pub")) else None,
                     "priv_encrypted": "ENCRYPTED" in open(os.path.join(workdir, "cosign.key"),
                                                           encoding="utf-8").read()}

    rows = []
    for n in SIZES:
        payload = os.path.join(payload_dir, "trace_%d.json" % n)
        payload_bytes = os.path.getsize(payload)
        sig, bundle = "t%d.sig" % n, "t%d.bundle" % n
        a = run([COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
                 "--output-signature", sig, payload], workdir)
        ab = run([COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
                  "--bundle", bundle, payload], workdir)
        st = timed(lambda sig=sig, payload=payload: run(
            [COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
             "--output-signature", sig, payload], workdir))
        sb = timed(lambda bundle=bundle, payload=payload: run(
            [COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
             "--bundle", bundle, payload], workdir))
        sig_bytes = os.path.getsize(os.path.join(workdir, sig))
        bundle_bytes = os.path.getsize(os.path.join(workdir, bundle)) if ab["rc"] == 0 else 0
        # 验签 A：联网（含 TUF 刷新）
        vt_net = timed(lambda sig=sig, payload=payload: run(
            [COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", sig,
             "--insecure-ignore-tlog=true", payload], workdir))
        # 验签 B：死代理（离线，TUF 刷新失败后降级）
        vt_off = timed(lambda sig=sig, payload=payload: run(
            [COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", sig,
             "--insecure-ignore-tlog=true", payload], workdir, env_extra=DEAD_PROXY))
        v0 = run([COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", sig,
                  "--insecure-ignore-tlog=true", payload], workdir, env_extra=DEAD_PROXY)
        # 验签 C：bundle + --offline（需要 TUF trusted_root）
        bd = run([COSIGN, "verify-blob", "--key", "cosign.pub", "--bundle", bundle,
                  "--offline=true", payload], workdir, env_extra=DEAD_PROXY, timeout=180)
        bo = run([COSIGN, "verify-blob", "--key", "cosign.pub", "--bundle", bundle,
                  "--offline=true", payload], workdir, timeout=180)
        # 签名 D：默认模式（尝试上传 Rekor）
        tl = run([COSIGN, "sign-blob", "--key", "cosign.key",
                  "--output-signature", "b%d.sig" % n, payload], workdir, timeout=180)
        rows.append({
            "steps": n, "payload_bytes": payload_bytes,
            "sign_rc": a["rc"], "sign_median_ms": st["median_ms"], "sign_min_ms": st["min_ms"],
            "sign_bundle_median_ms": sb["median_ms"],
            "sign_net_ms": round(st["median_ms"] - rep["cli_startup_baseline_ms"], 2),
            "sig_bytes": sig_bytes, "bundle_bytes": bundle_bytes,
            "verify_sig_rc": v0["rc"],
            "verify_sig_net_median_ms": vt_net["median_ms"],
            "verify_sig_offline_median_ms": vt_off["median_ms"],
            "verify_sig_offline_min_ms": vt_off["min_ms"],
            "verify_sig_offline_net_ms": round(
                vt_off["median_ms"] - rep["cli_startup_baseline_ms"], 2),
            "verify_bundle_offline_rc": bd["rc"], "verify_bundle_offline_ok": bd["rc"] == 0,
            "verify_bundle_offline_err_tail": (bd["err"] or "")[-160:],
            "verify_bundle_online_rc": bo["rc"],
            "verify_bundle_online_ms": bo["ms"],
            "sig_bytes_per_step": round(sig_bytes / n, 1),
            "tlog_upload_rc": tl["rc"],
            "tlog_upload_err_tail": (tl["err"] or tl["out"])[-200:],
        })
    rep["rows"] = rows

    # ---- 篡改定位：整条轨迹一个 blob
    payload = os.path.join(payload_dir, "trace_3.json")
    good = json.load(open(payload, encoding="utf-8"))
    run([COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
         "--output-signature", "tamper3.sig", payload], workdir)
    bad = json.loads(json.dumps(good))
    bad["entries"][1]["observation"]["detail"] = "TAMPERED BY S7"
    bad_path = os.path.join(workdir, "trace_3_tampered.json")
    with open(bad_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(bad, ensure_ascii=False))
    t1 = run([COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", "tamper3.sig",
              "--insecure-ignore-tlog=true", bad_path], workdir, env_extra=DEAD_PROXY)
    txt = (t1["err"] + " " + t1["out"])
    names_step = any(k in txt for k in ("step_01", "step01", "第1步", "steps[1]", "entry 1"))
    rep["tamper"] = {"single_blob": {
        "case": "改 trace 第 1 步 observation 后验签（整条轨迹一个 blob）",
        "rc": t1["rc"], "detected": t1["rc"] != 0, "err_tail": txt[-260:],
        "names_step": names_step,
        "note": "整条轨迹一个 blob 时只能得到「验签失败」，不点名任何步骤"}}

    # ---- 逐步各签一个 blob（cosign 的步级变体）
    per_step, loc = [], []
    for i in range(3):
        step_path = os.path.join(workdir, "step_%02d.json" % i)
        with open(step_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(good["entries"][i], ensure_ascii=False))
        r = run([COSIGN, "sign-blob", "--key", "cosign.key", "--tlog-upload=false",
                 "--output-signature", "step_%02d.sig" % i, step_path], workdir)
        per_step.append({"step": i, "rc": r["rc"],
                         "sig_bytes": os.path.getsize(os.path.join(workdir, "step_%02d.sig" % i))})
    with open(os.path.join(workdir, "step_01.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"n": 1, "evil": True}, ensure_ascii=False))
    for i in range(3):
        r = run([COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", "step_%02d.sig" % i,
                 "--insecure-ignore-tlog=true",
                 os.path.join(workdir, "step_%02d.json" % i)], workdir, env_extra=DEAD_PROXY)
        loc.append({"step": i, "rc": r["rc"], "ok": r["rc"] == 0,
                    "err_tail": (r["err"] or "")[-120:]})
    rep["tamper"]["per_step_sign"] = {
        "sigs": per_step, "sig_bytes_total": sum(s["sig_bytes"] for s in per_step),
        "verify_results": loc, "localized": [x["step"] for x in loc if not x["ok"]],
        "verify_calls_needed": len(loc),
        "note": "cosign 本身无步概念；按「每步一个 blob + 一个签名」自行切分后才能定位，"
                "代价是签名数=步数、验签次数=步数、体积=步数×96B（另加 blob 本身）"}

    # ---- keyless（OIDC+Fulcio+Rekor）无网
    kl = run([COSIGN, "sign-blob", "--bundle", "keyless.bundle",
              os.path.join(payload_dir, "trace_1.json")], workdir,
             env_extra=DEAD_PROXY, timeout=180)
    rep["keyless_offline"] = {"rc": kl["rc"], "ms": kl["ms"],
                             "err_tail": (kl["err"] or kl["out"])[-260:]}

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    print(json.dumps({
        "startup_ms": rep["cli_startup_baseline_ms"], "keygen_rc": rep["keygen"]["rc"],
        "rows": [{k: r[k] for k in ("steps", "sign_median_ms", "sig_bytes",
                                    "verify_sig_net_median_ms", "verify_sig_offline_median_ms",
                                    "verify_bundle_offline_rc", "tlog_upload_rc")}
                 for r in rows],
        "tamper_single": rep["tamper"]["single_blob"],
        "tamper_localized": rep["tamper"]["per_step_sign"]["localized"],
        "keyless_offline_rc": rep["keyless_offline"]["rc"],
    }, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
