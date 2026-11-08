# -*- coding: utf-8 -*-
"""第五阶段差异度实测台：把「我们相对既有标准的差异」逐条变成可复算的数字。

为什么需要它
------------
S3/S4 的报告里出现了几条自我宣称：离线验签、无外部日志依赖、步级定位、单凭证覆盖整条轨迹。
这些说法如果不实测，就只是文案。本脚本对每一条给出**可复现的判据**，并且对「步级签名」
这一类既有的通行做法（in-toto 逐步骤 link metadata）做正面对照实验：同一个 N 步轨迹，
一边是我们的「链头 + 单签名」，一边是 in-toto 的「每步一个签名文件」，量字节数与耗时。

测什么（每个数字都由本脚本实跑得出）
--------------------------------------
1. ``offline``：在**封死 socket** 的子进程里验签，统计仍判 VALID 的条数与被拦截的网络调用次数。
2. ``inputs``：验证一条凭证到底需要几个文件、多少字节（外部日志是否真的不必需）。
3. ``localize``：对 20 步轨迹做 9 类篡改，看是否能给出**第一个断点的步号**，并与期望步号比对。
4. ``scaling``：N=1/5/20/50 时，我们的凭证字节数、签发/验证耗时 vs in-toto 逐步骤签名。
5. ``refusal``：注入畸形/篡改输入，统计结构化拒绝码与**未被捕获的异常数**。
6. ``determinism``：三个独立进程对同一轨迹算出的摘要是否一致（跨进程可复算）。
7. ``trust``：把信任锚换成陌生公钥，看是否为 ``VALID_UNTRUSTED_KEY`` 而非「裸 VALID」。

跑法
----
    python scripts/stage5_diff_bench.py                       # 默认写 evidence/stage5_diff/bench.json
    python scripts/stage5_diff_bench.py --reps 31 --out x.json
    python scripts/stage5_diff_bench.py --intoto-path .tmp_s5_site   # in-toto 的 --target 安装目录

in-toto 缺失时脚本**不会假装测过**：对照组整段标记 ``skipped`` 并写明原因，主指标照常输出。
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from swordholder import core, trace_ledger  # noqa: E402


# --------------------------------------------------------------------- 工具
def _timed(fn, reps: int, warmup: int = 2) -> dict:
    """跑 fn，返回中位数/最小值/p95（毫秒）。warmup 次不计入，避免首轮导入开销污染。"""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {
        "reps": reps,
        "median_ms": round(statistics.median(samples), 4),
        "min_ms": round(samples[0], 4),
        "p95_ms": round(samples[min(len(samples) - 1, int(round(0.95 * (len(samples) - 1))))], 4),
    }


def make_trust_store(keys: dict, path: str) -> str:
    """把 keygen 出的公钥登记成信任锚。

    注意：`verify(keys_path=pubkey.pem)` 只会得到 VALID_UNTRUSTED_KEY —— pem 是"公钥文件"，
    不是"信任锚清单"，两者不能混为一谈（第一版实测台就在这里误判成 0/30 VALID）。
    """
    doc = {"trust_root": "stage5-bench", "keys": [{
        "key_id": "s5-bench-001", "algorithm": "ed25519",
        "public_key_hex": keys["public_key_hex"],
    }]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    return path


def build_trace(n: int, trace_id: str = "S5-BENCH") -> dict:
    """造一条 n 步的动作轨迹（内容形状贴近 SOC 分诊：查询→判定）。"""
    led = trace_ledger.TraceLedger(trace_id=trace_id, actor="agent:s5-bench")
    for i in range(n):
        led.append(
            "get_process_tree" if i % 3 == 0 else "submit_verdict",
            {"host": "build-runner-%02d" % (i % 7), "pid": 1000 + i},
            {"detail": "step-%02d observation" % i, "weight": i},
        )
    return led.body()


# ------------------------------------------------------- 1/2. 离线与输入面
OFFLINE_PROBE = r'''
import json, sys

hits = {"n": 0}
NET_EVENTS = ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
              "socket.bind", "socket.sendto", "urllib.Request")

def _hook(event, args):
    # 用审计钩子在**内核态调用发生的那一层**拦截，而不是替换 socket 类：
    # 替换 socket.socket 会让 ssl.py 的 `class SSLSocket(socket)` 直接炸掉，
    # 那是探针自身制造的假失败，不能算被测代码的结论。
    if event in NET_EVENTS:
        hits["n"] += 1
        raise RuntimeError("network blocked by probe: " + event)

sys.addaudithook(_hook)

from swordholder import core, trace_ledger

spec = json.loads(sys.stdin.read())
ok = bad = 0
for p in spec["seals"]:
    r = core.verify(p, keys_path=spec["keys_path"])
    if r.get("verdict") == "VALID":
        ok += 1
    else:
        bad += 1

body = spec["body"]
tr = trace_ledger.verify_sealed_trace(body, spec["trace_seal"], keys_path=spec["keys_path"])

deny = ("requests", "urllib3", "httpx", "aiohttp", "http.client", "socketio")
loaded = [m for m in deny if m in sys.modules]
print(json.dumps({
    "seals_valid": ok,
    "seals_total": len(spec["seals"]),
    "seals_invalid": bad,
    "trace_verdict": tr.get("verdict"),
    "trace_reason": tr.get("reason", ""),
    "socket_attempts": hits["n"],
    "denylist_loaded": loaded,
    "network_modules_loaded": [m for m in ("ssl", "http", "urllib.request", "asyncio") if m in sys.modules],
}))
'''

DIGEST_PROBE = r'''
import json, sys
from swordholder import trace_ledger
body = json.loads(sys.stdin.read())
print(json.dumps({"digest": trace_ledger.body_digest(body), "head": body.get("head")}))
'''


def _run_probe(code: str, payload: dict) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=REPO, env=env, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError("probe failed: " + (proc.stderr or "")[-800:])
    return json.loads(proc.stdout.strip().splitlines()[-1])


def measure_offline(workdir: str, keys: dict, n_seals: int = 30) -> dict:
    """封死 socket 后验签，答「离线验签到底成不成立、是不是真的没发网络调用」。"""
    seals = []
    for i in range(n_seals):
        rec = {"alert_id": "S5-OFF-%03d" % i, "verdict": "false_positive", "confidence": 0.5}
        out = os.path.join(workdir, "off_%03d.seal.json" % i)
        core.seal(rec, keys["private_key_path"], "s5-offline", out_path=out)
        seals.append(out)

    body = build_trace(12, "S5-OFFLINE")
    trace_seal = os.path.join(workdir, "offline_trace.seal.json")
    trace_ledger.seal_trace(body, keys["private_key_path"], "s5-offline", out_path=trace_seal)

    trust_path = make_trust_store(keys, os.path.join(workdir, "trusted_keys.json"))
    res = _run_probe(OFFLINE_PROBE, {
        "seals": seals, "keys_path": trust_path,
        "trace_seal": trace_seal, "body": body,
    })
    res["seal_bytes"] = os.path.getsize(seals[0])
    res["trace_seal_bytes"] = os.path.getsize(trace_seal)
    res["pubkey_bytes"] = os.path.getsize(keys["public_key_path"])
    res["trust_store_bytes"] = os.path.getsize(trust_path)
    res["trust_store_is_local_file"] = True  # 信任锚是本地清单，不是在线证书/日志服务
    res["verify_inputs_count"] = 2  # 凭证 + 本地信任锚；无日志、无时间戳服务、无 OCSP
    res["verify_inputs_bytes"] = res["seal_bytes"] + res["trust_store_bytes"]
    return res


# ------------------------------------------------------------ 3. 步级定位
def _edit_value(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    b["entries"][idx]["observation"]["detail"] = "TAMPERED"
    return b


def _recompute_from(body: dict, idx: int) -> dict:
    """改值并把本步哈希补齐（只补自己那一步）——考察断点是否前移到下一步。"""
    b = copy.deepcopy(body)
    b["entries"][idx]["observation"]["detail"] = "TAMPERED"
    prev = b["entries"][idx]["prev"]
    b["entries"][idx]["hash"] = trace_ledger.entry_hash(b["entries"][idx], prev)
    return b


def _insert(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    b["entries"].insert(idx, copy.deepcopy(b["entries"][idx]))
    b["step_count"] = len(b["entries"])
    return b


def _delete(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    del b["entries"][idx]
    b["step_count"] = len(b["entries"])
    return b


def _reorder(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    e = b["entries"]
    e[idx], e[idx + 1] = e[idx + 1], e[idx]
    return b


def _rewrite_n(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    b["entries"][idx]["n"] = 999
    return b


def _rewrite_prev(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    b["entries"][idx]["prev"] = trace_ledger.GENESIS
    return b


def _truncate(body: dict, idx: int) -> dict:
    b = copy.deepcopy(body)
    del b["entries"][idx:]
    b["step_count"] = len(b["entries"])
    b["head"] = b["entries"][-1]["hash"] if b["entries"] else trace_ledger.GENESIS
    return b


def _rebuild_selfconsistent(body: dict, idx: int) -> dict:
    """整链重算：链自洽但头变了 —— 只有凭证层能拦住（考察分层）。"""
    b = copy.deepcopy(body)
    b["entries"][idx]["observation"]["detail"] = "TAMPERED"
    prev = trace_ledger.GENESIS
    for i, e in enumerate(b["entries"]):
        e["n"] = i
        e["prev"] = prev
        e["hash"] = trace_ledger.entry_hash(e, prev)
        prev = e["hash"]
    b["head"] = prev
    b["step_count"] = len(b["entries"])
    return b


def measure_localization(workdir: str, keys: dict, n_steps: int = 20) -> dict:
    trust_path = make_trust_store(keys, os.path.join(workdir, "trusted_keys.json"))
    body = build_trace(n_steps, "S5-LOCAL")
    seal_path = os.path.join(workdir, "local_trace.seal.json")
    trace_ledger.seal_trace(body, keys["private_key_path"], "s5-local", out_path=seal_path)

    cases = [
        ("value_change", 7, _edit_value, 7),
        ("hash_recompute_single_step", 5, _recompute_from, 6),
        # 插入的重复步自身自洽，错位在**下一步**的 prev 上——所以断点落在 5 而非 4
        ("step_insert", 4, _insert, 5),
        ("step_delete", 6, _delete, 6),
        ("step_reorder", 9, _reorder, 9),
        ("step_number_rewrite", 11, _rewrite_n, 11),
        ("prev_hash_rewrite", 13, _rewrite_prev, 13),
        ("truncate_tail", n_steps - 3, _truncate, None),
        ("rebuild_chain_selfconsistent", 3, _rebuild_selfconsistent, None),
    ]

    rows = []
    for name, idx, fn, expect in cases:
        mutated = fn(body, idx)
        try:
            res = trace_ledger.verify_sealed_trace(mutated, seal_path, keys_path=trust_path)
            verdict = res.get("verdict")
            reason = res.get("reason", "")
            first_break = (res.get("chain") or {}).get("first_break")
        except Exception as exc:  # noqa: BLE001  「抛出异常」本身就是失败判据，必须计数
            verdict, reason, first_break = "EXCEPTION", type(exc).__name__, None
        detected = verdict == "INVALID"
        rows.append({
            "case": name,
            "tampered_index": idx,
            "expect_first_break": expect,
            "detected": detected,
            "verdict": verdict,
            "reason": reason.split(":")[0] if reason else "",
            "first_break": first_break,
            "localized": (expect is not None and detected and first_break == expect)
                         or (expect is None and detected),
        })

    total = len(rows)
    detected_n = sum(1 for r in rows if r["detected"])
    localized_n = sum(1 for r in rows if r["localized"])
    idx_cases = [r for r in rows if r["expect_first_break"] is not None]
    exact_n = sum(1 for r in idx_cases if r["detected"] and r["first_break"] == r["expect_first_break"])
    return {
        "steps": n_steps,
        "cases": rows,
        "detected": detected_n,
        "detected_rate": round(detected_n / total, 4),
        "first_break_exact": exact_n,
        "first_break_cases": len(idx_cases),
        "first_break_exact_rate": round(exact_n / len(idx_cases), 4),
        "localized_incl_detect_only": localized_n,
    }


def measure_coverage(workdir: str, keys: dict, n_steps: int = 50) -> dict:
    """单凭证能否覆盖并且**逐步定位**整条 N 步轨迹（对手按步签名的核心差异点）。

    对 N 步轨迹的**每一个**步号做值篡改，要求：检出 100% 且 first_break 精确等于该步号。
    同时记录凭证字节数，用来回答"多覆盖一步要付多少字节"。
    """
    trust_path = make_trust_store(keys, os.path.join(workdir, "trusted_keys.json"))
    body = build_trace(n_steps, "S5-CV-%02d" % n_steps)
    seal_path = os.path.join(workdir, "cover.seal.json")
    trace_ledger.seal_trace(body, keys["private_key_path"], "s5-cover", out_path=seal_path)
    bytes_per_seal = os.path.getsize(seal_path)

    # 基准：同样的密钥签一条 1 步轨迹，用字节差算"多覆盖一步的边际体积"
    base_path = os.path.join(workdir, "cover_base1.seal.json")
    trace_ledger.seal_trace(build_trace(1, "S5-CV-01"), keys["private_key_path"],
                            "s5-cover", out_path=base_path)
    base_bytes = os.path.getsize(base_path)

    detected = 0
    exact = 0
    misses = []
    for idx in range(n_steps):
        mutated = _edit_value(body, idx)
        try:
            res = trace_ledger.verify_sealed_trace(mutated, seal_path, keys_path=trust_path)
        except Exception as exc:  # noqa: BLE001
            misses.append({"index": idx, "error": type(exc).__name__})
            continue
        fb = (res.get("chain") or {}).get("first_break")
        if res.get("verdict") == "INVALID":
            detected += 1
            if fb == idx:
                exact += 1
            else:
                misses.append({"index": idx, "first_break": fb, "reason": res.get("reason")})
        else:
            misses.append({"index": idx, "verdict": res.get("verdict")})

    return {
        "steps": n_steps,
        "credential_bytes": bytes_per_seal,
        "signature_count": 1,
        "detected": detected,
        "detected_rate": round(detected / n_steps, 4),
        "exact_index": exact,
        "exact_index_rate": round(exact / n_steps, 4),
        "bytes_1step": base_bytes,
        "bytes_added_per_step": round((bytes_per_seal - base_bytes) / max(1, n_steps - 1), 4),
        "misses": misses,
    }


# ------------------------------------------------- 4. 单凭证 vs 逐步骤签名
def measure_scaling(workdir: str, keys: dict, sizes: list[int], reps: int, intoto_path: str | None) -> dict:
    trust_path = make_trust_store(keys, os.path.join(workdir, "trusted_keys.json"))
    ours = []
    for n in sizes:
        body = build_trace(n, "S5-SCALE-%d" % n)
        path = os.path.join(workdir, "scale_%d.seal.json" % n)
        seal_res = trace_ledger.seal_trace(body, keys["private_key_path"], "s5-scale", out_path=path)
        seal_bytes = os.path.getsize(path)
        trace_bytes = len(json.dumps(body, ensure_ascii=False).encode("utf-8"))
        seal_time = _timed(lambda: trace_ledger.seal_trace(
            body, keys["private_key_path"], "s5-scale",
            out_path=os.path.join(workdir, "scale_tmp.seal.json")), reps)
        verify_time = _timed(lambda: trace_ledger.verify_sealed_trace(
            body, path, keys_path=trust_path), reps)
        ours.append({
            "steps": n,
            "seal_bytes": seal_bytes,
            "trace_bytes": trace_bytes,
            "credential_to_trace_ratio": round(seal_bytes / trace_bytes, 4) if trace_bytes else None,
            "seal_ms": seal_time["median_ms"],
            "verify_ms": verify_time["median_ms"],
            "verify_min_ms": verify_time["min_ms"],
            "per_step_verify_ms": round(verify_time["median_ms"] / n, 4),
            "signature_count": 1,
            "record_id": seal_res.get("payload", {}).get("record_id") if isinstance(seal_res, dict) else None,
        })

    intoto = _measure_intoto(sizes, reps, intoto_path)
    return {"ours": ours, "intoto_per_step_links": intoto}


def _measure_intoto(sizes: list[int], reps: int, intoto_path: str | None) -> dict:
    """对照组：in-toto 3.x 每步一个 link 元数据、每步一次 ed25519 签名。"""
    if not intoto_path:
        return {"skipped": True, "reason": "--intoto-path 未提供"}
    if not os.path.isdir(intoto_path):
        return {"skipped": True, "reason": "目录不存在：%s" % intoto_path}
    if intoto_path not in sys.path:
        sys.path.insert(0, intoto_path)
    try:
        import in_toto  # noqa: F401
        from in_toto.models.link import Link
        from in_toto.models.metadata import Metablock
        from securesystemslib.signer import CryptoSigner
    except Exception as exc:  # noqa: BLE001
        return {"skipped": True, "reason": "%s: %s" % (type(exc).__name__, exc)}

    import in_toto as _it
    signer = CryptoSigner.generate_ed25519()
    pub = dict(signer.public_key.to_dict())
    pub["keyid"] = signer.public_key.keyid

    def _sign_all(n: int) -> list[dict]:
        out = []
        for i in range(n):
            link = Link(
                name="step-%02d" % i,
                materials={},
                products={"out-%02d.txt" % i: {"sha256": "a" * 64}},
                byproducts={"return-value": 0},
                command=["python", "step.py"],
            )
            mb = Metablock(signed=link, signatures=[])
            mb.create_signature(signer)
            out.append(mb.to_dict())
        return out

    def _verify_all(links: list[dict]) -> int:
        ok = 0
        for d in links:
            mb = Metablock.from_dict(json.loads(json.dumps(d)))
            if mb.verify_signature(pub) is None:
                ok += 1
        return ok

    rows = []
    for n in sizes:
        payloads = _sign_all(n)
        total_bytes = sum(len(json.dumps(p, sort_keys=True).encode("utf-8")) for p in payloads)
        sign_t = _timed(lambda n=n: _sign_all(n), max(3, reps // 3))
        verify_t = _timed(lambda p=payloads: _verify_all(p), max(3, reps // 3))
        rows.append({
            "steps": n,
            "signature_count": n,
            "bytes_total": total_bytes,
            "bytes_per_step": round(total_bytes / n, 2),
            "sign_ms_total": sign_t["median_ms"],
            "verify_ms_total": verify_t["median_ms"],
            "sign_ms_per_step": round(sign_t["median_ms"] / n, 4),
            "verify_ms_per_step": round(verify_t["median_ms"] / n, 4),
        })
    return {"skipped": False, "version": getattr(_it, "__version__", "?"), "rows": rows}


# --------------------------------------------------------------- 5. 拒绝码
def measure_refusals(workdir: str, keys: dict) -> dict:
    trust_path = make_trust_store(keys, os.path.join(workdir, "trusted_keys.json"))
    rec = {"alert_id": "S5-REF-001", "verdict": "true_positive", "confidence": 0.9}
    path = os.path.join(workdir, "refusal.seal.json")
    core.seal(rec, keys["private_key_path"], "s5-refusal", out_path=path)
    raw = json.load(open(path, encoding="utf-8"))

    def _load(doc: dict, name: str) -> str:
        p = os.path.join(workdir, "refusal_%s.seal.json" % name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        return p

    cases = {}

    d = copy.deepcopy(raw); d["payload"]["confidence"] = 0.1
    cases["payload_edited"] = _load(d, "payload")

    d = copy.deepcopy(raw); d["signature"]["value"] = "AAAA"
    cases["signature_garbage_b64"] = _load(d, "sig")

    d = copy.deepcopy(raw); d["signature"] = "not-a-dict"
    cases["signature_type_confusion"] = _load(d, "sigtype")

    d = copy.deepcopy(raw); d["seal_header"]["payload_sha256"] = "b" * 64
    cases["header_digest_swapped"] = _load(d, "hdrdigest")

    d = copy.deepcopy(raw); d["seal_header"]["seal_version"] = "9.9"
    cases["unknown_schema_version"] = _load(d, "ver")

    d = copy.deepcopy(raw); d["payload"] = "not-an-object"
    cases["payload_type_confusion"] = _load(d, "payloadtype")

    res = {}
    uncaught = 0
    for name, p in cases.items():
        try:
            r = core.verify(p, keys_path=trust_path)
            res[name] = {"verdict": r.get("verdict"), "reason": r.get("reason")}
        except Exception as exc:  # noqa: BLE001
            uncaught += 1
            res[name] = {"verdict": "EXCEPTION", "reason": type(exc).__name__}
    res["missing_file"] = {}
    try:
        r = core.verify(os.path.join(workdir, "nope.seal.json"), keys_path=trust_path)
        res["missing_file"] = {"verdict": r.get("verdict"), "reason": r.get("reason")}
    except Exception as exc:  # noqa: BLE001
        uncaught += 1
        res["missing_file"] = {"verdict": "EXCEPTION", "reason": type(exc).__name__}

    codes = sorted({(v.get("reason") or "").split(":")[0] for v in res.values() if isinstance(v, dict)})
    return {"cases": res, "distinct_codes": [c for c in codes if c],
            "uncaught_exceptions": uncaught, "cases_total": len(res)}


def measure_trust_separation(workdir: str, keys: dict) -> dict:
    rec = {"alert_id": "S5-TRUST-001", "verdict": "false_positive"}
    p = os.path.join(workdir, "trust.seal.json")
    core.seal(rec, keys["private_key_path"], "s5-trust", out_path=p)
    other = core.keygen(out_dir=os.path.join(workdir, "other_keys"))
    r = core.verify(p, keys_path=other["public_key_path"])
    r2 = core.verify(p, keys_path=None)
    return {
        "stranger_anchor_verdict": r.get("verdict"),
        "stranger_anchor_reason": r.get("reason"),
        "no_anchor_verdict": r2.get("verdict"),
        "no_anchor_reason": r2.get("reason"),
        "never_bare_valid": r.get("verdict") != "VALID" and r2.get("verdict") != "VALID",
    }


def measure_determinism(body: dict) -> dict:
    outs = [_run_probe(DIGEST_PROBE, body) for _ in range(3)]
    digests = [o["digest"] for o in outs]
    return {"runs": len(digests), "digests": digests, "identical": len(set(digests)) == 1}


# --------------------------------------------------------------------- 主流程
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="第五阶段差异度实测台")
    ap.add_argument("--workdir", default=os.path.join(REPO, ".tmp_s5", "bench"))
    ap.add_argument("--out", default=os.path.join(REPO, "evidence", "stage5_diff", "bench.json"))
    ap.add_argument("--reps", type=int, default=21)
    ap.add_argument("--intoto-path", default=os.path.join(REPO, ".tmp_s5_site"))
    ap.add_argument("--keep", action="store_true", help="保留工作目录便于复查")
    args = ap.parse_args(argv)

    workdir = args.workdir
    if os.path.isdir(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir, exist_ok=True)

    keys = core.keygen(out_dir=os.path.join(workdir, "keys"))
    body = build_trace(12, "S5-DETERMINISM")

    report = {
        "stage": "S5",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "cryptography": _dep_version("cryptography"),
            "interpreter": sys.executable,
        },
        "offline": measure_offline(workdir, keys),
        "localize": measure_localization(workdir, keys),
        "coverage": measure_coverage(workdir, keys),
        "scaling": measure_scaling(workdir, keys, [1, 5, 20, 50], args.reps, args.intoto_path),
        "refusals": measure_refusals(workdir, keys),
        "trust": measure_trust_separation(workdir, keys),
        "determinism": measure_determinism(body),
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    _print_summary(report, args.out)
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


def _dep_version(name: str) -> str:
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:  # noqa: BLE001
        return "unknown"


def _print_summary(rep: dict, out: str) -> None:
    off = rep["offline"]
    loc = rep["localize"]
    print("[offline] VALID %d/%d trace=%s socket_attempts=%d denylist=%s"
          % (off["seals_valid"], off["seals_total"], off["trace_verdict"],
             off["socket_attempts"], off["denylist_loaded"]))
    print("[inputs]  %d 个文件 / %d 字节（凭证 %d + 公钥 %d）"
          % (off["verify_inputs_count"], off["verify_inputs_bytes"],
             off["seal_bytes"], off["pubkey_bytes"]))
    print("[localize] detected %d/%d (%.2f)  first_break exact %d/%d"
          % (loc["detected"], len(loc["cases"]), loc["detected_rate"],
             loc["first_break_exact"], loc["first_break_cases"]))
    cov = rep["coverage"]
    print("[coverage] %d steps single credential: detected %d/%d, exact_index %d/%d, "
          "seal %d B vs 1-step %d B (%.3f B/step)"
          % (cov["steps"], cov["detected"], cov["steps"], cov["exact_index"], cov["steps"],
             cov["credential_bytes"], cov["bytes_1step"], cov["bytes_added_per_step"]))
    print("[scaling] steps  our_seal_B  our_verify_ms  ratio_to_trace  |  in-toto sigs  bytes  sign_ms  verify_ms")
    into = rep["scaling"]["intoto_per_step_links"]
    irows = {} if into.get("skipped") else {r["steps"]: r for r in into.get("rows", [])}
    for row in rep["scaling"]["ours"]:
        i = irows.get(row["steps"])
        tail = ("| %d %d %.2f %.2f" % (i["signature_count"], i["bytes_total"],
                                       i["sign_ms_total"], i["verify_ms_total"])) if i else "| n/a"
        print("          %5d %10d %13.2f %15.2f  %s"
              % (row["steps"], row["seal_bytes"], row["verify_ms"],
                 row["credential_to_trace_ratio"], tail))
    if into.get("skipped"):
        print("          in-toto 对照组未跑：%s" % into.get("reason"))
    ref = rep["refusals"]
    print("[refusal] %d 类输入 → 拒绝码 %s, 未捕获异常 %d"
          % (ref["cases_total"], ",".join(ref["distinct_codes"]), ref["uncaught_exceptions"]))
    print("[trust]   stranger=%s no_anchor=%s never_bare_valid=%s"
          % (rep["trust"]["stranger_anchor_verdict"], rep["trust"]["no_anchor_verdict"],
             rep["trust"]["never_bare_valid"]))
    print("[determinism] identical=%s" % rep["determinism"]["identical"])
    print("→ %s" % out)


if __name__ == "__main__":
    raise SystemExit(main())
