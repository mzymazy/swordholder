# -*- coding: utf-8 -*-
"""Epistemics Sprint 实验：动作轨迹的篡改可发现性对照（tamper-evidence bench）。

要回答的问题只有一个，但必须拆成两问，否则结论会被过度解读：

    Q1 三类方案（明文 / 仅全文摘要签名 / 链式账本）对四类篡改的检出率是多少？
    Q2 检出之后，能否**定位**到哪一步被改？能否只披露片段仍可验？

设计约束（写进报告 limitations 的前提）：
    * 轨迹为确定性合成（seed 固定），不依赖任何模型调用，任何人可重跑复现；
    * 四类篡改各只施加一次，且施加后**不重签**——持有私钥者重签的伪造不在本实验防御范围内；
    * L0 明文组的检出率恒为 0：没有可信基准时，篡改后的文件与原始文件不可区分，
      这不是"方案弱"，而是"无基准不可判"的必然结果，对照组存在的意义是把这个事实量化。

用法::

    .venv\\Scripts\\python.exe scripts\\epistemics_tamper_bench.py --out evidence/epistemics/bench.json
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import trace_ledger as tl  # noqa: E402

ACTIONS = ["get_asset_profile", "get_process_tree", "search_prior_alerts", "check_ioc",
           "lookup_ticket", "get_package_metadata", "submit_verdict"]
HOSTS = ["build-runner-07", "fin-ws-112", "db-prod-3", "hr-lt-08"]
VERDICTS = ["true_positive", "false_positive", "suspicious"]


def make_trace(seed: int, n_steps: int) -> dict:
    """确定性合成一条轨迹：同样的 (seed, n_steps) 永远得到同一份内容。"""
    rng = random.Random((seed, n_steps).__hash__())
    led = tl.TraceLedger(trace_id="TR-%05d" % seed, actor="synthetic-agent")
    for i in range(n_steps):
        led.append(
            ACTIONS[rng.randrange(len(ACTIONS))],
            {"host": HOSTS[rng.randrange(len(HOSTS))], "ioc": "10.0.%d.%d" % (rng.randrange(4), rng.randrange(256))},
            {"verdict": VERDICTS[rng.randrange(len(VERDICTS))], "confidence": round(rng.random(), 4)},
            ts="2026-11-13T10:%02d:00Z" % (i % 60),
        )
    return led.body()


# ------------------------------------------------------------------ 篡改算子
def tamper_modify(body: dict, rng: random.Random) -> tuple[dict, int]:
    b = copy.deepcopy(body)
    idx = rng.randrange(len(b["entries"]))
    b["entries"][idx]["observation"]["verdict"] = "false_positive"
    b["entries"][idx]["observation"]["confidence"] = 0.99
    return b, idx


def tamper_insert(body: dict, rng: random.Random) -> tuple[dict, int]:
    b = copy.deepcopy(body)
    idx = rng.randrange(len(b["entries"]))
    ghost = copy.deepcopy(b["entries"][idx])
    ghost["action"] = "exfiltrate_credentials"
    b["entries"].insert(idx, ghost)
    return b, idx


def tamper_delete(body: dict, rng: random.Random) -> tuple[dict, int]:
    b = copy.deepcopy(body)
    idx = rng.randrange(len(b["entries"]))
    del b["entries"][idx]
    return b, idx


def tamper_reorder(body: dict, rng: random.Random) -> tuple[dict, int]:
    b = copy.deepcopy(body)
    n = len(b["entries"])
    i = rng.randrange(n - 1)
    b["entries"][i], b["entries"][i + 1] = b["entries"][i + 1], b["entries"][i]
    return b, i


TAMPERS = {"modify": tamper_modify, "insert": tamper_insert,
           "delete": tamper_delete, "reorder": tamper_reorder}


# ------------------------------------------------------------------ 三方案
def check_plain(body: dict, original: dict | None = None) -> dict:
    """L0：明文 JSON。不给可信基准 → 无法判定。"""
    if original is None:
        return {"detected": False, "locatable": False, "note": "no_trusted_baseline"}
    same = tl._c14n(body) == tl._c14n(original)  # 需要可信副本才可能对比，这正是签名要解决的问题
    return {"detected": not same, "locatable": False, "note": "byte_compare_with_trusted_copy"}


def _full_digest(body: dict) -> str:
    return hashlib.sha256(tl._c14n(body["entries"]).encode("utf-8")).hexdigest()


def check_digest_only(body: dict, trusted: dict) -> dict:
    """L1：只对全文摘要签名（无逐步链）。能检出，但无法定位到步。"""
    ok = _full_digest(body) == trusted["digest"]
    return {"detected": not ok, "locatable": False, "note": "digest_mismatch"}


def check_ledger(body: dict, trusted: dict) -> dict:
    """L2：链式账本。能检出，并给出首个断点步号。"""
    res = tl.verify_chain(body)
    return {"detected": not res["ok"], "locatable": res["first_break"] is not None,
            "first_break": res["first_break"], "reason": res["reason"]}


# ------------------------------------------------------------------ 部分披露
def check_partial(body: dict, k: int) -> dict:
    """只披露最后 k 步，能否仍验得动？

    L2 可行性：披露段每步自带 prev，从段首 prev 起重算即可验段内完整；
    L1 可行性：摘要覆盖全文，缺任何一步都无法重算 → 不可验。
    """
    entries = body["entries"]
    if k >= len(entries):
        return {"verifiable": False, "reason": "trace_shorter_than_window"}
    window = entries[-k:]
    prev = window[0]["prev"]
    for entry in window:
        if entry["prev"] != prev:
            return {"verifiable": False, "reason": "window_prev_mismatch"}
        prev = tl.entry_hash(entry, prev)
        if entry["hash"] != prev:
            return {"verifiable": False, "reason": "window_hash_mismatch"}
    return {"verifiable": True, "reason": "", "tail_head": prev}


def run(n_traces: int = 200, lengths: tuple[int, ...] = (5, 10, 20, 50), seed: int = 20261113) -> dict:
    rng_global = random.Random(seed)
    stats = {p: {t: {"n": 0, "detected": 0, "locatable": 0, "locate_correct": 0}
                 for t in TAMPERS} for p in ("L0_plain", "L1_digest_only", "L2_ledger")}
    partial = {"L2_ledger": {"n": 0, "verifiable": 0}, "L1_digest_only": {"n": 0, "verifiable": 0}}
    clean_fp = {p: 0 for p in ("L1_digest_only", "L2_ledger")}  # 未篡改却报警 = 假阳性
    total = 0

    for i in range(n_traces):
        n_steps = lengths[i % len(lengths)]
        body = make_trace(i, n_steps)
        total += 1
        trusted = {"digest": _full_digest(body)}

        # 假阳性检查：未篡改时必须判干净
        if check_digest_only(body, trusted)["detected"]:
            clean_fp["L1_digest_only"] += 1
        if check_ledger(body, trusted)["detected"]:
            clean_fp["L2_ledger"] += 1

        # 部分披露：k = 三分之一步长，且至少 2 步
        k = max(2, n_steps // 3)
        p2 = check_partial(body, k)
        partial["L2_ledger"]["n"] += 1
        partial["L2_ledger"]["verifiable"] += 1 if p2["verifiable"] else 0
        partial["L1_digest_only"]["n"] += 1  # 全文摘要下，缺步即不可重算
        partial["L1_digest_only"]["verifiable"] += 0

        for tname, fn in TAMPERS.items():
            tampered, idx = fn(body, rng_global)
            r0 = check_plain(tampered, None)
            r1 = check_digest_only(tampered, trusted)
            r2 = check_ledger(tampered, trusted)
            for pname, r in (("L0_plain", r0), ("L1_digest_only", r1), ("L2_ledger", r2)):
                s = stats[pname][tname]
                s["n"] += 1
                s["detected"] += 1 if r["detected"] else 0
                s["locatable"] += 1 if r.get("locatable") else 0
                if pname == "L2_ledger" and r.get("locatable"):
                    s["locate_correct"] += 1 if r.get("first_break") == idx else 0

    out = {"meta": {"n_traces": total, "lengths": list(lengths), "seed": seed,
                    "tampers": list(TAMPERS), "false_positive": clean_fp,
                    "note": "synthetic deterministic traces; no model calls"},
           "detection": {p: {t: {**s, "detect_rate": round(s["detected"] / s["n"], 4) if s["n"] else None,
                                 "locate_rate": round(s["locate_correct"] / s["n"], 4) if s["n"] else None}
                             for t, s in per.items()} for p, per in stats.items()},
           "partial_disclosure": {p: {**v, "verifiable_rate": round(v["verifiable"] / v["n"], 4) if v["n"] else None}
                                  for p, v in partial.items()}}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence/epistemics/tamper_bench.json")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20261113)
    args = ap.parse_args()

    res = run(n_traces=args.n, seed=args.seed)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)

    print("traces=%d  seed=%d  false_positive=%s" % (
        res["meta"]["n_traces"], res["meta"]["seed"], res["meta"]["false_positive"]))
    print("%-14s %-9s %-8s %-8s %s" % ("scheme", "tamper", "detect", "locate", "locate_ok"))
    for pname, per in res["detection"].items():
        for tname, s in per.items():
            print("%-14s %-9s %-8.2f %-8.2f %.2f" % (
                pname, tname, s["detect_rate"], s["locate_rate"], s["locate_rate"]))
    print("partial_disclosure:", json.dumps(res["partial_disclosure"], ensure_ascii=False))
    print("saved ->", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
