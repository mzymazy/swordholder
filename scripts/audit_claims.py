#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""声明-证据审计复算器（claims registry evaluator）。

读 `evidence/claims/claims_registry.json`，做两件事：

1. **引用存在性核验**：对每条声明里写的 `ref`（仓库相对路径）做存在性检查，
   把「声称有证据但路径根本不存在」的声明挑出来（这是审计里最常见的假支撑）。
2. **评分复算**：按 registry 内 `scoring` 声明的权重与公式，算出「修补前 / 修补后」
   两套分数，输出 JSON，便于写进报告或做回归对比。

设计约束：
  * 只读，不改任何文件；
  * 不联网，不做语义判断——所有判断都在 registry 里显式写死，脚本只做算术，
    保证任何人跑出来的分数完全一致（可复算性优先于聪明）。

用法
----
    python scripts/audit_claims.py                 # 人类可读
    python scripts/audit_claims.py --json          # 机器可读
    python scripts/audit_claims.py --check-refs    # 只做引用存在性核验（CI 可用）
"""

from __future__ import annotations

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(REPO_ROOT, "evidence", "claims", "claims_registry.json")

CHECKED = ("V", "VR", "P", "U", "F", "S", "B")
GOOD = ("V", "VR")


def load_registry() -> dict:
    with open(REGISTRY, encoding="utf-8") as handle:
        return json.load(handle)


def ref_exists(ref: str) -> bool:
    """ref 可以是文件、目录；支持 `path:LINE` 形式（行号仅作定位，不参与存在性判断）。"""
    if not ref:
        return False
    path = ref.split(":")[0].strip()
    return os.path.exists(os.path.join(REPO_ROOT, path.replace("/", os.sep)))


def check_refs(registry: dict) -> list[dict]:
    problems = []
    for claim in registry["claims"]:
        if not claim.get("ref"):
            continue
        if not ref_exists(claim["ref"]):
            problems.append(
                {
                    "id": claim["id"],
                    "doc": claim["doc"],
                    "loc": claim.get("loc"),
                    "ref": claim["ref"],
                    "claim": claim["claim"],
                }
            )
    return problems


def score(registry: dict, phase: str) -> dict:
    """phase: 'before' 用 verdict_before，'after' 用 verdict。"""
    key = "verdict_before" if phase == "before" else "verdict"
    claims = registry["claims"]

    with_ref = [c for c in claims if c.get("ref")]
    trace_ok = [c for c in with_ref if ref_exists(c["ref"])]
    traceability = len(trace_ok) / len(with_ref) if with_ref else 0.0

    judged = [c for c in claims if c[key] in CHECKED]
    good = [c for c in judged if c[key] in GOOD]
    accuracy = len(good) / len(judged) if judged else 0.0

    recomputable = [c for c in claims if c.get("recomputable") == "yes"]
    recomp_ok = [c for c in recomputable if c[key] in GOOD]
    recomputability = len(recomp_ok) / len(recomputable) if recomputable else 0.0

    negatives = registry.get("negatives", [])
    neg_key = "disclosed_before" if phase == "before" else "disclosed_after"
    disclosed = [n for n in negatives if n.get(neg_key)]
    disclosure = len(disclosed) / len(negatives) if negatives else 0.0

    unfixed = {
        "F": sum(1 for c in claims if c[key] == "F"),
        "B": sum(1 for c in claims if c[key] == "B"),
        "U": sum(1 for c in claims if c[key] == "U"),
    }
    penalty = min(20.0, 5.0 * unfixed["F"] + 3.0 * unfixed["B"] + 2.0 * unfixed["U"])

    weights = registry["scoring"]["weights"]
    composite = 100.0 * (
        weights["traceability"] * traceability
        + weights["accuracy"] * accuracy
        + weights["recomputability"] * recomputability
        + weights["disclosure"] * disclosure
    ) - penalty

    return {
        "phase": phase,
        "claims_total": len(claims),
        "traceability": round(traceability, 4),
        "accuracy": round(accuracy, 4),
        "recomputability": round(recomputability, 4),
        "disclosure": round(disclosure, 4),
        "unfixed": unfixed,
        "penalty": round(penalty, 2),
        "composite": round(composite, 2),
        "counts": {
            v: sum(1 for c in claims if c[key] == v)
            for v in ("V", "VR", "P", "U", "F", "S", "B", "N")
        },
    }


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    registry = load_registry()
    problems = check_refs(registry)
    before, after = score(registry, "before"), score(registry, "after")

    if "--check-refs" in argv:
        if problems:
            print("引用失效 %d 处：" % len(problems))
            for item in problems:
                print("  - [%s] %s %s -> %s" % (item["id"], item["doc"], item["loc"], item["ref"]))
            return 1
        print("全部引用路径存在 -> 通过")
        return 0

    if "--json" in argv:
        print(
            json.dumps(
                {
                    "registry_claims": len(registry["claims"]),
                    "registry_negatives": len(registry.get("negatives", [])),
                    "ref_problems": problems,
                    "before": before,
                    "after": after,
                    "delta": round(after["composite"] - before["composite"], 2),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    print("声明-证据审计复算（registry: evidence/claims/claims_registry.json）")
    print("声明 %d 条 / 负结果 %d 条" % (len(registry["claims"]), len(registry.get("negatives", []))))
    if problems:
        print("\n引用失效 %d 处：" % len(problems))
        for item in problems:
            print("  - [%s] %s %s -> %s" % (item["id"], item["doc"], item["loc"], item["ref"]))
    else:
        print("引用存在性：全部通过")

    for res in (before, after):
        print(
            "\n[%s] 可追溯 %.1f%% · 准确 %.1f%% · 可复算 %.1f%% · 负结果披露 %.1f%% · 罚分 %.1f => 综合 %.2f"
            % (
                "修补前" if res["phase"] == "before" else "修补后",
                res["traceability"] * 100,
                res["accuracy"] * 100,
                res["recomputability"] * 100,
                res["disclosure"] * 100,
                res["penalty"],
                res["composite"],
            )
        )
        print("       判决分布：" + ", ".join("%s=%d" % kv for kv in res["counts"].items() if kv[1]))

    print("\n净变化：%+.2f 分" % (after["composite"] - before["composite"]))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
