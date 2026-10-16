# -*- coding: utf-8 -*-
"""
v2.2 判定器统一重判（qwen3:8b 四态 + qwen2.5vl:7b 两态）
=========================================================
背景：整改复核要求「固定判定器、逐题重判并自动生成全部表格」，且所有被引用的
评测行都必须标注判定器版本。本脚本对已存响应做纯本地重判（不重新调用模型），
输出 per-case 新旧判定差异与按类型汇总，供 README / 凭证 / 对比表直接引用。

输入（均为仓库内相对路径）：
  evaluation_results_v2.json                  (qwen3:8b baseline)
  evaluation_results_v2_injected.json         (qwen3:8b + system-prompt 注入)
  evaluation_results_v2_lora.json             (qwen3:8b + QLoRA 单态)
  evaluation_results_v2_lora_combined.json    (qwen3:8b + QLoRA + 注入 组合态)
  evidence/xmodel_qwen25vl7b_base.json        (qwen2.5vl:7b baseline)
  evidence/xmodel_qwen25vl7b_injected.json    (qwen2.5vl:7b injected)

输出：evidence/judge_rejudge_v2p2_8b_vl.json
用法：python evidence/rejudge_v2p2_8b_vl.py
说明：本脚本不写入任何绝对路径，可跨机器复现。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import eval_swordholder_v2 as v2  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXPECT_MAP = {sc["id"]: sc.get("expect", "") for kind in v2.SCENARIOS for sc in v2.SCENARIOS[kind]}
KINDS = ["recitation", "behavior", "adversarial", "reasoning", "normal"]

TARGETS = [
    "evaluation_results_v2.json",
    "evaluation_results_v2_injected.json",
    "evaluation_results_v2_lora.json",
    "evaluation_results_v2_lora_combined.json",
    "evidence/xmodel_qwen25vl7b_base.json",
    "evidence/xmodel_qwen25vl7b_injected.json",
]


def _sem_of(case):
    j = case.get("judge")
    if isinstance(j, dict):
        return j.get("semantic_metric", {})
    return {}


def rejudge(rel_path):
    with open(os.path.join(ROOT, rel_path.replace("/", os.sep)), encoding="utf-8") as f:
        data = json.load(f)
    rows, new_by_kind, old_by_kind, changed = [], {}, {}, []
    for case in data["cases"]:
        kind = case["kind"]
        verdict = v2.JUDGERS_V2[kind](case.get("response", ""), EXPECT_MAP.get(case["id"], ""))
        new_passed, old_passed = bool(verdict["passed"]), bool(case.get("passed"))
        new_by_kind.setdefault(kind, [0, 0])
        old_by_kind.setdefault(kind, [0, 0])
        new_by_kind[kind][0] += new_passed
        new_by_kind[kind][1] += 1
        old_by_kind[kind][0] += old_passed
        old_by_kind[kind][1] += 1
        if new_passed != old_passed:
            changed.append({"id": case["id"], "kind": kind, "old_passed": old_passed, "new_passed": new_passed})
        rows.append({
            "id": case["id"], "kind": kind,
            "old_passed": old_passed, "new_passed": new_passed,
            "changed": new_passed != old_passed,
            "old_judge_version": (case.get("judge") or {}).get("judge_version") if isinstance(case.get("judge"), dict) else None,
            "old_semantic": _sem_of(case),
            "new_semantic": verdict.get("semantic", {}),
        })
    result = {
        "file": rel_path,
        "model": data.get("model"),
        "old_judge_version": (data.get("cases") or [{}])[0].get("judge", {}).get("judge_version")
        if isinstance((data.get("cases") or [{}])[0].get("judge"), dict) else None,
        "judge_version": v2.JUDGE_VERSION,
        "total": len(rows),
        "old_pass": sum(v[0] for v in old_by_kind.values()),
        "new_pass": sum(v[0] for v in new_by_kind.values()),
        "by_kind_old": {k: "%d/%d" % (old_by_kind[k][0], old_by_kind[k][1]) for k in old_by_kind},
        "by_kind_v22": {k: "%d/%d" % (new_by_kind[k][0], new_by_kind[k][1]) for k in new_by_kind},
        "changed": changed,
        "rows": rows,
    }
    print("[%s] old=%d/%d v2.2=%d/%d changed=%s" % (
        rel_path, result["old_pass"], result["total"], result["new_pass"], result["total"],
        [(c["id"], c["old_passed"], c["new_passed"]) for c in changed]))
    print("    by_kind v2.2: " + "  ".join("%s=%s" % (k, result["by_kind_v22"].get(k, "-")) for k in KINDS))
    return result


def main():
    out = {
        "judge_version": v2.JUDGE_VERSION,
        "judge_impl": "eval_swordholder_v2.JUDGERS_V2（纯本地函数，不调用模型）",
        "generated_at_utc": "2026-10-16",
        "purpose": "统一判定器版本、逐题重判、消除基线/注入/单态/组合态与跨模型行之间的口径混用",
        "results": [rejudge(t) for t in TARGETS],
    }
    dst = os.path.join(ROOT, "evidence", "judge_rejudge_v2p2_8b_vl.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("[done] -> evidence/judge_rejudge_v2p2_8b_vl.json")


if __name__ == "__main__":
    main()
