# -*- coding: utf-8 -*-
"""
v2.2 判定器聚合表生成器（v9 整改 P1-1 / P1-2 / X-5 / X-6 整改）
=================================================================
输入：evidence/judge_rejudge_v2p2_8b_vl.json（由 rejudge_v2p2_8b_vl.py 逐题重判产出）
输出：evidence/judge_v2p2_aggregate.json
      - 每个状态的 5 类分项（recitation / behavior / adversarial / reasoning / normal）
      - 合计通过数 / 总数
      - 判定器版本（semantic-v2.2）、来源文件 sha256、生成脚本名、生成时间
      - 每状态对应的 artifact 目录与 artifact 计数（供威慑凭证 binding 使用）
      - 状态间逐题差异（新增通过 / 退化），用于 X-6 如实披露

设计原则：
  1. 一切数字来自逐题重判记录，不由人工维护，避免"汇总与逐题不一致"。
  2. 记录每条来源文件的 sha256，使表格可被机器复核。
  3. 不修改任何原始评测记录（evaluation_results_v2*.json 保持 v2.1 判定原样），
     只新增 v2.2 重判口径的聚合表。
"""
import hashlib
import json
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REJUDGE = os.path.join(HERE, "judge_rejudge_v2p2_8b_vl.json")
OUT = os.path.join(HERE, "judge_v2p2_aggregate.json")
JUDGE_VERSION = "semantic-v2.2"

# 状态元信息（模型标识与用途），与 README §3.1 表格逐一对应
STATE_META = {
    "evaluation_results_v2.json": dict(state="baseline", label="8B baseline（未注入公理）",
                                       model="qwen3:8b", role="headline"),
    "evaluation_results_v2_injected.json": dict(state="injected", label="8B + 公理注入（system prompt）",
                                                model="qwen3:8b+axiom-injection", role="headline"),
    "evaluation_results_v2_lora.json": dict(state="lora", label="8B + QLoRA 微调（单态）",
                                            model="qwen3:8b+qlora-v62", role="headline"),
    "evaluation_results_v2_lora_combined.json": dict(state="combined", label="8B + QLoRA + 公理注入（组合态）",
                                                     model="qwen3:8b+qlora-v62+system@0.1.0", role="headline"),
    "evidence/xmodel_qwen25vl7b_base.json": dict(state="xmodel_qwen25vl7b_baseline",
                                                 label="跨模型 qwen2.5vl:7b baseline",
                                                 model="qwen2.5vl:7b", role="cross_model"),
    "evidence/xmodel_qwen25vl7b_injected.json": dict(state="xmodel_qwen25vl7b_injected",
                                                     label="跨模型 qwen2.5vl:7b + 公理注入",
                                                     model="qwen2.5vl:7b+axiom-injection", role="cross_model"),
}
KINDS = ["recitation", "behavior", "adversarial", "reasoning", "normal"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    with open(REJUDGE, encoding="utf-8") as f:
        rj = json.load(f)

    states, passed_map = [], {}
    for res in rj["results"]:
        rel = res["file"].replace("/", os.sep)
        meta = STATE_META.get(res["file"])
        if meta is None:
            continue
        rows = res["rows"]
        passed_map[res["file"]] = {r["id"]: r["new_passed"] for r in rows}
        kinds = {}
        for k in KINDS:
            kr = [r for r in rows if r["kind"] == k]
            kinds[k] = {"passed": sum(1 for r in kr if r["new_passed"]), "total": len(kr)}
        art_dir = ""
        for r in rows:
            a = r.get("artifact") or ""
            if a:
                art_dir = os.path.dirname(a).replace("\\", "/")
                break
        art_abs = os.path.join(ROOT, art_dir) if art_dir else ""
        art_count = len([x for x in os.listdir(art_abs) if x.endswith(".txt")]) if art_dir and os.path.isdir(art_abs) else 0
        src_abs = os.path.join(ROOT, rel)
        item = {
            "state": meta["state"], "label": meta["label"], "model": meta["model"],
            "role": meta["role"],
            "result_file": res["file"],
            "result_sha256": sha256_file(src_abs) if os.path.isfile(src_abs) else "",
            "recorded_judge_version": res.get("recorded_judge_version", "semantic-v2.1"),
            "judge_version": JUDGE_VERSION,
            "kinds": kinds,
            "total_passed": sum(v["passed"] for v in kinds.values()),
            "total_count": sum(v["total"] for v in kinds.values()),
            "artifact_dir": art_dir,
            "artifact_count": art_count,
            "failed_ids": [r["id"] for r in rows if not r["new_passed"]],
            "flipped_ids": [r["id"] for r in rows if r.get("changed")],
        }
        states.append(item)

    order = ["baseline", "injected", "lora", "combined",
             "xmodel_qwen25vl7b_baseline", "xmodel_qwen25vl7b_injected"]
    states.sort(key=lambda s: order.index(s["state"]) if s["state"] in order else 99)

    # ---- X-6：状态间逐题差异（新增通过 / 退化），供文档如实披露 ----
    def diff(a, b):
        A, B = passed_map[a], passed_map[b]
        return {"newly_passed": [i for i in B if B[i] and not A[i]],
                "regressed": [i for i in B if not B[i] and A[i]]}

    deltas = []
    pairs = [("evaluation_results_v2.json", "evaluation_results_v2_injected.json"),
             ("evaluation_results_v2_injected.json", "evaluation_results_v2_lora_combined.json"),
             ("evaluation_results_v2_lora.json", "evaluation_results_v2_lora_combined.json"),
             ("evaluation_results_v2.json", "evaluation_results_v2_lora.json"),
             ("evidence/xmodel_qwen25vl7b_base.json", "evidence/xmodel_qwen25vl7b_injected.json")]
    for a, b in pairs:
        if a in passed_map and b in passed_map:
            d = diff(a, b)
            d.update({"from": a, "to": b,
                      "net": len(d["newly_passed"]) - len(d["regressed"]),
                      "from_passed": sum(passed_map[a].values()),
                      "to_passed": sum(passed_map[b].values())})
            deltas.append(d)

    doc = {
        "judge_version": JUDGE_VERSION,
        "judge_implementation": "eval_swordholder_v2.py::JUDGERS_V2（本地纯规则+语义判定函数，无第三方模型调用）",
        "generated_by": "evidence/gen_v2p2_aggregate.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_record": "evidence/judge_rejudge_v2p2_8b_vl.json",
        "source_record_sha256": sha256_file(REJUDGE),
        "source_record_generator": "evidence/rejudge_v2p2_8b_vl.py",
        "note": ("本表由逐题重判记录自动聚合，供 README §3.1 / §3.2 头条数字与威慑凭证 evidence 块直接引用；"
                 "原始评测记录 evaluation_results_v2*.json 保持其当时的判定器（semantic-v2.1）结果不变，"
                 "两者差异（如有）逐题列于本表 flipped_ids。"),
        "states": states,
        "state_deltas": deltas,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"[gen_v2p2_aggregate] done -> {OUT}")
    for s in states:
        print(f"  {s['state']:32s} {s['total_passed']}/{s['total_count']}  judge={s['judge_version']}  art={s['artifact_dir']}({s['artifact_count']})")
    for d in deltas:
        print(f"  delta {os.path.basename(d['from'])} -> {os.path.basename(d['to'])}: "
              f"{d['from_passed']}->{d['to_passed']} new={d['newly_passed']} reg={d['regressed']}")


if __name__ == "__main__":
    main()
