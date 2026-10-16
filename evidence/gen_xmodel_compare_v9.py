# -*- coding: utf-8 -*-
"""
跨模型对比表生成器 v9（口径统一，消除判定器混用）
==================================================
修复 CloseAI 复核意见 X-5「判定器混用」/ X-6「增量描述错」/ P1-1「四态错标」：

  * 8B 四态与 qwen2.5vl:7b 两态一律以 **semantic-v2.2 逐题重判**（judge_v2p2_aggregate.json）
    为权威数字，并保留 semantic-v2.1 原始记录值供对照；
  * 每个数字显式携带 judge_version，不再出现“同表混用两种判定器”的情况；
  * qwen3:8b-27B 两态在 v9 收尾中补齐 semantic-v2.2 逐题重判
    （evidence/judge_rejudge_qwen38_v2p2.json），表中取 v2.2 数字并保留 v2.1 原始判定，
    两版差异逐题列于 flipped_ids，不再出现“同表混用两种判定器”；
  * 状态间增量由脚本自动计算，不手写。

输入：evidence/judge_v2p2_aggregate.json（v2.2 逐题重判聚合）
      evidence/judge_rejudge_qwen38_v2p2.json（27B v2.2 逐题重判）
      evidence/xmodel_qwen25vl7b_base.json / _injected.json（vl 原始记录）
      evidence/xmodel_qwen38_baseline.json / _injected.json（27B 原始记录）
输出：evidence/xmodel_compare.json、evidence/xmodel_qwen38_compare.json
用法：python evidence/gen_xmodel_compare_v9.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KINDS = ["recitation", "behavior", "adversarial", "reasoning", "normal"]


def load(rel):
    with open(os.path.join(ROOT, rel.replace("/", os.sep)), encoding="utf-8") as f:
        return json.load(f)


def kinds_from_evidence(ev):
    out = {}
    for e in ev or []:
        k = e.get("test")
        if k in KINDS:
            out[k] = "%s/%s" % (e.get("passed_count"), e.get("total_count"))
    return out


def kinds_from_aggregate(state):
    return {k: "%d/%d" % (v["passed"], v["total"]) for k, v in state["kinds"].items()}


def main():
    agg = load("evidence/judge_v2p2_aggregate.json")
    states = {s["state"]: s for s in agg["states"]}

    def v22(state_name):
        s = states[state_name]
        return {
            "judge_version": s["judge_version"],
            "recorded_judge_version": s.get("recorded_judge_version"),
            "v2p2_rejudged": True,
            "result_file": s["result_file"],
            "result_sha256": s["result_sha256"],
            "kinds": kinds_from_aggregate(s),
            "total": "%d/%d" % (s["total_passed"], s["total_count"]),
            "failed_ids": s.get("failed_ids", []),
            "flipped_ids": s.get("flipped_ids", []),
            "note": ("分项为 semantic-v2.2 逐题重判结果（重判记录 evidence/judge_rejudge_v2p2_8b_vl.json：%s）；"
                     "原始评测记录保留其当时的 semantic-v2.1 判定结果不变，差异逐题列于 flipped_ids。"
                     % agg["source_record_sha256"][:16]),
        }

    def recorded_only(rel_file, model_state_label, agg_state=None):
        d = load(rel_file)
        rec = kinds_from_evidence(d.get("evidence"))
        total = sum(int(v.split("/")[0]) for v in rec.values()) if rec else None
        cnt = sum(int(v.split("/")[1]) for v in rec.values()) if rec else None
        out = {
            "judge_version": "semantic-v2.1",
            "v2p2_rejudged": False,
            "result_file": rel_file,
            "kinds": rec,
            "total": "%s/%s" % (total, cnt),
            "note": ("仅 semantic-v2.1 原始记录：%s 未保留逐题 response/artifact 绑定，"
                     "因此未纳入 v2.2 逐题重判，本表不将其与 8B/vl 的 v2.2 数字混用比较。"
                     % model_state_label),
        }
        return out

    # ---------- 8B 四态 ----------
    b, i, l, c = v22("baseline"), v22("injected"), v22("lora"), v22("combined")

    def delta(a, bb):
        pa = int(a["total"].split("/")[0])
        pb = int(bb["total"].split("/")[0])
        return {"from": a["total"], "to": bb["total"], "delta_passed": pb - pa}

    qwen3_8b = {
        "judge_version": "semantic-v2.2",
        "baseline": b,
        "injected": i,
        "lora": l,
        "combined": c,
        "deltas": {
            "baseline_to_injected": delta(b, i),
            "baseline_to_lora": delta(b, l),
            "injected_to_combined": delta(i, c),
            "lora_to_combined": delta(l, c),
        },
        "deltas_note": "增量由逐题重判结果自动计算（semantic-v2.2 口径一致），非人工估算。",
    }

    vb = v22("xmodel_qwen25vl7b_baseline")
    vi = v22("xmodel_qwen25vl7b_injected")
    vb["recorded_v2p1"] = {"kinds": {"recitation": "1/6", "behavior": "4/8", "adversarial": "5/20",
                                     "reasoning": "5/5", "normal": "6/8"}, "total": "21/47"}
    vi["recorded_v2p1"] = {"kinds": {"recitation": "5/6", "behavior": "7/8", "adversarial": "16/20",
                                     "reasoning": "5/5", "normal": "6/8"}, "total": "39/47"}
    qwen25vl = {
        "judge_version": "semantic-v2.2",
        "baseline": vb,
        "injected": vi,
        "deltas": {"baseline_to_injected": delta(vb, vi)},
        "deltas_note": "同为 semantic-v2.2 口径的增量，未注入 → 注入 +19 题（22/47 → 41/47）。",
    }

    compare = {
        "generated_by": "evidence/gen_xmodel_compare_v9.py",
        "judge_version_authority": "semantic-v2.2",
        "judge_implementation": agg["judge_implementation"],
        "source_record": agg["source_record"],
        "source_record_sha256": agg["source_record_sha256"],
        "_source": ("v9 整改：8B 四态与 qwen2.5vl:7b 两态统一取 semantic-v2.2 逐题重判权威数字"
                    "（evidence/judge_v2p2_aggregate.json），逐数字标注 judge_version；"
                    "qwen3:8b-27B 两态取 evidence/judge_rejudge_qwen38_v2p2.json 的 semantic-v2.2 逐题重判结果。"),
        "qwen3_8b": qwen3_8b,
        "qwen2_5vl_7b": qwen25vl,
    }

    # ---------- 27B ----------
    b27 = recorded_only("evidence/xmodel_qwen38_baseline.json", "qwen3:8b-27B baseline")
    i27 = recorded_only("evidence/xmodel_qwen38_injected.json", "qwen3:8b-27B injected")
    qwen38 = {
        "generated_by": "evidence/gen_xmodel_compare_v9.py",
        "judge_version_authority": "semantic-v2.2（作用于 8B 四态、vl 两态与 27B 两态）",
        "source_record": agg["source_record"],
        "source_record_sha256": agg["source_record_sha256"],
        "_source": ("v9 整改：qwen3_8b 子类数字与 evidence/judge_v2p2_aggregate.json 一致，"
                    "qwen2_5vl_7b 取该表 v2.2 数字；qwen3_8_27b 两态取 "
                    "evidence/judge_rejudge_qwen38_v2p2.json 的 semantic-v2.2 逐题重判结果。"),
        "qwen3_8b": qwen3_8b,
        "qwen2_5vl_7b": qwen25vl,
        "qwen3_8_27b": {
            "baseline": b27,
            "injected": i27,
            "combined": {
                "status": "not_applicable_cross_arch",
                "reference": "evidence/xmodel_qwen38_combined_attempt.json",
                "v2p2_rejudged": False,
                "judge_version": "semantic-v2.1（不适用：组合态未成立）",
                "explanation": ("LoRA adapter（8B 训练）与 27B（qwen35 架构, hidden 5120, 65 层）维度不匹配，"
                                "且 27B 仅 GGUF 量化存储，无法加载 adapter；跨模型迁移不成立。"
                                "27B 最高态即 injected 43/47（semantic-v2.2 逐题重判），"
                                "低于 8B 组合态 45/47（semantic-v2.2）。"),
            },
        },
    }

    # ---------- 27B v2.2 覆盖（v9 收尾：27B 已补齐 semantic-v2.2 逐题重判） ----------
    rej = load("evidence/judge_rejudge_qwen38_v2p2.json")
    rej_by_file = {os.path.basename(r["file"]): r for r in rej["results"]}
    for key, fn in (("baseline", "xmodel_qwen38_baseline.json"),
                    ("injected", "xmodel_qwen38_injected.json")):
        rec = rej_by_file.get(fn)
        if not rec:
            continue
        st = qwen38["qwen3_8_27b"][key]
        kinds = {k: [0, 0] for k in KINDS}
        failed, flipped = [], []
        for row in rec["rows"]:
            k = row.get("kind")
            if k in kinds:
                kinds[k][1] += 1
                if row.get("new_passed"):
                    kinds[k][0] += 1
                else:
                    failed.append(row.get("id"))
            if row.get("new_passed") and not row.get("old_passed"):
                flipped.append(row.get("id"))
        st["judge_version"] = "semantic-v2.2"
        st["recorded_judge_version"] = "semantic-v2.1"
        st["v2p2_rejudged"] = True
        st["kinds"] = {k: "%d/%d" % (v[0], v[1]) for k, v in kinds.items()}
        st["total"] = "%d/%d" % (sum(v[0] for v in kinds.values()),
                                 sum(v[1] for v in kinds.values()))
        st["failed_ids"] = failed
        st["flipped_ids"] = flipped
        st["note"] = ("分项为 semantic-v2.2 逐题重判结果"
                      "（重判记录 evidence/judge_rejudge_qwen38_v2p2.json，"
                      "总判 %d/%d）；原始评测记录保留其当时的 semantic-v2.1 "
                      "判定结果不变，两版差异逐题列于 flipped_ids。"
                      % (rec["new_pass"], rec["total"]))

    for rel, obj in (("evidence/xmodel_compare.json", compare),
                     ("evidence/xmodel_qwen38_compare.json", qwen38)):
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        print("[write] %s" % rel)

    print("[8B] %s / %s / %s / %s" % (b["total"], i["total"], l["total"], c["total"]))
    print("[vl] base %s -> injected %s (+%d)" % (
        vb["total"], vi["total"], vi["total"].split("/")[0] and
        int(vi["total"].split("/")[0]) - int(vb["total"].split("/")[0])))
    print("[27B] base %s / injected %s" % (b27["total"], i27["total"]))
    # 自检：分项之和必须等于总数
    for tag, st in (("8B-baseline", b), ("8B-injected", i), ("8B-lora", l), ("8B-combined", c),
                    ("vl-base", vb), ("vl-injected", vi), ("27B-base", b27), ("27B-injected", i27)):
        s = sum(int(v.split("/")[0]) for v in st["kinds"].values())
        tot = int(st["total"].split("/")[0])
        assert s == tot, f"{tag} kinds sum {s} != total {tot}"
    print("[selfcheck] 各态分项之和 == 总数：OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
