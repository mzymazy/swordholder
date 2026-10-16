# -*- coding: utf-8 -*-
"""
evaluation 记录 ↔ 原始响应工件 绑定审计（v9 三重核验口径，可跨机器复现）
=========================================================================
回应复核意见「绑定工件内容、提供可核验证据；改哈希不证明工件与回答一致」。
本版对逐题记录做三重核验，任一不成立即计入未绑定：

  T1 文本哈希：response_sha256 == sha256(cases[].response 原文 UTF-8)
  T2 工件字节：artifact_sha256 == sha256(cases[].artifact 文件字节)
  T3 内容包含：工件文件文本（行尾归一化）以 cases[].response 原文结尾
              —— 工件文件 =（PROMPT 头）+（原始响应），证明记录与工件内容一致，
                 而不仅是哈希相等。

边界说明（如实披露，不计入绑定分母）：
  - cases 无 response 字段的聚合统计记录（形如 {id, runs, pass_count, pass_rate, samples}，
    如 v3 稳定性/鲁棒性/对抗与 xadv 系列）不承载逐题原始响应工件，计入 structured_only；
    其逐样本工件目录（artifacts_v3_*/artifacts_xadv_*）随包提交，供人工核验。

用法：python evidence/verify_artifact_binding.py [--dry-run]
输出：evidence/artifact_binding_audit.json
退出码：存在未绑定或内容不一致即 1，否则 0。
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
DRY = "--dry-run" in sys.argv


def collect_targets():
    targets = []
    for name in sorted(os.listdir(ROOT)):
        if name.startswith("evaluation_results") and name.endswith(".json"):
            targets.append(name)
    ev = os.path.join(ROOT, "evidence")
    for name in sorted(os.listdir(ev)):
        if name.endswith(".json") and name.startswith(("xmodel_", "xadv_", "evaluation_results")):
            targets.append("evidence/" + name)
    return targets


def sha_b(b):
    return hashlib.sha256(b).hexdigest()


def norm(s):
    return s.replace("\r\n", "\n").replace("\r", "\n").strip()


def audit(rel):
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    cases = data.get("cases") or []
    if not cases:
        return None
    with_resp = bound = ok_text = ok_bytes = ok_content = 0
    structured_only = 0
    not_bound, bad_content = [], []
    for c in cases:
        resp = c.get("response")
        if not isinstance(resp, str):
            structured_only += 1
            continue
        with_resp += 1
        f_text = sha_b(resp.encode("utf-8")) == c.get("response_sha256")
        art = c.get("artifact")
        f_bytes = f_content = False
        file_hash = None
        if art:
            ap = os.path.join(ROOT, str(art).replace("/", os.sep))
            if os.path.exists(ap):
                raw = open(ap, "rb").read()
                file_hash = sha_b(raw)
                f_bytes = (c.get("artifact_sha256") == file_hash)
                f_content = norm(raw.decode("utf-8", errors="replace")).endswith(norm(resp))
        if f_text and f_bytes and f_content:
            bound += 1
            ok_text += 1
            ok_bytes += 1
            ok_content += 1
        else:
            not_bound.append({"id": c.get("id"), "artifact": art,
                              "T1_response_text_hash_ok": f_text,
                              "T2_artifact_bytes_hash_ok": f_bytes,
                              "T3_content_contains_response_ok": f_content,
                              "sha256_response_text": sha_b(resp.encode("utf-8")),
                              "sha256_artifact_bytes": file_hash,
                              "recorded_response_sha256": c.get("response_sha256"),
                              "recorded_artifact_sha256": c.get("artifact_sha256")})
        if art and os.path.exists(os.path.join(ROOT, str(art).replace("/", os.sep))) and not f_content:
            bad_content.append({"id": c.get("id"), "artifact": art})
    return {
        "file": rel,
        "model": data.get("model"),
        "cases": len(cases),
        "records_with_response": with_resp,
        "bound": bound,
        "T1_response_text_hash_ok": ok_text,
        "T2_artifact_bytes_hash_ok": ok_bytes,
        "T3_content_contains_response_ok": ok_content,
        "not_bound": not_bound,
        "content_inconsistent": bad_content,
        "structured_only": structured_only,
    }


def main():
    details = []
    tot = {"cases": 0, "resp": 0, "bound": 0, "T1": 0, "T2": 0, "T3": 0, "structured": 0}
    not_bound_all = []
    for t in collect_targets():
        r = audit(t)
        if r is None:
            continue
        details.append(r)
        tot["cases"] += r["cases"]
        tot["resp"] += r["records_with_response"]
        tot["bound"] += r["bound"]
        tot["T1"] += r["T1_response_text_hash_ok"]
        tot["T2"] += r["T2_artifact_bytes_hash_ok"]
        tot["T3"] += r["T3_content_contains_response_ok"]
        tot["structured"] += r["structured_only"]
        not_bound_all += [dict(x, file=r["file"]) for x in r["not_bound"]]
        print("[%-58s] cases=%-4d resp=%-4d bound=%-4d T1=%-3d T2=%-3d T3=%-3d structured=%-3d"
              % (r["file"], r["cases"], r["records_with_response"], r["bound"], r["T1_response_text_hash_ok"],
                 r["T2_artifact_bytes_hash_ok"], r["T3_content_contains_response_ok"], r["structured_only"]))

    out = {
        "check": "T1 response_sha256==sha256(response 原文)；T2 artifact_sha256==sha256(artifact 文件字节)；"
                 "T3 artifact 文件（行尾归一化）以 response 原文结尾；三项全部成立才算已绑定。",
        "generated_by": "evidence/verify_artifact_binding.py (v9)",
        "scope": "仓库根 evaluation_results*.json + evidence/{xmodel_,xadv_,evaluation_results}*.json",
        "structured_only_note": "无 response/artifact 字段的聚合统计记录（v3 稳定性/鲁棒性/对抗、xadv 系列）不计入绑定分母；"
                                "其逐样本工件目录 artifacts_v3_*/artifacts_xadv_* 随包提交，供人工核验。",
        "files_checked": len(details),
        "records_total": tot["cases"],
        "records_with_response": tot["resp"],
        "records_structured_only": tot["structured"],
        "bound_total": tot["bound"],
        "T1_response_text_hash_ok": tot["T1"],
        "T2_artifact_bytes_hash_ok": tot["T2"],
        "T3_content_contains_response_ok": tot["T3"],
        "not_bound_count": len(not_bound_all),
        "not_bound": not_bound_all,
        "binding_ratio_scope_A": (round(tot["bound"] / tot["resp"], 6) if tot["resp"] else None),
        "all_bound_scope_A": len(not_bound_all) == 0,
        "all_content_consistent": all(r["content_inconsistent"] == [] for r in details),
        "details": details,
    }
    print("\nrecords_total=%d with_response=%d bound=%d (T1=%d T2=%d T3=%d) not_bound=%d structured_only=%d"
          % (tot["cases"], tot["resp"], tot["bound"], tot["T1"], tot["T2"], tot["T3"], len(not_bound_all),
             tot["structured"]))
    print("all_bound_scope_A=%s  all_content_consistent=%s" % (out["all_bound_scope_A"], out["all_content_consistent"]))
    if DRY:
        print("[dry-run] 未写出 JSON")
        return
    op = os.path.join(ROOT, "evidence", "artifact_binding_audit.json")
    with open(op, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("已写出 evidence/artifact_binding_audit.json")
    sys.exit(0 if (out["all_bound_scope_A"] and out["all_content_consistent"]) else 1)


if __name__ == "__main__":
    main()
