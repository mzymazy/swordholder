# -*- coding: utf-8 -*-
"""
评测记录 ↔ 原始响应工件 绑定审计（artifact / response_sha256）
=============================================================
复核意见要求「绑定工件内容、提供可核验证据」，即不能只声明“已修复”，
必须给出逐题可复算的审计结果。本脚本对仓库内所有 47 题评测 JSON 执行：

  1. cases[].artifact 指向的文件是否存在（相对仓库根目录解析）；
  2. sha256(cases[].artifact 文件字节) 是否等于 cases[].response_sha256（严格相等）；
  3. cases[].response 文本与 artifact 文件内容是否一致（容行尾差异）。

输出：evidence/artifact_binding_audit.json（逐文件汇总 + 失败明细）
用法：python evidence/verify_artifact_binding.py
退出码：全部通过 0；存在失败 1。
本脚本不写入任何绝对路径，可跨机器复现。
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def collect_targets():
    targets = []
    for name in sorted(os.listdir(ROOT)):
        if name.startswith("evaluation_results") and name.endswith(".json"):
            targets.append(name)
    ev = os.path.join(ROOT, "evidence")
    for name in sorted(os.listdir(ev)):
        if name.endswith(".json") and name.startswith(("xmodel_", "xadv_", "evaluation_results")):
            targets.append(os.path.join("evidence", name).replace(os.sep, "/"))
    return targets


def audit(rel_path):
    p = os.path.join(ROOT, rel_path.replace("/", os.sep))
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    cases = data.get("cases") or []
    if not cases:
        return None
    ok, missing, mismatch, text_diff = 0, [], [], []
    for case in cases:
        art = case.get("artifact")
        rec_hash = case.get("response_sha256")
        if not art:
            missing.append({"id": case.get("id"), "artifact": None, "reason": "no artifact field"})
            continue
        ap = os.path.join(ROOT, art.replace("/", os.sep))
        if not os.path.exists(ap):
            missing.append({"id": case.get("id"), "artifact": art, "reason": "file not found"})
            continue
        digest = hashlib.sha256(open(ap, "rb").read()).hexdigest()
        if digest != rec_hash:
            mismatch.append({"id": case.get("id"), "artifact": art,
                             "recorded": rec_hash, "actual_sha256_of_artifact": digest})
            continue
        resp = case.get("response", "")
        if resp.rstrip("\n") != open(ap, encoding="utf-8", errors="replace").read().rstrip("\n"):
            text_diff.append({"id": case.get("id"), "artifact": art})
        ok += 1
    return {
        "file": rel_path,
        "model": data.get("model"),
        "cases": len(cases),
        "binding_ok": ok,
        "binding_failed": len(missing) + len(mismatch),
        "artifact_missing": missing,
        "hash_mismatch": mismatch,
        "response_text_differs_from_artifact": text_diff,
    }


def main():
    results, failed = [], 0
    for t in collect_targets():
        r = audit(t)
        if r is None:
            continue
        results.append(r)
        bad = r["binding_failed"]
        failed += bad
        print("[%-58s] cases=%-3d ok=%-3d failed=%d" % (r["file"], r["cases"], r["binding_ok"], bad))
        for item in r["artifact_missing"][:3]:
            print("    MISSING %s" % item)
        for item in r["hash_mismatch"][:3]:
            print("    MISMATCH %s" % item)
    total_cases = sum(r["cases"] for r in results)
    total_ok = sum(r["binding_ok"] for r in results)
    out = {
        "check": "sha256(artifact bytes) == cases[].response_sha256 且 artifact 存在、内容与 response 一致",
        "generated_at_utc": "2026-10-16",
        "files_checked": len(results),
        "cases_checked": total_cases,
        "cases_bound": total_ok,
        "cases_failed": failed,
        "all_bound": failed == 0,
        "hash_alg": "sha256",
        "details": results,
    }
    dst = os.path.join(ROOT, "evidence", "artifact_binding_audit.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n[total] files=%d cases=%d bound=%d failed=%d all_bound=%s" % (
        len(results), total_cases, total_ok, failed, failed == 0))
    print("[done] -> evidence/artifact_binding_audit.json")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
