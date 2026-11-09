# -*- coding: utf-8 -*-
"""S7 补充：in-toto 在「攻击者持有步骤签名密钥」时的两个加测（原 7 类篡改没覆盖）。

背景：原 7 类篡改都是「改数据但不重签」，必然被签名挡住。真正难的是内部人持钥场景：
  H1 = 改 link 里登记的产物哈希，并用 alice 私钥重签该 link（产物文件不动）
       → 预期：该 link 签名有效，但下一步/检查的 MATCH 规则对不上
  H2 = 改产物文件 + 改 link 哈希 + 重签（数据与元数据自洽）
       → 预期：如果 layout 没有外部锚点，就能一路通过 —— 这是 in-toto 的盲区，
          也是「每步一签」相对「单凭证覆盖全轨迹」的结构性代价之一，必须如实记录。

用法： python s7_intoto_resign.py
输出： s7_intoto_resign.json
"""
from __future__ import annotations

import json
import os
import shutil
import sys

TMP = os.environ["TEMP"]
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import s7_intoto_layout as L  # noqa: E402


def mutate_and_sign(src_root: str, dst_root: str, kind: str) -> dict:
    if os.path.isdir(dst_root):
        shutil.rmtree(dst_root)
    shutil.copytree(src_root, dst_root)
    links_dir = os.path.join(dst_root, "links")
    link_name = sorted(os.listdir(links_dir))[1]          # step01
    link_path = os.path.join(links_dir, link_name)
    with open(link_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    prod = list(doc["signed"]["products"].keys())[0]
    old = doc["signed"]["products"][prod]["sha256"]
    if kind == "H1_link_hash_resigned":
        doc["signed"]["products"][prod]["sha256"] = "1" * 64
        with open(link_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        detail = "改 %s 内 %s 的 sha256（原 %s… → 1111…），产物文件不动" % (link_name, prod, old[:8])
    else:  # H2_artifact_and_link_resigned
        art = os.path.join(dst_root, prod)
        with open(art, "w", encoding="utf-8") as fh:
            fh.write("EVIL PAYLOAD (forged by insider)\n")
        import hashlib
        new = hashlib.sha256(open(art, "rb").read()).hexdigest()
        doc["signed"]["products"][prod]["sha256"] = new
        with open(link_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        detail = ("改产物 %s 内容并同步改 %s 内哈希（%s… → %s…）" % (prod, link_name, old[:8], new[:8]))
    # 用 alice（该步骤的授权 functionary）重签
    sign = L.sh([L.SIGN_EXE, "-f", link_name, "-k", os.path.join(L.KEYS, "alice.key")],
                cwd=links_dir)
    verify = L.sh([L.VERIFY_EXE, "--layout", "root.layout",
                   "--verification-keys", os.path.join(L.KEYS, "owner.pub"),
                   "--link-dir", "links"], cwd=dst_root)
    err = verify["err"]
    named = [s for s in ("step00", "step01", "step02", "check_artifacts") if s in err]
    return {"case": kind, "mutation": detail, "resign_rc": sign["rc"],
            "resign_err_tail": sign["err"][-200:] if sign["rc"] else "",
            "verify_rc": verify["rc"], "detected": verify["rc"] != 0,
            "named_steps_in_error": named, "error_excerpt": err[-400:],
            "verify_out_tail": verify["out"][-200:]}


def main() -> int:
    base = os.path.join(TMP, "s7_bench", "intoto", "resign_base")
    r = L.run_pipeline(base, 3, verify_reps=1)
    base_ok = r.get("verify_rc") == 0 and all(s["rc"] == 0 for s in r["step_runs"])
    rep = {"base": {"verify_rc": r.get("verify_rc"), "base_ok": base_ok,
                    "step_rcs": [s["rc"] for s in r["step_runs"]]},
           "cases": []}
    if not base_ok:
        rep["error"] = "baseline pipeline not OK, abort"
    else:
        for kind in ("H1_link_hash_resigned", "H2_artifact_and_link_resigned"):
            rep["cases"].append(mutate_and_sign(base, os.path.join(TMP, "s7_bench", "intoto", kind),
                                                kind))
        rep["summary"] = {"cases": len(rep["cases"]),
                          "detected": sum(1 for c in rep["cases"] if c["detected"]),
                          "undetected": [c["case"] for c in rep["cases"] if not c["detected"]]}
    out = os.path.join(HERE, "s7_intoto_resign.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
