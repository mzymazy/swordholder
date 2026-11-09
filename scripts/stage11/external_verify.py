# -*- coding: utf-8 -*-
"""外部复算脚本（third-party verifier）——只用标准库，不 import swordholder。

用法::

    python external_verify.py --manifest repro_manifest.json --root /path/to/delivered/tree

做的事
------
1. 按清单逐文件重算 sha256，报告 missing / mismatched；
2. 重算整树摘要 tree_digest，与清单比对（改一个字节、挪一个文件都会变）；
3. 若清单里写了 ``expected`` 且给了 ``--actual``（一份实测结果 JSON），逐项比对
   期望值与实测值——不允许"我这边数字不一样但结论照旧"。

退出码：0 全部一致 / 1 有不一致 / 2 参数或文件问题。

为什么单独放一个脚本而不复用包内函数：外部审计方拿到的可能只有一个压缩包，
他需要一条不依赖被审方代码的验证路径；本脚本只依赖 Python 标准库。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

SCHEMA = "swordholder.repro_manifest/1"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for buf in iter(lambda: fh.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()


def tree_digest(files: list) -> str:
    pairs = sorted((f["path"], f["sha256"]) for f in files)
    blob = "".join("%s\0%s\n" % (p, s) for p, s in pairs).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def verify(manifest: dict, root: str) -> dict:
    if manifest.get("schema") != SCHEMA:
        raise SystemExit("清单 schema 不符：%r（期望 %s）"
                         % (manifest.get("schema"), SCHEMA))
    missing, mismatched, present = [], [], []
    for item in manifest.get("files", []):
        full = os.path.join(root, item["path"].replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(item["path"])
            continue
        present.append(item)
        actual = sha256_file(full)
        if actual != item["sha256"]:
            mismatched.append({"path": item["path"],
                               "expected": item["sha256"], "actual": actual})
    recomputed = (tree_digest(present)
                  if len(present) == len(manifest.get("files", [])) else None)
    declared = manifest.get("tree_digest")
    return {
        "ok": not missing and not mismatched and recomputed == declared,
        "checked": len(manifest.get("files", [])),
        "missing": missing,
        "mismatched": mismatched,
        "declared_tree_digest": declared,
        "recomputed_tree_digest": recomputed,
        "tree_digest_match": recomputed == declared,
    }


def compare_expected(expected: dict, actual: dict) -> dict:
    missing, diverged = [], []
    for key, want in (expected or {}).items():
        if key not in actual:
            missing.append(key)
        elif actual[key] != want:
            diverged.append({"key": key, "expected": want, "actual": actual[key]})
    return {"ok": not missing and not diverged, "missing": missing, "diverged": diverged}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="离线复算交付清单与期望值")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--actual", default=None, help="实测结果 JSON（用于比对 expected）")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    if not os.path.isfile(args.manifest):
        print("清单不存在：%s" % args.manifest, file=sys.stderr)
        return 2
    with open(args.manifest, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    report = {"manifest": os.path.abspath(args.manifest),
              "root": os.path.abspath(args.root),
              "hashes": verify(manifest, args.root),
              "expected": None}

    if args.actual:
        with open(args.actual, "r", encoding="utf-8") as fh:
            actual = json.load(fh)
        report["expected"] = compare_expected(manifest.get("expected") or {}, actual)

    ok = report["hashes"]["ok"] and (report["expected"] is None or report["expected"]["ok"])
    report["ok"] = ok
    text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=1)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
