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

# 哈希口径（与 swordholder/reproduce.py 保持一致，但这里必须独立实现：
# 第三方手里可能只有这个脚本 + 交付树，不能 import 被审方的包）
HASH_MODE_CANONICAL = "canonical-lf"
HASH_MODE_RAW = "raw"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for buf in iter(lambda: fh.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()


def sha256_canonical_file(path: str, chunk: int = 1 << 20) -> str:
    """CRLF 归一为 LF 后算 sha256（分块读，跨块 CRLF 用 carry 处理）。

    为什么必须归一：同一份 git 提交，Linux/macOS 检出是 LF，Windows 上
    ``core.autocrlf=true`` 检出是 CRLF，``git archive`` 导出又是 LF。按原始字节
    记哈希，同一提交会算出多个值，外部复算就成了假失败。归一化对两侧施加同一
    变换，"内容真被改动"依旧会被抓出来（改动不是换行风格差异）。
    """
    h = hashlib.sha256()
    carry = b""
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            buf = carry + buf
            if buf.endswith(b"\r"):
                carry, buf = buf[-1:], buf[:-1]
            else:
                carry = b""
            h.update(buf.replace(b"\r\n", b"\n"))
    if carry:
        h.update(carry)
    return h.hexdigest()


def file_digest(path: str, hash_mode: str) -> str:
    if hash_mode == HASH_MODE_RAW:
        return sha256_file(path)
    if hash_mode == HASH_MODE_CANONICAL:
        return sha256_canonical_file(path)
    raise SystemExit("清单 hash_mode 非法：%r（支持 %s / %s）"
                     % (hash_mode, HASH_MODE_CANONICAL, HASH_MODE_RAW))


def tree_digest(files: list) -> str:
    pairs = sorted((f["path"], f["sha256"]) for f in files)
    blob = "".join("%s\0%s\n" % (p, s) for p, s in pairs).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def verify(manifest: dict, root: str) -> dict:
    if manifest.get("schema") != SCHEMA:
        raise SystemExit("清单 schema 不符：%r（期望 %s）"
                         % (manifest.get("schema"), SCHEMA))
    hash_mode = manifest.get("hash_mode") or HASH_MODE_RAW
    missing, mismatched, actuals = [], [], []
    for item in manifest.get("files", []):
        full = os.path.join(root, item["path"].replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(item["path"])
            continue
        actual = file_digest(full, hash_mode)
        # 整树摘要按实际哈希复算，才能识别"内容被改"；按声明哈希复算等于自证
        actuals.append({"path": item["path"], "sha256": actual})
        if actual != item["sha256"]:
            detail = {"path": item["path"],
                      "expected": item["sha256"], "actual": actual}
            # 换行差异单独标出来：这类不一致不是内容被改，而是检出风格不同。
            # 判据：换成另一种口径后，实际文件与清单里记录的该口径哈希仍相同。
            other = HASH_MODE_RAW if hash_mode == HASH_MODE_CANONICAL else HASH_MODE_CANONICAL
            recorded = item.get("sha256_raw" if other == HASH_MODE_RAW else "sha256_canonical")
            other_actual = file_digest(full, other)
            detail["eol_only"] = bool(recorded is not None and other_actual == recorded)
            mismatched.append(detail)
    recomputed = (tree_digest(actuals)
                  if len(actuals) == len(manifest.get("files", [])) else None)
    declared = manifest.get("tree_digest")
    return {
        "ok": not missing and not mismatched and recomputed == declared,
        "checked": len(manifest.get("files", [])),
        "hash_mode": hash_mode,
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
