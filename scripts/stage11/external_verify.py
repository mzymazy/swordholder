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


# ---------------------------------------------------------------- 交付范围分账
# R1（S12.1 遗留）：以前清单只说"我交了这 74 个文件"，为什么不是 76 个、哪几个被
# 悄悄排除，全靠交付方自述。现在清单必须给出全仓库分账，审计方用下面这段**独立**
# 重算：universe = git ls-files（含未被忽略的未提交文件），declared = 清单路径，
# out_of_scope = universe - declared，两边数量与路径摘要都要对上。
# 少报一个文件想掩盖 → out_of_scope_digest 变；虚报一个不存在文件 → not_in_repo；
# 该交没交 → delivery_missing。三条都不是"交付方说了算"。
def _git_paths(root: str, extra_args: list) -> set | None:
    import subprocess

    try:
        res = subprocess.run(["git", "ls-files", "-z"] + list(extra_args), cwd=root,
                             capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return {p.replace("\\", "/") for p in res.stdout.decode("utf-8", "replace").split("\0")
            if p}


def _pathset_digest(paths) -> str:
    return hashlib.sha256("\n".join(sorted(paths)).encode("utf-8")).hexdigest()


def _path_content_digest(root: str, paths, hash_mode: str = "canonical-lf") -> str:
    """``path\\0sha256\\n`` 逐条串起来再 sha256——把「范围外那一半」的内容也锁死。

    独立实现，口径与交付方 reproduce.py 的 path_content_digest 一致（canonical-lf
    规范哈希）。缺失文件记 MISSING 而非跳过，删掉一个文件也必须让摘要变。
    """
    rows = []
    for p in sorted({str(p).replace("\\", "/") for p in paths}):
        full = os.path.join(root, p)
        if os.path.isfile(full):
            rows.append("%s\0%s\n" % (p, file_digest(full, hash_mode)))
        else:
            rows.append("%s\0MISSING\n" % p)
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def _under_prefix(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def _is_intrinsic_ignored(path: str) -> bool:
    """纯运行期产物（__pycache__/*.pyc/.log 等）：无需解释，也不算交付缺口。

    与 swordholder/reproduce.py 的 is_intrinsic_ignored 同规则、独立实现（本文件
    不 import 本项目，避免"用被审方的代码审被审方"）。
    """
    parts = path.replace("\\", "/").split("/")
    intrinsic_parts = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                       ".tox", ".eggs", ".venv", "venv", "node_modules",
                       ".ipynb_checkpoints"}
    if any(p in intrinsic_parts for p in parts[:-1]):
        return True
    name = parts[-1]
    if name.startswith(".coverage"):
        return True
    return os.path.splitext(name)[1].lower() in {
        ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".log", ".err", ".out"}


def check_scope(manifest: dict, root: str) -> dict:
    scope = (manifest.get("extra") or {}).get("scope") or {}
    if not scope:
        return {"ok": False, "error": "E_SCOPE_DECLARED_MISSING",
                "note": "清单未声明 extra.scope，无法核验交付范围"}
    tracked = _git_paths(root, [])
    if tracked is None:
        return {"ok": False, "error": "E_SCOPE_NOT_A_REPO",
                "note": "%s 不是可读 git 仓库（clone 后应可用）" % root}
    untracked = _git_paths(root, ["--others", "--exclude-standard"]) or set()
    ignored = _git_paths(root, ["--others", "--ignored", "--exclude-standard"]) or set()
    universe = tracked | (untracked - tracked)
    declared = {f["path"].replace("\\", "/") for f in manifest.get("files", [])}
    out_of_scope = universe - declared
    prefixes = [p.replace("\\", "/") for p in (scope.get("delivery_prefixes") or [])]

    def under(path):
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)

    not_in_repo = sorted(declared - universe)
    delivery_missing = sorted(p for p in universe if under(p) and p not in declared)
    # 内容摘要的豁免前缀：由清单自己声明，但必须与交付前缀互不相交（否则可借"运行
    # 产物"之名给交付物免检）；evidence/ 下的清单与探针结果本身也在豁免范围内，
    # 因为它们要被摘要覆盖就等于要求清单预先包含自己的哈希——自指、不可能诚实做到。
    exclude_prefs = [str(p).replace("\\", "/") for p in
                     (scope.get("content_exclude_prefixes")
                      or ["evidence/"])]
    hash_mode = manifest.get("hash_mode") or "raw"
    content_covered = {p for p in out_of_scope if not _under_prefix(p, exclude_prefs)}
    ignored_all = sorted(p for p in ignored if under(p))
    ignored_under = [p for p in ignored_all if not _is_intrinsic_ignored(p)]
    explained = set(p.replace("\\", "/") for p in (scope.get("ignored_explained") or []))
    unexplained_ignored = sorted(set(ignored_under) - explained)
    checks = {
        "no_unbacked_entries": not not_in_repo,
        "no_delivery_gap": not delivery_missing,
        "out_of_scope_count_matches": len(out_of_scope) == scope.get("out_of_scope_count"),
        "out_of_scope_digest_matches": _pathset_digest(out_of_scope)
                                       == scope.get("out_of_scope_digest"),
        # 范围外那半的内容也要对得上（仅锁路径等于允许改内容）
        "out_of_scope_content_matches": bool(scope.get("out_of_scope_content_digest"))
        and _path_content_digest(root, content_covered, hash_mode)
        == scope.get("out_of_scope_content_digest"),
        "content_exclusion_safe": not any(under(p) for p in exclude_prefs),
        # 存在未提交且未被忽略的文件 => 这棵树上还有没交代的东西
        "no_untracked_in_repo": not (untracked - tracked),
        "declared_count_matches": len(declared) == scope.get("declared_count"),
        "ignored_all_explained": not unexplained_ignored,
        # 交付物必须都落在声明的交付前缀之内：防止"声明 A 目录、实际夹带 B 目录"。
        # （原先这里比的是 prefixes 自己 vs 自己，恒真，等于没查——已改掉）
        "declared_within_prefixes": bool(declared) and all(under(p) for p in declared),
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "recomputed": {
            "tracked_count": len(tracked),
            "universe_count": len(universe),
            "declared_count": len(declared),
            "out_of_scope_count": len(out_of_scope),
            "out_of_scope_digest": _pathset_digest(out_of_scope),
            "out_of_scope_content_digest": _path_content_digest(root, content_covered, hash_mode),
            "content_exclude_prefixes": exclude_prefs,
            "content_covered_count": len(content_covered),
            "untracked_uncommitted_count": len(untracked - tracked),
            "not_in_repo": not_in_repo,
            "delivery_missing": delivery_missing,
            "ignored_under_delivery": ignored_under,
            "ignored_unexplained": unexplained_ignored,
            "ignored_intrinsic_count": len(ignored_all) - len(ignored_under),
        },
        "declared_scope": {"mode": scope.get("mode"),
                           "declared_count": scope.get("declared_count"),
                           "out_of_scope_count": scope.get("out_of_scope_count"),
                           "out_of_scope_digest": scope.get("out_of_scope_digest"),
                           "out_of_scope_content_digest":
                               scope.get("out_of_scope_content_digest")},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="离线复算交付清单与期望值")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--actual", default=None, help="实测结果 JSON（用于比对 expected）")
    ap.add_argument("--check-scope", action="store_true",
                    help="额外核验交付范围分账（需在 git 仓库内运行）")
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
              "expected": None,
              "scope": check_scope(manifest, args.root) if args.check_scope else None}

    if args.actual:
        with open(args.actual, "r", encoding="utf-8") as fh:
            actual = json.load(fh)
        report["expected"] = compare_expected(manifest.get("expected") or {}, actual)

    ok = (report["hashes"]["ok"]
          and (report["expected"] is None or report["expected"]["ok"])
          and (report["scope"] is None or report["scope"]["ok"]))
    report["ok"] = ok
    text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=1)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
