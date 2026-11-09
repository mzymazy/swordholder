# -*- coding: utf-8 -*-
"""外部可复现：交付清单（manifest）的生成与离线校验。

要解决的问题
------------
「我们跑通了」和「你也能跑通」是两件事。前者只需要一份报告，后者需要三样东西：
1. **交付内容固定**：交付树里每个文件的 sha256 写死在清单里，改一个字节就对不上；
2. **环境固定**：Python 版本、依赖版本、仓库提交号写进清单，避免"我这里能跑"；
3. **判定可复算**：清单里记下期望的探针分档与计数，外部复跑后逐项比对，
   不允许"复跑结果不一样但都算通过"。

边界
----
- 只做清单与校验，不打包、不上传、不签名（签名走 seal/certify 那条线）。
- 校验不需要网络、不需要本包的依赖：``scripts/stage11/external_verify.py`` 只用
  标准库重算哈希（真正的第三方视角）。
- 清单**不声明**"结果正确"：它只声明"你算出来的哈希/计数应与这份一致"。
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from typing import Any, Iterable

SCHEMA = "swordholder.repro_manifest/1"

# ---------------------------------------------------------------- 哈希口径
# 跨 checkout 的坑（S12.1 修订）：仓库里存的是 LF，Windows 上 ``core.autocrlf``
# 会把文本以 CRLF 检出，``git archive`` 导出的干净树又是 LF。若清单按「工作区原始
# 字节」记 sha256，同一份提交在两个 checkout 上算出两个值，外部复算必然假失败。
# 因此默认口径是 **canonical-lf**：先把 CRLF 归一成 LF 再算哈希。归一化对两侧
# 施加同一变换，所以"改一个字节必失败"的能力完全保留（真实改动不是换行差异）。
HASH_MODE_CANONICAL = "canonical-lf"
HASH_MODE_RAW = "raw"
HASH_MODES = (HASH_MODE_CANONICAL, HASH_MODE_RAW)


class ReproduceError(ValueError):
    """清单非法或路径越界。"""


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def canonical_bytes(data: bytes) -> bytes:
    """把 CRLF 归一成 LF（不动单独的 CR / LF），得到与换行风格无关的内容。"""
    return data.replace(b"\r\n", b"\n")


def sha256_canonical_file(path: str, chunk: int = 1 << 20) -> str:
    """按 canonical-lf 口径算 sha256 与字节数（分块读，处理跨块的 CRLF）。"""
    h = hashlib.sha256()
    total = 0
    carry = b""
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            buf = carry + buf
            # 末字节是 CR 时留到下一块判断，避免把跨块 CRLF 当成独立 CR
            if buf.endswith(b"\r"):
                carry, buf = buf[-1:], buf[:-1]
            else:
                carry = b""
            norm = buf.replace(b"\r\n", b"\n")
            total += len(norm)
            h.update(norm)
    if carry:
        total += len(carry)
        h.update(carry)
    return h.hexdigest(), total


def sha256_raw_file(path: str) -> str:
    """raw 口径的逐字节 sha256（命名与 canonical 口径对齐，便于在测试里对照）。"""
    return sha256_file(path)


def digest(path: str, hash_mode: str = HASH_MODE_CANONICAL) -> tuple:
    """按指定口径返回 (sha256, 字节数)。bytes 也随口径走，避免两侧字节数不等。"""
    if hash_mode == HASH_MODE_RAW:
        return sha256_file(path), os.path.getsize(path)
    if hash_mode == HASH_MODE_CANONICAL:
        return sha256_canonical_file(path)
    raise ReproduceError("E_REPRO_HASH_MODE: 未知哈希口径 %r（支持 %s）"
                         % (hash_mode, ", ".join(HASH_MODES)))


def _rel(root: str, path: str) -> str:
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    if rel.startswith(".."):
        raise ReproduceError("E_REPRO_PATH_ESCAPE: %s 不在交付根 %s 内" % (path, root))
    return rel.replace("\\", "/")


def file_fingerprint(root: str, path: str,
                     hash_mode: str = HASH_MODE_CANONICAL) -> dict:
    full = path if os.path.isabs(path) else os.path.join(root, path)
    if not os.path.isfile(full):
        raise ReproduceError("E_REPRO_FILE_MISSING: 文件不存在：%s" % full)
    sha, size = digest(full, hash_mode)
    item = {
        "path": _rel(root, full),
        "bytes": size,
        "sha256": sha,
    }
    # 另一种口径的哈希另存一份：它不是判据（换行风格变化会变），而是给"这份清单是在
    # 哪种检出风格下生成的"留痕，出问题时能一眼区分"内容被改"与"只是换行不同"。
    if hash_mode == HASH_MODE_CANONICAL:
        raw_sha, raw_size = digest(full, HASH_MODE_RAW)
        item["sha256_raw"] = raw_sha
        if raw_size != size:
            item["raw_bytes"] = raw_size
    else:
        canon_sha, canon_size = digest(full, HASH_MODE_CANONICAL)
        item["sha256_canonical"] = canon_sha
        if canon_size != size:
            item["canonical_bytes"] = canon_size
    return item


def tree_digest(files: Iterable[dict]) -> str:
    """把 (路径, 哈希) 排序后压成一个总摘要——顺序无关、改名会影响。"""
    pairs = sorted((f["path"], f["sha256"]) for f in files)
    blob = "".join("%s\0%s\n" % (p, s) for p, s in pairs).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _dep_versions() -> dict:
    out = {}
    for name in ("cryptography", "pytest"):
        try:
            mod = __import__(name)
            out[name] = getattr(mod, "__version__", "unknown")
        except Exception:  # noqa: BLE001  外部环境可能没装
            out[name] = None
    return out


def _git_state(root: str, pathspec: list[str] | None = None) -> dict:
    def run(*args: str) -> str | None:
        try:
            res = subprocess.run(["git", *args], cwd=root, capture_output=True,
                                 text=True, encoding="utf-8", timeout=20)
            return res.stdout.strip() if res.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    # dirty 只针对交付树本身：evidence/ 在每次复跑后都会变，把它算进来会让
    # 「清单是否代表已提交状态」永远为真，反而失去意义。
    status = run("status", "--porcelain", "--", *pathspec) if pathspec else run("status", "--porcelain")
    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(status),
            "dirty_scope": list(pathspec) if pathspec else None}


def _pkg_version() -> str | None:
    try:
        from . import __version__  # noqa: PLC0415
        return __version__
    except Exception:  # noqa: BLE001
        return None


def git_tracked_paths(root: str) -> set | None:
    """返回 ``git ls-files`` 的相对路径集合（posix 分隔）；不在 git 仓库里返回 None。

    清单只能收「第三方拿得到」的文件：``git archive`` / clone 导出的树只含被跟踪
    文件，若把 ``.gitignore`` 掉的本机产物（例如 ``*.seal.json`` 这类运行期记录）
    写进清单，外部复算必然报 missing——那是清单的错，不是交付树的错。
    """
    try:
        res = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True,
                             timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    out = res.stdout.decode("utf-8", "replace")
    return {p.replace("\\", "/") for p in out.split("\0") if p}


def collect(root: str, patterns: list[str]) -> list[str]:
    """按目录前缀或后缀收文件（足够用，不引入 glob 复杂度）。"""
    picked = []
    for pat in patterns:
        if pat.endswith("/"):
            base = os.path.join(root, pat.rstrip("/"))
            for path, _dirs, files in os.walk(base):
                picked.extend(os.path.join(path, f) for f in files
                              if not f.endswith((".pyc", ".tmp")))
        elif any(ch in pat for ch in "*?["):
            raise ReproduceError("E_REPRO_PATTERN_UNSUPPORTED: 不支持通配符 %r" % pat)
        else:
            picked.append(os.path.join(root, pat))
    uniq = sorted({os.path.abspath(p) for p in picked if os.path.exists(p)})
    missing = [p for p in picked if not os.path.exists(p)]
    if missing:
        raise ReproduceError("E_REPRO_PATH_MISSING: %s" % ", ".join(missing))
    return uniq


def build_manifest(root: str, paths: list[str], *, extra: dict | None = None,
                   expected: dict | None = None, commands: list[str] | None = None,
                   include_git: bool = True, dirty_scope: list[str] | None = None,
                   hash_mode: str = HASH_MODE_CANONICAL,
                   tracked_only: bool = False) -> dict:
    """生成交付清单。``expected`` 一般放探针分档/计数，供外部复跑比对。

    ``tracked_only=True`` 时只收 git 跟踪的文件，并把被剔除的未跟踪文件记进
    ``extra["untracked_excluded"]``——清单必须是"第三方取得到的文件"的清单。
    """
    root = os.path.abspath(root)
    excluded: list[str] = []
    if tracked_only:
        tracked = git_tracked_paths(root)
        if tracked is None:
            raise ReproduceError("E_REPRO_NOT_A_REPO: %s 不是 git 仓库，无法按跟踪文件收清单"
                                 % root)
        kept = []
        for p in paths:
            rel = _rel(root, p)
            if rel in tracked:
                kept.append(p)
            else:
                excluded.append(rel)
        paths = kept
    files = [file_fingerprint(root, p, hash_mode) for p in paths]
    merged_extra = dict(extra or {})
    if tracked_only:
        merged_extra.setdefault("tracked_only", True)
        merged_extra.setdefault("untracked_excluded", sorted(excluded))
        merged_extra.setdefault("untracked_excluded_count", len(excluded))
    return {
        "schema": SCHEMA,
        "root_name": os.path.basename(root.rstrip("\\/")),
        "hash_mode": hash_mode,
        "generated_at": subprocess.run(
            [sys.executable, "-c",
             "import time;print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))"],
            capture_output=True, text=True, encoding="utf-8").stdout.strip(),
        "swordholder_version": _pkg_version(),
        "env": {
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "deps": _dep_versions(),
            "git": _git_state(root, dirty_scope) if include_git else None,
        },
        "files": files,
        "file_count": len(files),
        "total_bytes": sum(f["bytes"] for f in files),
        "tree_digest": tree_digest(files),
        "commands": commands or [],
        "expected": expected or {},
        "extra": merged_extra,
    }


def verify_manifest(manifest: dict, root: str) -> dict:
    """离线校验交付树是否与清单一致。不需要网络、不需要装本包。

    哈希口径随清单：老清单（无 ``hash_mode``）按原始字节比，新清单按 canonical-lf 比。
    """
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ReproduceError("E_REPRO_SCHEMA: 清单 schema 不符（期望 %s）" % SCHEMA)
    hash_mode = manifest.get("hash_mode") or HASH_MODE_RAW
    missing, mismatched, present = [], [], []
    for item in manifest.get("files", []):
        full = os.path.join(root, item["path"].replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(item["path"])
            continue
        present.append(item)
        actual = digest(full, hash_mode)[0]
        if actual != item["sha256"]:
            detail = {"path": item["path"], "expected": item["sha256"], "actual": actual}
            # 换行差异单独标出来：这类不一致不是内容被改，而是检出风格不同。
            # 判据：换成另一种口径后，实际文件与清单里记录的该口径哈希仍相同。
            other = HASH_MODE_RAW if hash_mode == HASH_MODE_CANONICAL else HASH_MODE_CANONICAL
            recorded = item.get("sha256_raw" if other == HASH_MODE_RAW else "sha256_canonical")
            other_actual = digest(full, other)[0]
            detail["eol_only"] = bool(recorded is not None and other_actual == recorded)
            mismatched.append(detail)
    declared = manifest.get("tree_digest")
    recomputed = tree_digest(present) if len(present) == len(manifest.get("files", [])) else None
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


def compare_expected(expected: dict, actual: dict, *, prefix: str = "") -> dict:
    """逐项比对期望值与实测值，返回不一致明细（missing / diverged）。"""
    missing, diverged = [], []
    for key, want in expected.items():
        name = "%s%s" % (prefix, key)
        if not isinstance(actual, dict) or key not in actual:
            missing.append(name)
        elif actual[key] != want:
            diverged.append({"key": name, "expected": want, "actual": actual[key]})
    return {"ok": not missing and not diverged, "missing": missing, "diverged": diverged}


def dump(manifest: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, sort_keys=True, indent=1)
    return path


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
