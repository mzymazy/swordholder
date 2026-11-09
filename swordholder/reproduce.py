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


def _rel(root: str, path: str) -> str:
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    if rel.startswith(".."):
        raise ReproduceError("E_REPRO_PATH_ESCAPE: %s 不在交付根 %s 内" % (path, root))
    return rel.replace("\\", "/")


def file_fingerprint(root: str, path: str) -> dict:
    full = path if os.path.isabs(path) else os.path.join(root, path)
    if not os.path.isfile(full):
        raise ReproduceError("E_REPRO_FILE_MISSING: 文件不存在：%s" % full)
    return {
        "path": _rel(root, full),
        "bytes": os.path.getsize(full),
        "sha256": sha256_file(full),
    }


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
                   include_git: bool = True, dirty_scope: list[str] | None = None) -> dict:
    """生成交付清单。``expected`` 一般放探针分档/计数，供外部复跑比对。"""
    root = os.path.abspath(root)
    files = [file_fingerprint(root, p) for p in paths]
    return {
        "schema": SCHEMA,
        "root_name": os.path.basename(root.rstrip("\\/")),
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
        "extra": extra or {},
    }


def verify_manifest(manifest: dict, root: str) -> dict:
    """离线校验交付树是否与清单一致。不需要网络、不需要装本包。"""
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ReproduceError("E_REPRO_SCHEMA: 清单 schema 不符（期望 %s）" % SCHEMA)
    missing, mismatched, present = [], [], []
    for item in manifest.get("files", []):
        full = os.path.join(root, item["path"].replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(item["path"])
            continue
        present.append(item)
        actual = sha256_file(full)
        if actual != item["sha256"]:
            mismatched.append({"path": item["path"], "expected": item["sha256"],
                               "actual": actual})
    declared = manifest.get("tree_digest")
    recomputed = tree_digest(present) if len(present) == len(manifest.get("files", [])) else None
    return {
        "ok": not missing and not mismatched and recomputed == declared,
        "checked": len(manifest.get("files", [])),
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
