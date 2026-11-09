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


SCOPE_MODE = "repo-partition"

# 运行产物目录：参与**路径分账**（谁在仓库里必须交代清楚），但不参与**内容摘要**。
# 理由不是放水，而是自指：清单自身、探针结果、回执都在 evidence/ 下，把它们算进内容
# 摘要意味着"清单要预先包含自己的哈希"，任何诚实实现都做不到；真把它们算进去，唯一
# 能通过的写法就是事后重算——那才是真的自证。内容摘要因此覆盖除运行产物外的全部
# 未交付文件（代码、脚本、测试、文档），偷改这些照样被抓。
CONTENT_EXCLUDE_PREFIXES = ("evidence/",)


def _git_ls(root: str, extra_args: list[str], *, timeout: float = 90.0) -> set | None:
    """``git ls-files -z`` 的薄封装。非 git 仓库返回 None（不静默当空集）。"""
    try:
        res = subprocess.run(["git", "ls-files", "-z"] + list(extra_args), cwd=root,
                             capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    out = res.stdout.decode("utf-8", "replace")
    return {p.replace("\\", "/") for p in out.split("\0") if p}


def git_repo_universe(root: str) -> dict | None:
    """「提交后这棵树里有什么」的那个集合。

    ``tracked`` = 已跟踪；``untracked`` = 存在但未提交且**未被 .gitignore 忽略**（即
    确实该提交的东西）；``ignored`` = 被 .gitignore 挡住的（运行期产物、密钥、.venv）。

    分账口径取 ``tracked ∪ untracked``：构建清单时本阶段新增文件可能还没 commit，
    但提交后它们必然进入 ``tracked``，用并集才能让「此刻的分账」与「clone 后的分账」
    算出同一个值。
    """
    tracked = _git_ls(root, [])
    if tracked is None:
        return None
    untracked = _git_ls(root, ["--others", "--exclude-standard"]) or set()
    ignored = _git_ls(root, ["--others", "--ignored", "--exclude-standard"]) or set()
    return {"tracked": tracked, "untracked": untracked - tracked, "ignored": ignored,
            "universe": tracked | (untracked - tracked)}


def pathset_digest(paths: Iterable[str]) -> str:
    """对一组相对路径取摘要（排序、LF 连接、UTF-8）。用于锁死「不在范围内」那一半。"""
    joined = "\n".join(sorted(paths)).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def path_content_digest(root: str, paths: Iterable[str],
                        hash_mode: str = HASH_MODE_CANONICAL) -> str:
    """对「一组文件的内容」取摘要：``path\\0sha256\\n`` 逐条拼后 sha256。

    与 ``pathset_digest`` 的区别：那个只锁路径集合，内容被改照样对得上；这里连内容
    一起锁死，于是「不在交付清单里的那部分」也不再是黑盒——交付方偷偷改一个未交付
    文件（比如 evidence 里的探针结果），摘要立刻对不上。缺失的文件按 ``MISSING``
    计入而不跳过，避免「删掉就算过」。
    """
    rows = []
    for p in sorted({str(p).replace("\\", "/") for p in paths}):
        full = os.path.join(root, p)
        if os.path.isfile(full):
            rows.append("%s\0%s\n" % (p, digest(full, hash_mode)[0]))
        else:
            rows.append("%s\0MISSING\n" % p)
    return hashlib.sha256("".join(rows).encode("utf-8")).hexdigest()


def _under(path: str, prefixes: Iterable[str]) -> bool:
    for pre in prefixes or ():
        pre = pre.replace("\\", "/")
        if path == pre or path.startswith(pre.rstrip("/") + "/"):
            return True
    return False


# 与内容无关、纯粹是「跑一遍就长出来」的产物目录/后缀。它们被 .gitignore 挡住是
# 语言/工具链的既定事实，不构成「交付方私藏了什么」——若也要逐条解释，真实的排除
# 项（如带凭证的样本）就会被上千条 .pyc 淹没，等于变相放水。第三方用同一份清单
# 重算时按相同规则剔除，结论一致。
INTRINSIC_IGNORED_PARTS = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    ".eggs", ".venv", "venv", "node_modules", ".ipynb_checkpoints",
})
INTRINSIC_IGNORED_SUFFIXES = frozenset({
    ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".log", ".err", ".out",
})


def is_intrinsic_ignored(path: str) -> bool:
    """这条被忽略的路径是不是「纯运行期产物」（无需解释，也不算交付缺口）。"""
    parts = path.replace("\\", "/").split("/")
    if any(p in INTRINSIC_IGNORED_PARTS for p in parts[:-1]):
        return True
    name = parts[-1]
    if name.startswith(".coverage"):
        return True
    return os.path.splitext(name)[1].lower() in INTRINSIC_IGNORED_SUFFIXES


def _norm_declared(root: str, path: str) -> str:
    """把「声明为交付物的路径」统一成相对 root 的 posix 路径。

    调用方可能给绝对路径（``collect()`` 的返回值就是绝对路径），也可能给相对路径。
    以前这里只做反斜杠替换，绝对路径会被当成"仓库里不存在的文件"，让 not_in_repo
    冒出一堆假阳性——第三方按自己的习惯传参就会误判交付造假，所以必须归一。
    """
    raw = str(path).replace("\\", "/")
    if not os.path.isabs(raw):
        return raw
    root_abs = os.path.abspath(root)
    try:
        if os.path.commonpath([root_abs, os.path.abspath(raw)]) != root_abs:
            return raw
    except ValueError:  # 跨盘符
        return raw
    return os.path.relpath(os.path.abspath(raw), root_abs).replace("\\", "/")


def scope_report(root: str, declared: Iterable[str], *,
                 delivery_prefixes: Iterable[str] = (),
                 included_ignored: Iterable[str] = (),
                 content_exclude_prefixes: Iterable[str] = CONTENT_EXCLUDE_PREFIXES,
                 hash_mode: str = HASH_MODE_CANONICAL) -> dict:
    """把「交付范围」变成可机械复核的全量分账（R1 的收敛手段）。

    要解决的问题：以前清单只说「我交了这 74 个文件」，为什么不是 76 个、哪 2 个被
    悄悄排除，全靠清单作者自述。现在改成**仓库内每个待提交文件都必须有归属**：

    - ``declared``：清单里的文件（有哈希，交付物）；
    - ``out_of_scope``：``universe - declared``——不交付的部分，用路径集合摘要锁死。

    第三方拿到 clone 后自己跑 ``git ls-files`` 重算这两半，任何「少报几个文件以掩盖」
    都会让 ``out_of_scope_digest`` 对不上或 ``delivery_missing`` 非空，无处可藏。
    """
    root = os.path.abspath(root)
    universe_doc = git_repo_universe(root)
    if universe_doc is None:
        raise ReproduceError("E_REPRO_NOT_A_REPO: %s 不是 git 仓库，无法做交付范围分账" % root)
    universe = universe_doc["universe"]
    declared_set = {_norm_declared(root, p) for p in declared}
    out_of_scope = universe - declared_set
    exclude_prefs = tuple(p.replace("\\", "/") for p in content_exclude_prefixes or ())
    content_covered = {p for p in out_of_scope if not _under(p, exclude_prefs)}
    content_excluded = sorted(out_of_scope - content_covered)
    not_in_repo = sorted(declared_set - universe)
    delivery_missing = sorted(p for p in universe
                              if _under(p, delivery_prefixes) and p not in declared_set)
    ignored_all = [p for p in universe_doc["ignored"] if _under(p, delivery_prefixes)]
    ignored_under = sorted(p for p in ignored_all if not is_intrinsic_ignored(p))
    ignored_intrinsic = len(ignored_all) - len(ignored_under)
    ignored_used = sorted(p for p in (included_ignored or ()) if p in universe_doc["ignored"])
    unexplained_ignored = sorted(set(ignored_under) - set(ignored_used))
    return {
        "mode": SCOPE_MODE,
        "ok": not not_in_repo and not delivery_missing and not unexplained_ignored,
        "delivery_prefixes": sorted({p.replace("\\", "/") for p in delivery_prefixes}),
        "tracked_count": len(universe_doc["tracked"]),
        "untracked_uncommitted_count": len(universe_doc["untracked"]),
        "universe_count": len(universe),
        "declared_count": len(declared_set),
        "out_of_scope_count": len(out_of_scope),
        "out_of_scope_digest": pathset_digest(out_of_scope),
        "out_of_scope_content_digest": path_content_digest(root, content_covered,
                                                          hash_mode),
        "content_exclude_prefixes": sorted(exclude_prefs),
        "content_excluded_count": len(content_excluded),
        "content_covered_count": len(content_covered),
        "declared_digest": pathset_digest(declared_set),
        "not_in_repo": not_in_repo,
        "delivery_missing": delivery_missing,
        "ignored_under_delivery": ignored_under,
        "ignored_explained": ignored_used,
        "ignored_unexplained": unexplained_ignored,
        "ignored_intrinsic_count": ignored_intrinsic,
        "sample_out_of_scope": sorted(out_of_scope)[:8],
    }


def verify_scope(manifest: dict, root: str, *, delivery_prefixes: Iterable[str] = ()) -> dict:
    """独立复核清单声明的交付范围是否真的成立（只读、只看 git 与清单）。"""
    files = manifest.get("files") or []
    declared = [f["path"] for f in files]
    scope = (manifest.get("extra") or {}).get("scope") or {}
    prefixes = list(delivery_prefixes or scope.get("delivery_prefixes") or [])
    try:
        report = scope_report(root, declared, delivery_prefixes=prefixes,
                              included_ignored=scope.get("ignored_explained") or [],
                              content_exclude_prefixes=scope.get(
                                  "content_exclude_prefixes", CONTENT_EXCLUDE_PREFIXES),
                              hash_mode=manifest.get("hash_mode") or HASH_MODE_CANONICAL)
    except ReproduceError as exc:
        return {"ok": False, "error": str(exc)[:200], "checked": len(declared)}
    checks = {
        "no_unbacked_entries": not report["not_in_repo"],
        "no_delivery_gap": not report["delivery_missing"],
        "all_out_of_scope_accounted": (report["out_of_scope_count"]
                                       == scope.get("out_of_scope_count")
                                       and report["out_of_scope_digest"]
                                       == scope.get("out_of_scope_digest")),
        # 范围外那半不只是"路径集合对得上"：内容摘要也要对上，否则交付方改一个
        # 不在清单里的文件（如未交付的脚本、测试、文档）就能绕过整册校验。
        "out_of_scope_content_matches": bool(scope.get("out_of_scope_content_digest"))
        and report["out_of_scope_content_digest"]
        == scope.get("out_of_scope_content_digest"),
        # 内容摘要的豁免不能拿来藏东西：被排除在内容摘要外的前缀不得落在交付前缀内，
        # 否则"交付物"就能以"运行产物"为名免检。
        "content_exclusion_safe": not any(
            _under(p, report["delivery_prefixes"])
            for p in report["content_exclude_prefixes"]),
        # 仓库里存在未提交且未被忽略的文件 = 这棵树上还有"我看见了但没交代"的东西。
        # 第三方 clone 后此值必为 0；我方工作区也必须为 0，否则视为交付不闭包。
        "no_untracked_in_repo": report["untracked_uncommitted_count"] == 0,
        "declared_count_matches": report["declared_count"] == len(declared),
        "ignored_all_explained": not report["ignored_unexplained"],
        # 原来的 prefixes_match 是拿 prefixes 跟自己比，恒真，已废弃。
        # 现在要求：清单声明的每一个文件都必须落在自己声明的交付前缀之内。
        "declared_within_prefixes": all(
            _under(p.replace("\\", "/"), report["delivery_prefixes"]) for p in declared),
    }
    return {"ok": all(checks.values()), "checks": checks,
            "recomputed": {k: report[k] for k in
                           ("tracked_count", "universe_count", "declared_count",
                            "out_of_scope_count", "out_of_scope_digest",
                            "out_of_scope_content_digest",
                            "content_exclude_prefixes", "content_covered_count",
                            "content_excluded_count",
                            "untracked_uncommitted_count",
                            "not_in_repo", "delivery_missing", "ignored_unexplained")},
            "checked": len(declared)}


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
                   tracked_only: bool = False,
                   delivery_prefixes: list[str] | None = None,
                   ignored_explained: list[str] | None = None) -> dict:
    """生成交付清单。``expected`` 一般放探针分档/计数，供外部复跑比对。

    ``tracked_only=True`` 时只收 git 跟踪的文件，并把被剔除的未跟踪文件记进
    ``extra["untracked_excluded"]``——清单必须是"第三方取得到的文件"的清单。

    ``delivery_prefixes`` 非空时，额外写入 ``extra["scope"]``：全仓库分账（交付了什么、
    其余为什么不在范围），供 ``verify_scope`` / ``external_verify.py --check-scope``
    独立重算。这一步把「交付范围由交付方自述」换成「每个待提交文件都有归属且可复算」。
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
    if delivery_prefixes:
        declared_rel = [_rel(root, p) for p in paths]
        merged_extra["scope"] = scope_report(
            root, declared_rel, delivery_prefixes=delivery_prefixes,
            included_ignored=ignored_explained or [], hash_mode=hash_mode)
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
    missing, mismatched, actuals = [], [], []
    for item in manifest.get("files", []):
        full = os.path.join(root, item["path"].replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(item["path"])
            continue
        actual = digest(full, hash_mode)[0]
        # 整树摘要按**实际**哈希复算：它才真正回答"你手上这棵树是不是清单声明的那棵"；
        # 若按清单里声明的哈希复算，摘要校验就退化成"清单自我一致"，改一个字节也照样过。
        actuals.append({"path": item["path"], "sha256": actual})
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
    recomputed = tree_digest(actuals) if len(actuals) == len(manifest.get("files", [])) else None
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
