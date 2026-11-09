# -*- coding: utf-8 -*-
"""一键端到端复现：clone 之后**一条命令**跑完全部可复算声称。

    python scripts/stage13/run_all.py

它做的事（顺序即依赖顺序）
--------------------------
1. **环境快照**：解释器、版本、git HEAD、工作树是否干净、平台；
2. **新鲜复跑全部探针**：``compliance_probe.py`` → 本轮 probes + counts 落到
   ``--out-dir``（默认 ``evidence/stage13/e2e``，已 gitignore）；
3. **对账**：用随交付发出的 ``external_verify.py``（仅标准库）拿**仓库里已提交的**
   清单，去核①本 clone 的每个文件哈希②整树摘要③交付范围分账④把**本轮新跑出的**
   分档与清单里声明的期望逐项比对——这是"换一台机器、换一个检出风格也复现得出同一
   结论"的判据，而不是在自己工作区自己证自己；
4. **重算稳定性**：用本轮 probes 重新生成一份清单，其 ``tree_digest`` / 分账摘要
   必须与已提交清单一致（防"清单是手改过的"）；
5. **单元测试**：``pytest tests -q``（``--skip-tests`` 可跳过）；
6. **透明日志回执**：若有 ``evidence/stage13/s13_anchor_receipts.json``，调
   ``verify_anchor.py`` 去公共只追加日志实查（``--skip-network`` 可跳过）。

只依赖 Python 标准库；仓库里存在 ``.venv`` 时自动优先使用它（``cryptography`` 仅
用于 SET 验签，缺失会如实标记 skipped 而非假装通过）。

退出码：0 全通过 / 1 有步骤不通过 / 2 环境不满足（不是 git 仓库等）。
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_FALLBACK = os.path.dirname(os.path.dirname(HERE))
MANIFEST = "evidence/stage13/s13_manifest.json"
RECEIPTS = "evidence/stage13/s13_anchor_receipts.json"
STATEMENT = "evidence/stage13/s13_anchor_statement.json"
DEFAULT_OUT = "evidence/stage13/e2e"


def pick_python(root: str) -> tuple:
    """选解释器：优先**这个 root 自带**的 .venv，其次当前解释器。

    注意"自带"二字：在 clone 目录里跑时若误用我方工作区 .venv，等于用我的环境证我
    的仓库，外部性就没了。这里如实标注 ``origin``，让第三方一眼看出用的是谁的环境。
    """
    root_abs = os.path.abspath(root)
    for parts in (("Scripts", "python.exe"), ("bin", "python")):
        cand = os.path.join(root_abs, ".venv", *parts)
        if os.path.isfile(cand):
            return cand, "root-venv"
    exe = os.path.abspath(sys.executable).replace("\\", "/").lower()
    origin = "caller-venv" if "/.venv/" in exe else "caller-interpreter"
    return sys.executable, origin


def run(cmd: list, cwd: str, timeout: float = 1800.0) -> dict:
    """跑一条命令。刻意不传 text/encoding：``python -I`` 会让子进程吐出 cp936/其它
    编码的字节，父进程按 utf-8 强行解码会炸，这里拿 bytes 再 replace 兜底。"""
    t0 = time.time()
    try:
        res = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        out = res.stdout.decode("utf-8", "replace")
        err = res.stderr.decode("utf-8", "replace")
        rc = res.returncode
    except subprocess.TimeoutExpired:
        out, err, rc = "", "TIMEOUT after %.0fs" % timeout, 124
    except OSError as exc:
        out, err, rc = "", "OSError: %s" % exc, 127
    return {"cmd": cmd, "returncode": rc, "ok": rc == 0,
            "seconds": round(time.time() - t0, 2),
            "stdout_tail": out[-4000:], "stderr_tail": err[-2000:]}


def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def git_out(root: str, *args: str) -> str | None:
    try:
        res = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout.decode("utf-8", "replace").strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="swordholder 一键端到端复现")
    ap.add_argument("--root", default=REPO_FALLBACK, help="交付树根（clone 后的仓库根）")
    ap.add_argument("--out-dir", default=DEFAULT_OUT)
    ap.add_argument("--summary", default="evidence/stage13/s13_e2e_summary.json")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--skip-network", action="store_true")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    out_dir = args.out_dir if os.path.isabs(args.out_dir) else os.path.join(root, args.out_dir)
    summary_path = args.summary if os.path.isabs(args.summary) else os.path.join(root, args.summary)
    py, py_origin = pick_python(root)
    os.makedirs(out_dir, exist_ok=True)

    head = git_out(root, "rev-parse", "HEAD")
    if head is None:
        print(json.dumps({"ok": False, "reason": "E_NOT_A_GIT_REPO", "root": root},
                         ensure_ascii=False, indent=1))
        return 2
    status = git_out(root, "status", "--porcelain") or ""

    steps = {}
    summary = {
        "schema": "swordholder.e2e_summary/1",
        "root": root,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": {"executable": py, "version": platform.python_version(),
                   "origin": py_origin,
                   "same_as_source_repo": (os.path.abspath(py).lower().startswith(
                       os.path.abspath(REPO_FALLBACK).lower())),
                   "caller_executable": sys.executable},
        "env": {"platform": platform.platform(), "head": head,
                "worktree_clean": not status.strip(),
                "dirty_entries": len([l for l in status.splitlines() if l.strip()])},
        "steps": steps,
    }

    # ---- 1. 环境自检（不是 git 仓库 / 清单缺失直接判失败，不猜）
    pre = {"manifest_present": os.path.isfile(os.path.join(root, args.manifest)),
           "receipts_present": os.path.isfile(os.path.join(root, RECEIPTS)),
           "statement_present": os.path.isfile(os.path.join(root, STATEMENT))}
    steps["env"] = {"ok": pre["manifest_present"], "detail": pre}
    if not pre["manifest_present"]:
        summary["ok"] = False
        summary["reason"] = "E_MANIFEST_MISSING: %s" % args.manifest
        _write(summary_path, summary)
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=1))
        return 1

    # ---- 2. 新鲜复跑全部探针
    probes_out = os.path.join(out_dir, "probes.json")
    counts_out = os.path.join(out_dir, "counts.json")
    probe_cmd = [py, os.path.join("scripts", "stage11", "compliance_probe.py"),
                 "--out", probes_out, "--counts-out", counts_out]
    # 幂等：树里已带外部日志回执时，让 P11 走「核验既有条目」而不是「再提交一条」。
    # 否则每个人跑一次一键复现，就往 sigstore 公共日志塞一条无法删除的垃圾条目。
    anchor_dir = os.path.join(root, "evidence", "stage13")
    anchor_present = os.path.isfile(os.path.join(anchor_dir, "s13_anchor_receipts.json"))
    if anchor_present:
        probe_cmd += ["--anchor-out", anchor_dir]
    steps["probe"] = run(probe_cmd, root)
    steps["probe"]["counts"] = (load_json(probes_out) or {}).get("counts")
    steps["probe"]["anchor_reused"] = anchor_present

    # ---- 3. 对账：已提交清单 × 本 clone 树 × 本轮分档
    verify_out = os.path.join(out_dir, "external_verify.json")
    steps["verify"] = run([py, "-I", os.path.join("scripts", "stage11", "external_verify.py"),
                           "--manifest", args.manifest, "--root", ".",
                           "--check-scope", "--actual", counts_out,
                           "--json-out", verify_out], root)
    vdoc = load_json(verify_out) or {}
    hashes = vdoc.get("hashes") or {}
    scope = vdoc.get("scope") or {}
    expected = vdoc.get("expected") or {}
    summary["facts"] = {
        "manifest_file_count": len(((load_json(os.path.join(root, args.manifest)) or {})
                                    .get("files") or [])),
        "checked": hashes.get("checked"),
        "hash_mode": hashes.get("hash_mode"),
        "declared_tree_digest": hashes.get("declared_tree_digest"),
        "recomputed_tree_digest": hashes.get("recomputed_tree_digest"),
        "tree_digest_match": hashes.get("tree_digest_match"),
        "missing": hashes.get("missing"),
        "mismatched_count": len(hashes.get("mismatched") or []),
        "scope_ok": scope.get("ok"),
        "scope_checks": scope.get("checks"),
        "scope_declared": (scope.get("recomputed") or {}).get("declared_count"),
        "scope_out_of_scope": (scope.get("recomputed") or {}).get("out_of_scope_count"),
        "scope_out_of_scope_digest": (scope.get("recomputed") or {}).get("out_of_scope_digest"),
        "expected_ok": expected.get("ok"),
        "expected_missing": expected.get("missing"),
        "expected_diverged": expected.get("diverged"),
        "fresh_counts": (load_json(counts_out) or {}),
    }

    # ---- 4. 重算稳定性：本轮新清单必须与已提交清单同摘要
    rebuilt = os.path.join(out_dir, "manifest.rebuilt.json")
    steps["rebuild"] = run([py, os.path.join("scripts", "stage13", "build_manifest13.py"),
                            "--root", ".", "--probes", probes_out, "--out", rebuilt], root)
    old = load_json(os.path.join(root, args.manifest)) or {}
    new = load_json(rebuilt) or {}
    same = (bool(old) and bool(new)
            and old.get("tree_digest") == new.get("tree_digest")
            and old.get("file_count") == new.get("file_count")
            and ((old.get("extra") or {}).get("scope") or {}).get("out_of_scope_digest")
            == ((new.get("extra") or {}).get("scope") or {}).get("out_of_scope_digest"))
    steps["rebuild"]["stability"] = {
        "tree_digest_equal": old.get("tree_digest") == new.get("tree_digest"),
        "file_count_equal": old.get("file_count") == new.get("file_count"),
        "scope_digest_equal":
            ((old.get("extra") or {}).get("scope") or {}).get("out_of_scope_digest")
            == ((new.get("extra") or {}).get("scope") or {}).get("out_of_scope_digest"),
        "committed": {"tree_digest": old.get("tree_digest"),
                      "file_count": old.get("file_count")},
        "rebuilt": {"tree_digest": new.get("tree_digest"),
                    "file_count": new.get("file_count")},
    }
    steps["rebuild"]["ok"] = bool(steps["rebuild"]["ok"] and same)

    # ---- 5. 单元测试
    if args.skip_tests:
        steps["tests"] = {"ok": True, "skipped": True,
                          "reason": "--skip-tests"}
    else:
        steps["tests"] = run([py, "-m", "pytest", "tests", "-q", "--tb=line"], root, 3600)
        tail = steps["tests"]["stdout_tail"].strip().splitlines()
        steps["tests"]["tail"] = tail[-3:] if tail else []

    # ---- 6. 透明日志回执实查（网络；缺失时跳过而不是判失败）
    if args.skip_network or not pre["receipts_present"]:
        steps["anchor"] = {"ok": True, "skipped": True,
                           "reason": "--skip-network" if args.skip_network
                           else "E_NO_RECEIPTS（未找到 %s）" % RECEIPTS}
    else:
        anchor_json = os.path.join(out_dir, "anchor_verify.json")
        cmd = [py, "-I", os.path.join("scripts", "stage13", "verify_anchor.py"),
               "--receipt", RECEIPTS, "--json-out", anchor_json, "--verify-set"]
        if pre["statement_present"]:
            cmd += ["--statement", STATEMENT]
        steps["anchor"] = run(cmd, root, 300)
        steps["anchor"]["detail"] = load_json(anchor_json) or {}

    ok = all(s.get("ok") for s in steps.values())
    summary["ok"] = bool(ok)
    summary["failed_steps"] = [k for k, v in steps.items() if not v.get("ok")]
    summary["one_command"] = ("python scripts/stage13/run_all.py  # 本文件由它生成："
                              "%d 步 %s" % (len(steps), "全部通过" if ok else "存在失败"))
    _write(summary_path, summary)
    print(json.dumps({"ok": summary["ok"], "failed_steps": summary["failed_steps"],
                      "steps": {k: {"ok": v.get("ok"), "seconds": v.get("seconds")}
                                for k, v in steps.items()},
                      "facts": {k: summary["facts"][k] for k in
                                ("checked", "tree_digest_match", "scope_ok",
                                 "expected_ok", "mismatched_count")},
                      "summary": summary_path},
                     ensure_ascii=False, sort_keys=True, indent=1))
    return 0 if ok else 1


def _write(path: str, doc: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1))


if __name__ == "__main__":
    sys.exit(main())
