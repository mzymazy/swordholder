#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""构建可分发发行物（wheel + sdist）并写 SHA256SUMS。

为什么需要这个脚本
------------------
`dist/` 在 `.gitignore` 里（本仓库不把二进制塞进 git），所以 clone 下来的人必须自己构建；
而构建有两个容易踩的坑，本脚本把它们固化掉：

1. **构建解释器必须同时有 setuptools 与 wheel**。项目 `.venv` 往往只装了 setuptools，
   直接 `python -m build --no-isolation` 会报 `invalid command 'bdist_wheel'`。
2. **`--no-isolation` 时依赖必须在同一解释器里可见**。若用系统/内置 runtime python，
   可能需要显式把它的 site-packages 加进 `PYTHONPATH`。

用法
----
    python scripts/build_release.py                    # 自动挑解释器
    python scripts/build_release.py --python <exe>      # 指定解释器
    python scripts/build_release.py --check             # 只检查环境，不构建

产物：`dist/swordholder-<version>-py3-none-any.whl`、`dist/swordholder-<version>.tar.gz`、
`dist/SHA256SUMS`。构建完成后建议再跑 `scripts/verify_release.py` 做隔离安装验收。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(REPO_ROOT, "dist")


def read_version() -> str:
    """从 pyproject.toml 读 version（权威源，不从包内 __init__ 猜）。"""
    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("version") and "=" in s:
                return s.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("pyproject.toml 里找不到 version")


PROBE = (
    "import importlib.util as u;"
    "print('%s|%s|%s' % (u.find_spec('setuptools') is not None,"
    " u.find_spec('wheel') is not None, __import__('sys').version.split()[0]))"
)


def probe(python_exe: str) -> dict:
    try:
        out = subprocess.run(
            [python_exe, "-c", PROBE],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"exe": python_exe, "ok": False, "reason": f"无法执行：{exc}"}
    if out.returncode != 0:
        return {"exe": python_exe, "ok": False, "reason": (out.stderr or "").strip()[:300]}
    parts = (out.stdout or "").strip().split("|")
    if len(parts) != 3:
        return {"exe": python_exe, "ok": False, "reason": f"探测输出异常：{out.stdout!r}"}
    has_setuptools, has_wheel, pyver = parts
    return {
        "exe": python_exe,
        "ok": has_setuptools == "True" and has_wheel == "True",
        "python": pyver,
        "setuptools": has_setuptools == "True",
        "wheel": has_wheel == "True",
        "reason": "" if has_setuptools == "True" and has_wheel == "True" else "缺 setuptools 或 wheel",
    }


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="构建 swordholder 发行物并写 SHA256SUMS")
    ap.add_argument("--python", default="", help="指定构建用解释器（默认自动探测）")
    ap.add_argument("--check", action="store_true", help="只检查构建环境")
    args = ap.parse_args()

    # 允许用环境变量传解释器路径：Windows 下命令行带空格的路径（如 Program Files）容易被
    # cmd/PowerShell 的引号规则切断，环境变量是更稳的通道。
    cli_python = args.python or os.environ.get("SWORDHOLDER_BUILD_PYTHON", "").strip()

    candidates = [cli_python] if cli_python else [sys.executable]
    if not cli_python:
        for extra in (
            os.path.join(REPO_ROOT, ".venv", "Scripts", "python.exe"),
            os.path.join(REPO_ROOT, ".venv", "bin", "python"),
        ):
            if os.path.exists(extra):
                candidates.append(extra)

    reports = [probe(c) for c in candidates]
    dedup: dict[str, dict] = {}
    for r in reports:
        key = os.path.normcase(os.path.abspath(r["exe"]))
        dedup.setdefault(key, r)
    reports = list(dedup.values())
    usable = [r for r in reports if r.get("ok")]
    for r in reports:
        state = "OK " if r.get("ok") else "NO "
        print(
            f"[build_release] {state}{r['exe']}  py={r.get('python', '?')} "
            f"setuptools={r.get('setuptools')} wheel={r.get('wheel')} {r.get('reason', '')}"
        )

    if args.check:
        return 0 if usable else 2

    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")

    if usable:
        builder = usable[0]["exe"]
        isolated = False
        # 让 --no-isolation 下的 setuptools/wheel 可见：把构建解释器自身的 site-packages 前置
        site = subprocess.run(
            [builder, "-c", "import site,sys;print(';'.join(site.getsitepackages()+[site.getusersitepackages()]))"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if site.returncode == 0 and site.stdout.strip():
            env["PYTHONPATH"] = site.stdout.strip() + (";" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    else:
        # 退回隔离构建：CI runner / 干净容器里通常只装了 build 而没装 wheel，
        # 让 build 自己建临时环境拉 setuptools+wheel，比直接失败更有用。
        builder = reports[0]["exe"] if reports else sys.executable
        isolated = True
        print(
            "[build_release] 无解释器同时具备 setuptools+wheel，改为隔离构建（build 自建环境拉依赖，需网络）："
            + builder,
            file=sys.stderr,
        )

    version = read_version()
    os.makedirs(DIST, exist_ok=True)

    cmd = [builder, "-m", "build", "--wheel", "--sdist", "--outdir", DIST]
    if not isolated:
        cmd.insert(3, "--no-isolation")
    print("[build_release] " + " ".join(cmd))
    run = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = (run.stdout or "") + (run.stderr or "")
    if run.returncode != 0:
        print("[build_release] 构建失败：\n" + tail[-2000:], file=sys.stderr)
        return 1

    wheel = os.path.join(DIST, f"swordholder-{version}-py3-none-any.whl")
    sdist = os.path.join(DIST, f"swordholder-{version}.tar.gz")
    missing = [p for p in (wheel, sdist) if not os.path.exists(p)]
    if missing:
        print("[build_release] 构建命令成功但产物缺失：" + ", ".join(missing), file=sys.stderr)
        print(tail[-2000:], file=sys.stderr)
        return 1

    sums_path = os.path.join(DIST, "SHA256SUMS")
    lines = []
    for p in (wheel, sdist):
        digest = sha256_of(p)
        lines.append(f"{digest}  {os.path.basename(p)}")
    with open(sums_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    report = {
        "version": version,
        "builder": builder,
        "artifacts": [
            {"name": os.path.basename(p), "bytes": os.path.getsize(p), "sha256": sha256_of(p)}
            for p in (wheel, sdist)
        ],
        "sha256sums": sums_path,
    }
    print(json.dumps(report, ensure_ascii=False, indent=1))
    print("[build_release] 下一步：python scripts/verify_release.py --out release_check.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
