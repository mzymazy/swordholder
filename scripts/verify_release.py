"""发行物验收：把 dist/ 里的 wheel 装进一个隔离目录，再从"外部视角"跑最小接入示例。

为什么需要它
------------
仓库里所有测试都是**在源码树上**跑的（``pytest`` 直接 import ``swordholder``）。源码树能过
不等于发行物能过：包数据（schema / policy / samples）漏打、entry point 写错、版本号漂移
这类问题只在"装起来的 wheel"里才暴露。本脚本把验收改成对外可复算的：

    pip install <wheel> --target <隔离目录> --no-deps --no-index
    PYTHONPATH=<隔离目录> python examples/minimal_integration.py

判定标准全部来自实际返回：wheel 的 SHA256 与 ``dist/SHA256SUMS`` 一致、隔离目录里的
版本号与 ``pyproject.toml`` 一致、包数据齐全、示例 13 项检查全过。任何一项不符即失败，
退出码 1，并在 JSON 报告里写明是哪一项。

用法
----
    python scripts/verify_release.py                    # 用 dist/ 里最新的 wheel
    python scripts/verify_release.py --write-sums       # 先重写 dist/SHA256SUMS 再验收
    python scripts/verify_release.py --wheel <path> --out release_check.json
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Any

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(REPO, "dist")
REQUIRED_DATA = [
    "swordholder/alert.schema.json",
    "swordholder/seal.schema.json",
    "swordholder/policy/default-soc-triage.yaml",
    "swordholder/policy/email-outbound-approval.yaml",
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pyproject_version() -> str:
    text = open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8").read()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else ""


def newest_wheel() -> str:
    wheels = sorted(glob.glob(os.path.join(DIST, "*.whl")), key=os.path.getmtime)
    return wheels[-1] if wheels else ""


def write_sums(wheel: str) -> str:
    sdist = sorted(glob.glob(os.path.join(DIST, "*.tar.gz")), key=os.path.getmtime)
    lines = [f"{sha256_file(wheel)}  {os.path.basename(wheel)}"]
    if sdist:
        lines.append(f"{sha256_file(sdist[-1])}  {os.path.basename(sdist[-1])}")
    path = os.path.join(DIST, "SHA256SUMS")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def check_sums(wheel: str) -> tuple[bool, str]:
    path = os.path.join(DIST, "SHA256SUMS")
    if not os.path.exists(path):
        return False, "E_NO_SUMS"
    for line in open(path, encoding="utf-8").read().splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        digest, name = parts
        if name == os.path.basename(wheel):
            actual = sha256_file(wheel)
            return (actual == digest), ("OK" if actual == digest else f"E_SUM_MISMATCH:{actual[:12]}")
    return False, "E_NOT_LISTED"


def run(cmd: list[str], env: dict[str, str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=cwd)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="swordholder 发行物（wheel）隔离验收")
    ap.add_argument("--wheel", default=None)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--out", default=None)
    ap.add_argument("--write-sums", action="store_true")
    ap.add_argument("--keep", action="store_true", help="保留隔离目录便于排查")
    args = ap.parse_args(argv)

    wheel = args.wheel or newest_wheel()
    checks: list[dict[str, Any]] = []

    def add(cid: str, name: str, passed: bool, detail: str = "") -> None:
        checks.append({"id": cid, "name": name, "passed": bool(passed), "detail": detail})

    if not wheel or not os.path.exists(wheel):
        report = {"ok": False, "stage": "locate_wheel", "dist": DIST}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    if args.write_sums:
        write_sums(wheel)
    ok, detail = check_sums(wheel)
    add("R1", "wheel SHA256 与 dist/SHA256SUMS 一致", ok, detail)

    version = pyproject_version()
    in_wheel_version = ""
    names: list[str] = []
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        for n in names:
            if n.endswith(".dist-info/METADATA"):
                meta = z.read(n).decode("utf-8", "replace")
                m = re.search(r"^Version:\s*(.+)$", meta, re.M)
                in_wheel_version = m.group(1).strip() if m else ""
    add("R2", "wheel 内 METADATA 版本与 pyproject.toml 一致",
        bool(version) and in_wheel_version == version, f"pyproject={version} wheel={in_wheel_version}")

    missing = [d for d in REQUIRED_DATA if d not in names]
    add("R3", "必带包数据（schema / policy）齐全", not missing, "missing=" + ",".join(missing) if missing else "OK")

    w = zipfile.ZipFile(wheel)
    samples = [n for n in names if n.startswith("swordholder/samples/") and n.endswith(".json")]
    add("R4", "样例告警随 wheel 分发", len(samples) >= 3, f"samples={len(samples)}")

    work = tempfile.mkdtemp(prefix="swordholder-release-")
    target = os.path.join(work, "site")
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("pythonpath", "pythonhome", "pythonstartup")}
    env["PYTHONPATH"] = target
    env["PYTHONIOENCODING"] = "utf-8"

    proc = run([args.python, "-m", "pip", "install", wheel, "--target", target,
                "--no-deps", "--no-index", "--quiet"], env=env, cwd=work)
    add("R5", "wheel 可离线安装（pip --no-index --no-deps）", proc.returncode == 0,
        (proc.stdout + proc.stderr).strip()[-300:] or "OK")

    proc = run([args.python, "-c",
                "import swordholder,sys;print(swordholder.__version__);print(swordholder.__file__)"],
               env=env, cwd=work)
    isolated_version = proc.stdout.splitlines()[0].strip() if proc.returncode == 0 and proc.stdout else ""
    origin = proc.stdout.splitlines()[1].strip() if len(proc.stdout.splitlines()) > 1 else ""
    add("R6", "隔离目录可 import 且版本一致",
        isolated_version == version, f"version={isolated_version} origin={origin}")

    ex_out = os.path.join(work, "minimal_check.json")
    proc = run([args.python, os.path.join(REPO, "examples", "minimal_integration.py"),
                "--workdir", os.path.join(work, "run"), "--out", ex_out], env=env, cwd=work)
    example_ok = os.path.exists(ex_out)
    example_report: dict[str, Any] = {}
    if example_ok:
        example_report = json.load(open(ex_out, encoding="utf-8"))
        example_ok = bool(example_report.get("ok"))
    add("R7", "隔离安装 + 最小接入示例全部通过", example_ok,
        f"{proc.stdout.strip()[-200:]}" if proc.stdout else (proc.stderr.strip()[-200:]))

    report = {
        "ok": all(c["passed"] for c in checks),
        "tool": "swordholder.verify_release",
        "wheel": wheel,
        "wheel_sha256": sha256_file(wheel),
        "wheel_bytes": os.path.getsize(wheel),
        "wheel_files": len(names),
        "version": version,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "checks": checks,
        "example": {
            "passed": example_report.get("summary", {}).get("passed"),
            "total": example_report.get("summary", {}).get("total"),
            "failed": example_report.get("summary", {}).get("failed"),
            "checks": example_report.get("checks", []),
            "timing": example_report.get("timing", {}),
            "payload_sha256": example_report.get("payload_sha256"),
        },
        "workdir": work,
    }

    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(f"[verify_release] {sum(1 for c in checks if c['passed'])}/{len(checks)} release checks "
          f"{'PASS' if report['ok'] else 'FAIL'}")
    for c in checks:
        if not c["passed"]:
            print(f"  FAIL {c['id']} {c['name']} :: {c['detail']}", file=sys.stderr)
    if args.out:
        print(f"[verify_release] report -> {args.out}")

    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
