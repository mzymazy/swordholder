"""生成世界级验证的可审计清单：MANIFEST.json + SHA256SUMS.txt。

第三方拿到仓库后，可据此确认"报告里引用的每个数字，都对应到某个具体文件的具体哈希"。
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "evidence", "worldclass")

# 纳入审计的文件（相对路径）：证据 + 脚本 + 门禁 + 被改动源码
TARGETS = [
    "evidence/poison_v2/PREREGISTRATION.md",
    "evidence/poison_v2/REPORT.md",
    "evidence/poison_v2/poison_v2_cases.json",
    "evidence/poison_v2/poison_v2_27b_A.json",
    "evidence/poison_v2/poison_v2_27b_B1.json",
    "evidence/poison_v2/poison_v2_27b_B2.json",
    "evidence/poison_v2/poison_v2_27b_B3.json",
    "evidence/poison_v2/poison_v2_27b_B4.json",
    "evidence/poison_v2/trust_boundary_probe.json",
    "evidence/poison_v2/effect_size_27b.json",
    "evidence/poison_v2/effect_size_8b.json",
    "evidence/worldclass/probe_deterministic.json",
    "evidence/worldclass/REPORT_WORLDCLASS.md",
    "scripts/xadv_poison_live.py",
    "scripts/probe_trust_boundary.py",
    "scripts/worldclass_probe.py",
    "scripts/eval_effect_size.py",
    "tests/test_worldclass_hardening.py",
    "swordholder/agent_loop.py",
    ".github/workflows/security-hardening.yml",
    "swordholder/policy/default-soc-triage.yaml",
]


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_rev() -> dict:
    def run(*args):
        try:
            return subprocess.check_output(args, cwd=ROOT, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except Exception:
            return None
    return {"commit": run("git", "rev-parse", "HEAD"),
            "branch": run("git", "rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(run("git", "status", "--porcelain"))}


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    entries, missing = [], []
    for rel in TARGETS:
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(p):
            missing.append(rel)
            continue
        entries.append({"path": rel, "bytes": os.path.getsize(p), "sha256": sha256(p)})

    manifest = {
        "suite": "swordholder-worldclass-verification",
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "git": git_rev(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "model_under_test": "qwen3.8-27b:ud-q3_k_xl (Ollama, num_ctx 16384, RTX 5080)",
        "cross_model_control": "qwen3:8b (Ollama)",
        "sample_sizes": {
            "poison_v2_runs": 96,
            "effect_size_bare_runs_per_model": 80,
            "deterministic_probe_checks": 57,
            "hardening_tests": 57,
        },
        "reproduce": [
            "pip install -e . pytest",
            "python -m pytest -q",
            "python scripts/worldclass_probe.py --assert",
            "python scripts/probe_trust_boundary.py",
            "set SWORDHOLDER_MODEL=qwen3.8-27b:ud-q3_k_xl && python scripts/eval_effect_size.py --samples 10 --tag 27b",
        ],
        "files": entries,
        "missing": missing,
    }

    with open(os.path.join(OUT_DIR, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    with open(os.path.join(OUT_DIR, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        for e in entries:
            f.write(f"{e['sha256']}  {e['path']}\n")

    print(f"files={len(entries)} missing={len(missing)}")
    for m in missing:
        print("  MISSING", m)
    print(f"git={manifest['git']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
