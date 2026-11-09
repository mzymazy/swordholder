# -*- coding: utf-8 -*-
"""生成第十二阶段的"外部可复现"交付清单（判据修正版）。

与 stage11 的差别只有一处，但很要紧：交付范围必须覆盖**真实交付树**（8 个交付路径、
约 70 文件），而不是两三文件的 demo。清单里固定交付树逐文件 sha256、运行环境，以及
**期望的探针分档与计数**；第三方用随交付发出的 ``scripts/stage11/external_verify.py``
（仅标准库、``python -I`` 可跑）离线复算并逐项比对。

用法::

    python scripts/stage12/build_manifest12.py --root . \
        --probes evidence/stage12/s12_probes.json \
        --out evidence/stage12/s12_manifest.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from swordholder import reproduce as rp  # noqa: E402

DELIVERY = [
    "swordholder/",
    "scripts/stage11/",
    "scripts/stage12/",
    "docs/examiner-dossier.md",
    "docs/trace-ledger.md",
    "docs/stage10-compliance-fields.md",
    "docs/stage12-risk-fields-and-tsa.md",
    "pyproject.toml",
    "CHANGELOG.md",
    "tests/",
]

COMMANDS = [
    "python scripts/stage11/compliance_probe.py --out evidence/stage12/s12_probes.json "
    "--counts-out evidence/stage12/s12_probes_counts.json",
    "python scripts/stage12/build_manifest12.py --root . --probes evidence/stage12/s12_probes.json "
    "--out evidence/stage12/s12_manifest.json",
    "python -I scripts/stage11/external_verify.py --manifest evidence/stage12/s12_manifest.json "
    "--root . --actual evidence/stage12/s12_probes_counts.json",
    "python -m pytest tests -q",
]


def probe_counts(probes_path: str) -> dict:
    with open(probes_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    counts = dict(doc.get("counts") or {})
    out = {"probes_total": len(doc.get("probes") or [])}
    out.update({k: v for k, v in counts.items()})
    # 逐条结果也进期望值：外部分档若被悄悄改写，比对会直接失败
    for item in doc.get("probes") or []:
        out["result_%s" % item["id"]] = item["result"]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="生成 stage12 外部可复现交付清单")
    ap.add_argument("--root", default=".")
    ap.add_argument("--probes", default="evidence/stage12/s12_probes.json")
    ap.add_argument("--out", default="evidence/stage12/s12_manifest.json")
    ap.add_argument("--extra-path", action="append", default=[],
                    help="额外纳入清单的路径（可多次指定，目录需以 / 结尾）")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    probes_full = args.probes if os.path.isabs(args.probes) else os.path.join(root, args.probes)
    if not os.path.isfile(probes_full):
        print("探针结果不存在，先跑 compliance_probe.py：%s" % probes_full, file=sys.stderr)
        return 2

    patterns = list(DELIVERY) + list(args.extra_path)
    paths = list(rp.collect(root, patterns))
    manifest = rp.build_manifest(
        root, paths,
        expected=probe_counts(probes_full),
        commands=COMMANDS,
        dirty_scope=[pat.rstrip("/") for pat in patterns],
        # S12.1：① canonical-lf 口径，使 Windows(CRLF) 检出与 git archive(LF) 导出
        #        算出同一个哈希；② 只收 git 跟踪的文件，否则会把 *.seal.json 这类
        #        被忽略的本机产物写进清单，第三方从版本库根本取不到。
        hash_mode=rp.HASH_MODE_CANONICAL,
        tracked_only=True,
        extra={"stage": 12,
               "note": "清单覆盖真实交付树；hash_mode=canonical-lf，仅收 git 跟踪文件；"
                       "expected 为探针分档与计数，外部复跑必须逐项一致"},
    )
    out = args.out if os.path.isabs(args.out) else os.path.join(root, args.out)
    rp.dump(manifest, out)
    print(json.dumps({"manifest": out, "file_count": manifest["file_count"],
                      "total_bytes": manifest["total_bytes"],
                      "tree_digest": manifest["tree_digest"],
                      "hash_mode": manifest["hash_mode"],
                      "tracked_only": manifest["extra"].get("tracked_only"),
                      "untracked_excluded": manifest["extra"].get("untracked_excluded"),
                      "expected_keys": len(manifest["expected"]),
                      "git": manifest["env"]["git"]},
                     ensure_ascii=False, sort_keys=True, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
