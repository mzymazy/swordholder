# -*- coding: utf-8 -*-
"""生成第十三阶段的交付清单（含**全仓库分账**，收敛 R1）。

相对 stage12 的两处变化：

1. 交付范围新增 ``scripts/stage13/``、S13 新文档；
2. 清单里写 ``extra.scope``：仓库中每个待提交文件都必须有归属——要么在 ``files``
   里（有哈希、是交付物），要么落在 ``out_of_scope``（用路径集合摘要锁死）。
   以前"为什么只交 74 个而不是 76 个、哪两个被排除"全靠交付方一句话；
   现在第三方跑 ``external_verify.py --check-scope`` 自己重算两半，对不上就失败。

用法::

    python scripts/stage13/build_manifest13.py --root . \
        --probes evidence/stage13/s13_probes.json \
        --out evidence/stage13/s13_manifest.json
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
    "scripts/stage13/",
    "docs/examiner-dossier.md",
    "docs/trace-ledger.md",
    "docs/stage10-compliance-fields.md",
    "docs/stage12-risk-fields-and-tsa.md",
    "docs/stage13-transparency-and-scope.md",
    "pyproject.toml",
    "CHANGELOG.md",
    "tests/",
]

# 交付路径下确实存在、但按设计**不交付**的文件（本机运行产物）。
# 必须逐条给出理由：分账核对时"被忽略且未解释"的文件会让 scope.ok=False。
IGNORED_EXPLAINED = [
    "swordholder/samples/alert_02_token.seal.json",
]

IGNORED_REASONS = {
    "swordholder/samples/alert_02_token.seal.json":
        "本机跑 samples 时生成的签封产物（*.seal.json 已在 .gitignore）；"
        "含本机随机密钥签署的封条，属运行期产物，不应进入版本库；"
        "第三方 clone 后跑 tests 会自行生成同名文件，无需分发",
}

COMMANDS = [
    "python scripts/stage13/run_all.py --root . --out-dir evidence/stage13/e2e "
    "--summary evidence/stage13/s13_e2e_summary.json",
    "python scripts/stage13/build_manifest13.py --root . "
    "--probes evidence/stage13/s13_probes.json --out evidence/stage13/s13_manifest.json",
    "python -I scripts/stage11/external_verify.py --manifest evidence/stage13/s13_manifest.json "
    "--root . --check-scope --actual evidence/stage13/s13_probes_counts.json",
    "python -m pytest tests -q",
]


def probe_counts(probes_path: str) -> dict:
    with open(probes_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    counts = dict(doc.get("counts") or {})
    out = {"probes_total": len(doc.get("probes") or [])}
    out.update({k: v for k, v in counts.items()})
    for item in doc.get("probes") or []:
        out["result_%s" % item["id"]] = item["result"]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="生成 stage13 交付清单（含全仓库分账）")
    ap.add_argument("--root", default=".")
    ap.add_argument("--probes", default="evidence/stage13/s13_probes.json")
    ap.add_argument("--out", default="evidence/stage13/s13_manifest.json")
    ap.add_argument("--extra-path", action="append", default=[],
                    help="额外纳入清单的路径（可多次指定，目录需以 / 结尾）")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    probes_full = args.probes if os.path.isabs(args.probes) else os.path.join(root, args.probes)
    if not os.path.isfile(probes_full):
        print("探针结果不存在，先跑 compliance_probe.py：%s" % probes_full, file=sys.stderr)
        return 2

    out = args.out if os.path.isabs(args.out) else os.path.join(root, args.out)
    # 清单自身也是仓库里的一个文件，必须先落位再分账：否则 out_of_scope 会漏掉它，
    # 提交后（它变成 tracked）第三方重算出的摘要与声明值不一致——假失败。
    if not os.path.isfile(out):
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("{}")

    patterns = list(DELIVERY) + list(args.extra_path)
    paths = list(rp.collect(root, patterns))
    manifest = rp.build_manifest(
        root, paths,
        expected=probe_counts(probes_full),
        commands=COMMANDS,
        dirty_scope=[pat.rstrip("/") for pat in patterns],
        hash_mode=rp.HASH_MODE_CANONICAL,
        tracked_only=True,
        delivery_prefixes=patterns,
        ignored_explained=IGNORED_EXPLAINED,
        extra={"stage": 13,
               "note": "清单覆盖真实交付树；hash_mode=canonical-lf，仅收 git 跟踪文件；"
                       "extra.scope 为全仓库分账（每个待提交文件必有归属）；"
                       "expected 为探针分档与计数，外部复跑必须逐项一致",
               "ignored_reasons": IGNORED_REASONS,
               "one_command": "python scripts/stage13/run_all.py --root . --out-dir "
                              "evidence/stage13/e2e --summary evidence/stage13/s13_e2e_summary.json"},
    )
    rp.dump(manifest, out)
    scope = manifest["extra"].get("scope") or {}
    print(json.dumps({"manifest": out, "file_count": manifest["file_count"],
                      "total_bytes": manifest["total_bytes"],
                      "tree_digest": manifest["tree_digest"],
                      "hash_mode": manifest["hash_mode"],
                      "tracked_only": manifest["extra"].get("tracked_only"),
                      "scope_ok": scope.get("ok"),
                      "scope_declared": scope.get("declared_count"),
                      "scope_out_of_scope": scope.get("out_of_scope_count"),
                      "scope_out_of_scope_digest": scope.get("out_of_scope_digest"),
                      "scope_delivery_missing": scope.get("delivery_missing"),
                      "scope_ignored_unexplained": scope.get("ignored_unexplained"),
                      "expected_keys": len(manifest["expected"]),
                      "git": manifest["env"]["git"]},
                     ensure_ascii=False, sort_keys=True, indent=1))
    return 0 if scope.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
