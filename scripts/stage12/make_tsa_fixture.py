# -*- coding: utf-8 -*-
"""生成离线可复核的 RFC 3161 时间戳 fixture（一次联网，之后永久离线可用）。

fixture 内容 = 固定 payload + 其规范化字节的 TSA token + freetsa 根证书。
测试与探针都只读它，不联网；只有本脚本需要网络。
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from swordholder import timestamp as ts  # noqa: E402
from swordholder.trace_ledger import _c14n  # noqa: E402

FIXED_PAYLOAD = {
    "actor": "stage12-fixture",
    "digest": "0f" * 32,
    "head": "1a" * 32,
    "record_id": "trace-stage12-fixture",
    "step_count": 3,
    "trace_id": "trace-stage12-fixture",
}
URL = "https://freetsa.org/tsr"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                   "evidence", "stage12_tsa_fixture.json")
ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    "evidence", "stage12_tsa_freetsa_root.pem")


def main() -> int:
    roots = [open(ROOT, "rb").read()] if os.path.exists(ROOT) else None
    payload_bytes = _c14n(FIXED_PAYLOAD).encode("utf-8")
    stamp = ts.stamp_digest(ts.digest_of(payload_bytes), URL, trusted_roots=roots)
    doc = {
        "schema": "swordholder.tsa_fixture/1",
        "url": URL,
        "payload": FIXED_PAYLOAD,
        "payload_c14n_sha256": ts.digest_of(payload_bytes).hex(),
        "digest_alg": stamp["digest_alg"],
        "imprint_sha256": stamp["digest_hex"],
        "nonce": stamp["nonce"],
        "gen_time": stamp["verified"]["tst"]["gen_time"],
        "token_b64": stamp["token_b64"],
        "token_sha256": stamp["token_sha256"],
        "checks": stamp["verified"]["checks"],
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1, sort_keys=True)
    print("fixture ->", OUT)
    print("gen_time:", doc["gen_time"], "checks_all_true:",
          all(bool(v) for v in doc["checks"].values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
