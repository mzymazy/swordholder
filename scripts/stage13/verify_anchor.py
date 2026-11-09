# -*- coding: utf-8 -*-
"""独立核验一张透明日志回执——只用标准库，不 import swordholder。

用法::

    python verify_anchor.py --receipt s13_anchor_receipts.json --statement s13_anchor_statement.json
    python verify_anchor.py --receipt ... --statement ... --verify-set      # 需要 cryptography
    python verify_anchor.py --receipt ... --uuid <uuid> --digest <sha256>  # 无 statement 时直接指定

做的事（每一步都能被审计方独立重做）
------------------------------------
1. 把 ``statement`` 按规范 JSON（键排序、无空白、UTF-8）重算摘要，与回执里的
   ``artifact_sha256`` 比对——回执锚定的确实是这份声明；
2. ``GET {log_url}/api/v1/log/entries/<entry_uuid>``：条目必须存在（公共只追加
   日志里写进去就删不掉）；
3. 解条目体，取 ``spec.data.hash.value``，与上一步摘要比对——日志里记的确实是这份声明；
4. ``--verify-set`` 时用日志公钥验 ``signedEntryTimestamp``——回执是被日志签名的；
5. 另调一次 ``POST /api/v1/index/retrieve`` 按摘要反查，条目应能被检索到。

退出码：0 通过 / 1 不通过 / 2 参数或网络问题。

为什么要这个脚本：``swordholder/transparency.py`` 是交付方代码，审计方不该靠它取证。
这里只依赖标准库 + 一个公开 HTTP 接口，任何人都能跑。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

SCHEMA = "swordholder.anchor_receipt/1"
DEFAULT_URL = "https://rekor.sigstore.dev"


def canonical(obj) -> bytes:
    """与交付方同一口径的规范 JSON：键排序、``,``/``:`` 紧凑分隔、UTF-8。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def get(url: str, timeout: float = 25.0):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                              "User-Agent": "swordholder-verify-anchor/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


def post(url: str, payload: dict, timeout: float = 25.0):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json",
                                          "User-Agent": "swordholder-verify-anchor/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def verify_set(entry: dict, url: str) -> dict:
    """用日志公钥验 SET。缺 cryptography 时如实报 skipped，不伪装成通过。"""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return {"verified": None, "skipped": True,
                "reason": "E_NO_CRYPTOGRAPHY: 未安装 cryptography，SET 验签跳过"}
    set_b64 = ((entry.get("verification") or {}).get("signedEntryTimestamp"))
    if not set_b64:
        return {"verified": False, "skipped": False, "reason": "E_NO_SET"}
    status, body = get(url + "/api/v1/log/publicKey")
    if status != 200:
        return {"verified": False, "skipped": False, "reason": "E_PUBKEY_HTTP_%s" % status}
    pem = json.loads(body.decode("utf-8", "replace"))  # 该端点返回 JSON 字符串而非裸 PEM
    payload = json.dumps({"body": entry.get("body"),
                          "integratedTime": entry.get("integratedTime"),
                          "logID": entry.get("logID"),
                          "logIndex": entry.get("logIndex")},
                         separators=(",", ":")).encode("utf-8")
    try:
        pub = serialization.load_pem_public_key(pem.encode("ascii"))
        pub.verify(base64.b64decode(set_b64), payload, ec.ECDSA(hashes.SHA256()))
        return {"verified": True, "skipped": False}
    except InvalidSignature:
        return {"verified": False, "skipped": False, "reason": "E_SET_BAD_SIGNATURE"}
    except (ValueError, TypeError) as exc:
        return {"verified": False, "skipped": False,
                "reason": "E_SET_UNUSABLE: %s" % str(exc)[:120]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="独立核验透明日志回执")
    ap.add_argument("--receipt", required=True, help="回执 JSON")
    ap.add_argument("--statement", default=None, help="被锚定的声明 JSON（与回执同目录常伴）")
    ap.add_argument("--uuid", default=None, help="无 statement 时直接给条目 uuid")
    ap.add_argument("--digest", default=None, help="无 statement 时直接给声明摘要")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--verify-set", action="store_true")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    with open(args.receipt, "r", encoding="utf-8") as fh:
        receipt = json.load(fh)
    report = {"receipt": args.receipt, "backend": receipt.get("backend"),
              "log_url": receipt.get("log_url") or args.url}

    if receipt.get("schema") != SCHEMA:
        print(json.dumps({"ok": False, "reason": "E_RECEIPT_SCHEMA: %r"
                          % receipt.get("schema")}, ensure_ascii=False))
        return 1
    url = (receipt.get("log_url") or args.url).rstrip("/")

    if args.statement:
        with open(args.statement, "r", encoding="utf-8") as fh:
            statement = json.load(fh)
        local = hashlib.sha256(canonical(statement)).hexdigest()
    elif args.digest:
        local = args.digest
    else:
        print("需要 --statement 或 --digest", file=sys.stderr)
        return 2
    uuid = args.uuid or receipt.get("entry_uuid")
    report.update({"declared_digest": receipt.get("artifact_sha256"),
                   "local_digest": local,
                   "digest_match": receipt.get("artifact_sha256") == local,
                   "entry_uuid": uuid, "external": bool(receipt.get("external"))})
    if not uuid:
        report.update({"ok": False, "reason": "E_NO_UUID"})
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return 1

    try:
        status, body = get(url + "/api/v1/log/entries/" + uuid)
    except (urllib.error.URLError, OSError) as exc:
        report.update({"ok": False, "reason": "E_NETWORK: %s" % str(exc)[:160]})
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return 2
    report["entry_http_status"] = status
    report["entry_present"] = status == 200
    if status != 200:
        report.update({"ok": False, "reason": "E_ENTRY_MISSING_HTTP_%s" % status})
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return 1

    doc = json.loads(body.decode("utf-8", "replace"))
    entry = doc.get(uuid) or next(iter(doc.values()))
    report["integrated_time"] = entry.get("integratedTime")
    report["log_index"] = entry.get("logIndex")
    report["log_id"] = entry.get("logID")
    try:
        inner = json.loads(base64.b64decode(entry.get("body") or ""))
        value = ((inner.get("spec") or {}).get("data") or {}).get("hash", {}).get("value")
        report["body_digest"] = value
        report["body_digest_match"] = value == local
        report["kind"] = inner.get("kind")
    except (ValueError, TypeError):
        report["body_digest_match"] = False
        report["reason_body"] = "E_BODY_DECODE"

    try:
        st2, body2 = post(url + "/api/v1/index/retrieve", {"hash": "sha256:" + local})
        found = json.loads(body2.decode("utf-8", "replace") or "[]") if st2 == 200 else []
        report["search_http_status"] = st2
        report["search_hits"] = found if isinstance(found, list) else []
        report["search_finds_entry"] = uuid in (found or [])
    except (urllib.error.URLError, OSError, ValueError) as exc:
        report["search_error"] = str(exc)[:160]

    if args.verify_set:
        report["set"] = verify_set(entry, url)

    checks = {
        "digest_match": bool(report.get("digest_match")),
        "entry_present": bool(report.get("entry_present")),
        "body_digest_match": bool(report.get("body_digest_match")),
        "external_log": bool(report.get("external")),
        "searchable_by_digest": bool(report.get("search_finds_entry")),
    }
    if args.verify_set:
        checks["set_verified"] = (report.get("set") or {}).get("verified") is True
    report["checks"] = checks
    report["ok"] = all(checks.values())
    text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=1)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
