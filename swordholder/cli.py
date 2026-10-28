"""命令行入口：swordholder <command>

示例：
    swordholder keygen --out keys
    swordholder seal triage.json -k keys/swordholder_ed25519_private.pem --issuer soc@example
    swordholder verify triage.seal.json --keys trusted_keys.json
    swordholder triage alert.json --llm --seal -k keys/swordholder_ed25519_private.pem
    swordholder demo
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, core, rules


def _dump(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_keygen(args) -> int:
    res = core.keygen(args.out)
    _dump({"private_key_path": res.get("private_key_path"),
           "public_key_path": res.get("public_key_path"),
           "public_key_hex": res.get("public_key_hex"),
           "note": "私钥不要入库；把 public_key_hex 登记到 trusted_keys.json 才算建立信任锚"})
    return 0


def cmd_seal(args) -> int:
    out = args.out or (os.path.splitext(args.record)[0] + ".seal.json")
    res = core.seal(args.record, args.key, args.issuer, subject=args.subject, out_path=out)
    _dump({"seal_path": res["seal_path"], "payload_sha256": res["payload_sha256"],
           "seal_id": res.get("seal_id"), "subject": res.get("subject")})
    return 0


def cmd_verify(args) -> int:
    res = core.verify(args.seal, keys_path=args.keys)
    _dump(res)
    return 0 if res.get("verdict") in ("VALID", "VALID_UNTRUSTED_KEY") else 1


def cmd_triage(args) -> int:
    result = core.triage(args.alert, use_llm=args.llm)
    if args.seal:
        if not args.key:
            print("--seal 需要 -k 指定私钥", file=sys.stderr)
            return 2
        record_path = os.path.splitext(args.alert)[0] + ".triage.json"
        with open(record_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        sealed = core.seal(result, args.key, "swordholder-triage/" + __version__,
                           out_path=record_path.replace(".triage.json", ".seal.json"))
        result = dict(result, seal=sealed["seal_path"], payload_sha256=sealed["payload_sha256"])
    _dump(result)
    return 0


def cmd_demo(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    key_path = os.path.join(args.keys, "swordholder_ed25519_private.pem")
    if not os.path.exists(key_path):
        core.keygen(args.keys)
    samples = rules.sample_alerts()
    if not samples:
        print("未找到样例告警", file=sys.stderr)
        return 2

    rows, tamper = [], None
    for path in samples:
        result = core.triage(path, use_llm=args.llm)
        rec = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".triage.json")
        with open(rec, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        sealed = core.seal(result, key_path, "swordholder-triage/" + __version__,
                           out_path=rec.replace(".triage.json", ".seal.json"))
        verdict = core.verify(sealed["seal_path"], keys_path=args.keys_file)
        rows.append({"alert_id": result.get("alert_id"), "verdict": result.get("verdict"),
                     "severity": result.get("severity"), "confidence": result.get("confidence"),
                     "sealed": verdict.get("verdict"), "seal_path": sealed["seal_path"]})

    # 篡改演示
    first = rows[0]["seal_path"]
    with open(first, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["payload"]["verdict"] = "false_positive"
    data["payload"]["actions"] = []
    tampered = os.path.join(args.out, "tampered.seal.json")
    with open(tampered, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tamper = core.verify(tampered, keys_path=args.keys_file)

    _dump({"rows": rows,
           "tamper": {"verdict": tamper.get("verdict"), "reason": tamper.get("reason")},
           "out_dir": args.out})
    ok = all(r["sealed"] in ("VALID", "VALID_UNTRUSTED_KEY") for r in rows) \
        and tamper.get("reason") == "E_PAYLOAD_TAMPERED"
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swordholder", description="给结论盖章，让任何人能验签")
    p.add_argument("--version", action="version", version=f"swordholder {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="生成 ed25519 密钥对")
    k.add_argument("--out", default="keys")
    k.set_defaults(func=cmd_keygen)

    s = sub.add_parser("seal", help="给一份 JSON 结论盖章")
    s.add_argument("record")
    s.add_argument("-k", "--key", required=True, help="私钥 pem 路径")
    s.add_argument("--issuer", required=True)
    s.add_argument("--subject", default=None)
    s.add_argument("-o", "--out", default=None)
    s.set_defaults(func=cmd_seal)

    v = sub.add_parser("verify", help="独立验签")
    v.add_argument("seal")
    v.add_argument("--keys", default=None, help="信任锚 json；不给则只验签名，不建立信任")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("triage", help="分诊一条告警")
    t.add_argument("alert")
    t.add_argument("--llm", action="store_true", help="叠加本机 Ollama（可选）")
    t.add_argument("--seal", action="store_true", help="同时盖章")
    t.add_argument("-k", "--key", default=None)
    t.set_defaults(func=cmd_triage)

    d = sub.add_parser("demo", help="跑通内置样例：分诊→盖章→验签→篡改检出")
    d.add_argument("--out", default=".demo_out")
    d.add_argument("--keys", default="keys")
    d.add_argument("--keys-file", default=None, help="信任锚 json，默认用仓库根 trusted_keys.json（如存在）")
    d.add_argument("--llm", action="store_true")
    d.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
