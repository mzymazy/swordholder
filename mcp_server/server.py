"""Swordholder MCP Server — 让任意 Agent 在处置结论上盖可验签的章。

零框架依赖：直接实现 MCP stdio JSON-RPC 2.0（initialize / tools/list / tools/call / ping），
仅依赖 cryptography 与 pyyaml（与仓库核心依赖一致）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import traceback
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SERVER_NAME = "swordholder-mcp"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"
SEAL_DOMAIN = b"swordholder-seal-v1\n"
DEFAULT_KEYS = os.path.join(REPO_ROOT, "trusted_keys.json")


# ---------------------------------------------------------------- 工具函数

def c14n(obj) -> bytes:
    """json-c14n-v1：键排序、无多余空白、UTF-8、不转义非 ASCII。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_private_key(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(path, "rb") as f:
        raw = f.read()
    return load_pem_private_key(raw, password=None)


def public_hex_from_private(priv) -> str:
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _err(msg: str) -> dict:
    return {"ok": False, "error": msg}


# ---------------------------------------------------------------- 业务实现

def tool_keygen(args: dict) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    out_dir = args.get("out_dir") or os.path.join(REPO_ROOT, "keys")
    os.makedirs(out_dir, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path = os.path.join(out_dir, "swordholder_ed25519_private.pem")
    if os.path.exists(priv_path):
        return _err(f"私钥已存在，拒绝覆盖：{priv_path}")
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    pub_hex = public_hex_from_private(priv)
    return {
        "ok": True,
        "private_key_path": priv_path,
        "public_key_hex": pub_hex,
        "notice": "私钥仅在本机，切勿提交到版本库或随报告分发",
    }


def tool_seal_record(args: dict) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    payload = args.get("payload")
    record_path = args.get("record_path")
    if payload is None and record_path:
        with open(record_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    if payload is None:
        return _err("必须提供 payload（对象）或 record_path")

    key_path = args.get("private_key_path")
    if not key_path or not os.path.exists(key_path):
        return _err(f"私钥不存在：{key_path}")

    priv = load_private_key(key_path)
    if not isinstance(priv, Ed25519PrivateKey):
        return _err("私钥类型不是 ed25519")

    header = {
        "seal_version": "1.0",
        "seal_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": args.get("issuer") or "swordholder-mcp/0.1.0",
        "subject": args.get("subject") or "unspecified",
        "signature_alg": "ed25519",
        "canonicalization": "json-c14n-v1",
        "payload_sha256": sha256_hex(c14n(payload)),
        "public_key_hex": public_hex_from_private(priv),
        "record_ref": record_path or "inline",
    }
    signing_input = SEAL_DOMAIN + bytes.fromhex(header["payload_sha256"]) + b"\n" + c14n(header)
    sig = base64.b64encode(priv.sign(signing_input)).decode("ascii")

    seal = {"seal_header": header, "payload": payload,
            "signature": {"alg": "ed25519", "value": sig}}

    out_path = args.get("out_path")
    if not out_path:
        stem = os.path.splitext(os.path.basename(record_path))[0] if record_path else "record"
        out_path = os.path.join(REPO_ROOT, f"{stem}.seal.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(seal, f, ensure_ascii=False, indent=2)

    return {"ok": True, "seal_path": out_path, "seal_id": header["seal_id"],
            "payload_sha256": header["payload_sha256"], "public_key_hex": header["public_key_hex"]}


def tool_verify_seal(args: dict) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    seal_path = args.get("seal_path")
    if not seal_path or not os.path.exists(seal_path):
        return _err(f"seal 文件不存在：{seal_path}")
    with open(seal_path, "r", encoding="utf-8") as f:
        seal = json.load(f)

    header = seal.get("seal_header") or {}
    payload = seal.get("payload")
    sig_b64 = (seal.get("signature") or {}).get("value")
    if not header or payload is None or not sig_b64:
        return {"verdict": "INVALID", "reason": "E_MALFORMED_SEAL"}

    actual = sha256_hex(c14n(payload))
    if actual != header.get("payload_sha256"):
        return {"verdict": "INVALID", "reason": "E_PAYLOAD_TAMPERED",
                "expected": header.get("payload_sha256"), "actual": actual}

    signing_input = SEAL_DOMAIN + bytes.fromhex(header["payload_sha256"]) + b"\n" + c14n(header)
    pub_hex = header.get("public_key_hex", "")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            base64.b64decode(sig_b64), signing_input)
    except (InvalidSignature, ValueError):
        return {"verdict": "INVALID", "reason": "E_BAD_SIGNATURE"}

    keys_path = args.get("keys_path") or DEFAULT_KEYS
    trust = "unknown"
    if os.path.exists(keys_path):
        try:
            with open(keys_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            keys = raw if isinstance(raw, list) else raw.get("keys", [])
            hexes = {str(k.get("public_key", k.get("public_key_hex", ""))).lower() for k in keys}
            trust = "trusted" if pub_hex.lower() in hexes else "untrusted"
        except Exception:
            trust = "unknown"

    result = {"verdict": "VALID", "reason": "OK", "seal_id": header.get("seal_id"),
              "subject": header.get("subject"), "created_at": header.get("created_at"),
              "payload_sha256": header["payload_sha256"], "public_key_hex": pub_hex,
              "trust": trust}
    if trust == "untrusted":
        result["verdict"] = "VALID_UNTRUSTED_KEY"
        result["reason"] = "E_UNTRUSTED_KEY"
    return result


def tool_verify_proof(args: dict) -> dict:
    proof_path = args.get("proof_path")
    if not proof_path or not os.path.exists(proof_path):
        return _err(f"凭证不存在：{proof_path}")
    import verify_proof as vp

    keys_path = args.get("keys_path") or DEFAULT_KEYS
    max_age = int(args.get("max_age_days") or 365)
    verdict = vp.verify(proof_path, allow_demo=bool(args.get("allow_demo", False)),
                        trusted_keys_path=keys_path, max_age_days=max_age)
    text = verdict if isinstance(verdict, str) else json.dumps(verdict, ensure_ascii=False)
    return {"verdict": text.split()[0] if text else "INVALID",
            "reason": text, "proof_path": proof_path}


def tool_list_trusted_keys(args: dict) -> dict:
    keys_path = args.get("keys_path") or DEFAULT_KEYS
    if not os.path.exists(keys_path):
        return _err(f"信任锚文件不存在：{keys_path}")
    with open(keys_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    keys = raw if isinstance(raw, list) else raw.get("keys", [])
    out = []
    for k in keys:
        pub = str(k.get("public_key", k.get("public_key_hex", "")))
        out.append({"key_id": k.get("key_id") or k.get("id"),
                    "public_key_hex": pub,
                    "fingerprint_sha256_16": sha256_hex(pub.encode())[:16]})
    return {"ok": True, "keys_path": keys_path, "count": len(out), "keys": out}


# ---------------------------------------------------------------- MCP 协议层

TOOLS = [
    {
        "name": "verify_proof",
        "description": "验证一份 Swordholder 安全凭证（deterrence proof）是否完整、未篡改、在有效期内且由信任锚签发。返回 VALID / INVALID 及原因码。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proof_path": {"type": "string", "description": "凭证 yaml 的绝对或相对路径"},
                "keys_path": {"type": "string", "description": "信任锚 json 路径，默认仓库根 trusted_keys.json"},
                "max_age_days": {"type": "integer", "description": "允许的最大有效期天数，默认 365"},
                "allow_demo": {"type": "boolean", "description": "是否允许 demo 签发状态，默认 false"},
            },
            "required": ["proof_path"],
        },
    },
    {
        "name": "seal_record",
        "description": "对任意处置记录/告警分诊结论（JSON）签名封装为 .seal.json：摘要绑定 + ed25519 签名，任何人事后可独立验签。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {"type": "object", "description": "内联的 JSON 记录"},
                "record_path": {"type": "string", "description": "或提供 JSON 文件路径"},
                "private_key_path": {"type": "string", "description": "ed25519 PKCS8 PEM 私钥路径"},
                "issuer": {"type": "string", "description": "签发方标识"},
                "subject": {"type": "string", "description": "被签对象，如告警 ID / 资产名"},
                "out_path": {"type": "string", "description": "输出路径，默认 <record>.seal.json"},
            },
            "required": ["private_key_path"],
        },
    },
    {
        "name": "verify_seal",
        "description": "验证 .seal.json：重算 payload 摘要、校验 ed25519 签名、并比对信任锚列表。返回 VALID / VALID_UNTRUSTED_KEY / INVALID 与原因码。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seal_path": {"type": "string", "description": ".seal.json 路径"},
                "keys_path": {"type": "string", "description": "信任锚 json 路径"},
            },
            "required": ["seal_path"],
        },
    },
    {
        "name": "list_trusted_keys",
        "description": "列出当前信任锚及其公钥指纹，用于人工核对签发方身份。",
        "inputSchema": {"type": "object",
                        "properties": {"keys_path": {"type": "string"}}},
    },
    {
        "name": "keygen",
        "description": "在本地生成 ed25519 密钥对（私钥不覆盖已有文件、仅本机保存），返回公钥十六进制供登记为信任锚。",
        "inputSchema": {"type": "object",
                        "properties": {"out_dir": {"type": "string"}}},
    },
]

HANDLERS = {
    "verify_proof": tool_verify_proof,
    "seal_record": tool_seal_record,
    "verify_seal": tool_verify_seal,
    "list_trusted_keys": tool_list_trusted_keys,
    "keygen": tool_keygen,
}


def handle(req: dict) -> dict | None:
    method = req.get("method")
    rid = req.get("id")
    if rid is None:
        return None  # 通知类消息不需要响应
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL_VERSION,
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if not handler:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": f"未知工具：{name}"}}
        try:
            out = handler(args)
            is_error = isinstance(out, dict) and out.get("ok") is False
            result = {"content": [{"type": "text",
                                   "text": json.dumps(out, ensure_ascii=False, indent=2)}],
                      "isError": bool(is_error)}
        except Exception:
            result = {"content": [{"type": "text",
                                   "text": "工具执行异常：" + traceback.format_exc(limit=3)}],
                      "isError": True}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"未实现的方法：{method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "解析失败"}}
        else:
            resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
