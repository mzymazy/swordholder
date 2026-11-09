# -*- coding: utf-8 -*-
"""外部时间戳（RFC 3161 TSA）——把「证据在某个时刻已经存在」这件事挪出被记录方的手心。

要解决的问题
------------
链式哈希 + 签名只能证明「记录内部没被改过」，以及「谁用某把私钥签的」。它证明不了
**时间**：持有私钥的人今天补签一份，验签方无从分辨。取证场景里这句话很致命——
被记录方可以把证据连签名一起重做一遍，然后声称「本来就是这样的」。

RFC 3161 时间戳把 digest 交给一个**独立第三方**（TSA），由 TSA 用它的私钥签一份
``TSTInfo``（含 digest、序列号、发放时刻）。此后任何人都能用 TSA 的公钥验证：
「这个 digest 在 genTime 之前就已存在」。要伪造就得攻破 TSA 的私钥。

本模块做了什么
--------------
只做三件必要的事，不引入任何第三方依赖（DER 编解码自己写，约 200 行）：

1. :func:`build_request` 生成 ``TimeStampReq``（version / messageImprint / nonce / certReq）；
2. :func:`parse_response` 解析 ``TimeStampResp``：状态码、失败原因、token；
3. :func:`verify_token` 校验 token：**messageImprint 与本地 digest 一致**、nonce 回环、
   ``SignedData`` 上的 CMS 签名（signedAttrs 的 DER 重算）、``messageDigest`` 属性、
   ``signingCertificateV2`` 里 ESSCertIDv2 与签名证书的绑定、证书有效期；
   给了 ``trusted_roots`` 时再做一层签发关系校验（证书链）。

边界（必须与能力一起声明）
--------------------------
- 时间戳**只承诺「何时存在」**，不承诺「证据还在」：token 本身仍是文件，谁删谁没。
  要抵抗「连证据一起处理掉」，还需要 WORM 存储或第三方代管——本模块不做这两件事。
- 未内置根证书集，因此默认**不做** CA 信任链校验（:func:`verify_token` 会如实返回
  ``trust_enforced: false``）。调用方可用 ``trusted_roots`` 传入自己信任的根证书
  （PEM/DER 字节列表），此时签发关系与签名都会被校验。
- 需要网络。取不到 token 就返回失败，**不产生**「假时间戳」或本地自签 fallback。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

SCHEMA = "swordholder.timestamp/1"

DEFAULT_TIMEOUT = 15.0
"""单次 TSA 请求超时（秒）。超时即失败，不重试到天荒地老。"""

KNOWN_TSAS = (
    ("freetsa", "https://freetsa.org/tsr"),
    ("digicert", "http://timestamp.digicert.com"),
    ("sectigo", "http://timestamp.sectigo.com"),
)
"""公开可用的 RFC 3161 端点（按实测可用性排序）。仅作默认候选，不保证长期可用。"""

HASH_OIDS = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
OID_HASHES = {v: k for k, v in HASH_OIDS.items()}

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ATTR_SIGNING_CERT_V1 = "1.2.840.113549.1.9.16.2.12"
OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"

# 签名算法 OID → (算法族, 摘要)；摘要为 None 表示沿用 SignerInfo.digestAlgorithm
SIG_ALGS = {
    "1.2.840.113549.1.1.1": ("rsa", None),
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.4.1": ("ecdsa", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
}


class TimestampError(Exception):
    """时间戳请求/解析/校验过程中的确定性失败。"""


# ---------------------------------------------------------------- DER 编码
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    while len(body) > 1 and body[0] == 0x00 and not body[1] & 0x80:
        body = body[1:]
    return _tlv(0x02, body)


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise TimestampError("E_TSA_OID_INVALID: %r" % dotted)
    body = bytearray([parts[0] * 40 + parts[1]])
    for num in parts[2:]:
        chunk = bytearray([num & 0x7F])
        num >>= 7
        while num:
            chunk.insert(0, 0x80 | (num & 0x7F))
            num >>= 7
        body.extend(chunk)
    return _tlv(0x06, bytes(body))


def _der_seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _der_octets(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_bool(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def _der_explicit(num: int, content: bytes) -> bytes:
    return _tlv(0xA0 | num, content)


# ---------------------------------------------------------------- DER 解析
class _Node:
    """一个 DER TLV 节点：保留原始字节，便于重算被签名的那段 DER。"""

    __slots__ = ("tag", "content", "raw")

    def __init__(self, tag: int, content: bytes, raw: bytes):
        self.tag = tag
        self.content = content
        self.raw = raw

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_class(self) -> int:
        return (self.tag & 0xC0) >> 6

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F

    def children(self) -> list["_Node"]:
        if not self.constructed:
            raise TimestampError("E_TSA_DER_NOT_CONSTRUCTED: tag=0x%02x 不是构造类型" % self.tag)
        return parse_all(self.content)

    def as_int(self) -> int:
        if self.tag != 0x02:
            raise TimestampError("E_TSA_DER_NOT_INT: tag=0x%02x" % self.tag)
        return int.from_bytes(self.content, "big", signed=True)

    def as_oid(self) -> str:
        if self.tag != 0x06 or not self.content:
            raise TimestampError("E_TSA_DER_NOT_OID: tag=0x%02x" % self.tag)
        first = self.content[0]
        parts = [first // 40, first % 40]
        num = 0
        for byte in self.content[1:]:
            num = (num << 7) | (byte & 0x7F)
            if not byte & 0x80:
                parts.append(num)
                num = 0
        return ".".join(str(p) for p in parts)

    def as_text(self) -> str:
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            return self.content.decode("latin-1")


def parse_one(data: bytes, pos: int = 0) -> tuple[_Node, int]:
    """解析 ``data[pos:]`` 开头的一个 TLV，返回 (节点, 下一个位置)。"""
    if pos >= len(data):
        raise TimestampError("E_TSA_DER_TRUNCATED: 偏移 %d 处无内容" % pos)
    tag = data[pos]
    idx = pos + 1
    if idx >= len(data):
        raise TimestampError("E_TSA_DER_TRUNCATED: 长度字段被截断")
    first = data[idx]
    idx += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or idx + count > len(data):
            raise TimestampError("E_TSA_DER_BAD_LENGTH: 长度字段非法")
        length = int.from_bytes(data[idx:idx + count], "big")
        idx += count
    end = idx + length
    if end > len(data):
        raise TimestampError("E_TSA_DER_TRUNCATED: 声明长度 %d 超出数据" % length)
    return _Node(tag, data[idx:end], data[pos:end]), end


def parse_all(data: bytes) -> list[_Node]:
    out, pos = [], 0
    while pos < len(data):
        node, pos = parse_one(data, pos)
        out.append(node)
    return out


# ---------------------------------------------------------------- 请求构造
def digest_of(data: bytes, hash_name: str = "sha256") -> bytes:
    try:
        return hashlib.new(hash_name, data).digest()
    except ValueError as exc:  # pragma: no cover - 参数错误
        raise TimestampError("E_TSA_HASH_UNSUPPORTED: %s (%s)" % (hash_name, exc))


def build_request(digest: bytes, hash_name: str = "sha256", nonce: int | None = None,
                  cert_req: bool = True) -> bytes:
    """构造 ``TimeStampReq``（DER）。``cert_req=True`` 要求 TSA 把签名证书放进 token。"""
    if hash_name not in HASH_OIDS:
        raise TimestampError("E_TSA_HASH_UNSUPPORTED: %s" % hash_name)
    if not isinstance(digest, (bytes, bytearray)) or not digest:
        raise TimestampError("E_TSA_DIGEST_EMPTY: digest 必须是非空 bytes")
    imprint = _der_seq(_der_seq(_der_oid(HASH_OIDS[hash_name]), _der_null()),
                       _der_octets(bytes(digest)))
    body = [_der_int(1), imprint]
    if nonce is None:
        nonce = secrets.randbits(64) or 1
    body.append(_der_int(int(nonce)))
    if cert_req:
        body.append(_der_bool(True))
    return _der_seq(*body)


# ---------------------------------------------------------------- 响应解析
def parse_response(der: bytes) -> dict:
    """解析 ``TimeStampResp``：返回 ``{status, status_string, fail_info, token_der}``。

    ``status``：0 granted / 1 grantedWithMods / 2 rejection / 3 waiting / 4 revocationWarning /
    5 revocationNotification。非 0/1 一律视为失败（调用方不得把 rejection 当成功）。
    """
    root, _ = parse_one(der)
    if root.tag != 0x30:
        raise TimestampError("E_TSA_RESP_NOT_SEQUENCE")
    parts = root.children()
    if not parts or parts[0].tag != 0x30:
        raise TimestampError("E_TSA_RESP_NO_STATUS")
    status_parts = parts[0].children()
    if not status_parts:
        raise TimestampError("E_TSA_RESP_EMPTY_STATUS")
    status = status_parts[0].as_int()
    status_string: list[str] = []
    fail_info = None
    for node in status_parts[1:]:
        if node.tag == 0x30:
            status_string = [n.as_text() for n in node.children()]
        elif node.tag == 0x03:
            fail_info = int.from_bytes(node.content, "big") if node.content else None
    token = parts[1].raw if len(parts) > 1 else None
    return {"status": status, "status_string": status_string, "fail_info": fail_info,
            "token_der": token}


def _generalized_time(node: _Node) -> str:
    if node.tag != 0x18:
        raise TimestampError("E_TSA_GENTIME_INVALID: tag=0x%02x" % node.tag)
    return node.as_text()


def _parse_tst_info(der: bytes) -> dict:
    root, _ = parse_one(der)
    if root.tag != 0x30:
        raise TimestampError("E_TSA_TSTINFO_NOT_SEQUENCE")
    nodes = root.children()
    if len(nodes) < 5:
        raise TimestampError("E_TSA_TSTINFO_TRUNCATED")
    version = nodes[0].as_int()
    policy = nodes[1].as_oid()
    imprint_parts = nodes[2].children()
    alg = imprint_parts[0].children()[0].as_oid()
    hashed = imprint_parts[1].content
    serial = nodes[3].as_int()
    gen_time = _generalized_time(nodes[4])
    nonce = None
    tsa_present = False
    for node in nodes[5:]:
        if node.tag == 0x02:
            nonce = node.as_int()
        elif node.tag_class == 2 and node.tag_number == 0:
            tsa_present = True
    return {"version": version, "policy": policy, "hash_alg": OID_HASHES.get(alg, alg),
            "hash_oid": alg, "hashed_message": hashed.hex(), "serial": serial,
            "gen_time": gen_time, "nonce": nonce, "tsa_name_present": tsa_present}


def _hash_by_oid(oid: str, data: bytes) -> bytes:
    name = OID_HASHES.get(oid)
    if not name:
        raise TimestampError("E_TSA_HASH_UNSUPPORTED: %s" % oid)
    return hashlib.new(name, data).digest()


def _attr_values(attrs: list[_Node]) -> dict:
    """把 signedAttrs 的 [0] 节点拆成 ``{oid: [value_node, ...]}``。"""
    out: dict[str, list[_Node]] = {}
    for attr in attrs:
        parts = attr.children()
        if len(parts) < 2:
            continue
        oid = parts[0].as_oid()
        out.setdefault(oid, []).extend(parts[1].children())
    return out


def _parse_signed_data(token: bytes) -> dict:
    content_info, _ = parse_one(token)
    ci = content_info.children()
    if len(ci) < 2 or ci[0].as_oid() != OID_SIGNED_DATA:
        raise TimestampError("E_TSA_NOT_SIGNED_DATA")
    if not (ci[1].tag_class == 2 and ci[1].tag_number == 0):
        raise TimestampError("E_TSA_SIGNED_DATA_WRAPPER_MISSING")
    signed = ci[1].children()[0].children()
    econtent_info = None
    certs: list[bytes] = []
    signer_infos = None
    for node in signed[2:]:
        if node.tag == 0x30:
            econtent_info = node
        elif node.tag_class == 2 and node.tag_number == 0:
            certs = [n.raw for n in node.children()]
        elif node.tag == 0x31:
            signer_infos = node
    if econtent_info is None:
        raise TimestampError("E_TSA_ECONTENT_MISSING")
    if signer_infos is None or not signer_infos.children():
        raise TimestampError("E_TSA_SIGNERINFO_MISSING")
    enc = econtent_info.children()
    etype = enc[0].as_oid()
    if len(enc) < 2 or not (enc[1].tag_class == 2 and enc[1].tag_number == 0):
        raise TimestampError("E_TSA_ECONTENT_MISSING")
    inner = enc[1].children()[0]
    econtent = inner.content if inner.tag == 0x04 else inner.raw
    return {"econtent_type": etype, "econtent": econtent, "certs": certs,
            "signer_info": signer_infos.children()[0]}


def _parse_signer_info(node: _Node) -> dict:
    parts = node.children()
    if len(parts) < 5:
        raise TimestampError("E_TSA_SIGNERINFO_TRUNCATED")
    sid = parts[1]
    digest_alg = parts[2].children()[0].as_oid()
    idx = 3
    signed_attrs = None
    if parts[idx].tag_class == 2 and parts[idx].tag_number == 0:
        signed_attrs = parts[idx]
        idx += 1
    sig_alg = parts[idx].children()[0].as_oid()
    signature = parts[idx + 1].content
    issuer, serial = None, None
    if sid.tag == 0x30:
        sid_parts = sid.children()
        issuer = sid_parts[0].raw
        serial = sid_parts[1].as_int()
    return {"issuer_der": issuer, "serial": serial, "digest_alg": digest_alg,
            "signed_attrs": signed_attrs, "sig_alg": sig_alg, "signature": signature}


def _pick_cert(certs: Sequence[bytes], issuer_der: bytes | None, serial: int | None) -> bytes | None:
    from cryptography import x509  # noqa: PLC0415

    for der in certs:
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001
            continue
        if issuer_der is None or serial is None:
            return der
        if cert.serial_number == serial and cert.issuer.public_bytes() == issuer_der:
            return der
    return None


def _verify_signature(cert_der: bytes, sig_alg: str, signed_bytes: bytes, signature: bytes,
                      digest_alg: str | None = None) -> dict:
    from cryptography import x509  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: PLC0415

    family, hash_name = SIG_ALGS.get(sig_alg, (None, None))
    if family is None:
        return {"ok": False, "reason": "E_TSA_SIG_ALG_UNSUPPORTED: %s" % sig_alg}
    if hash_name is None:
        # rsaEncryption 等「不带摘要」的算法标识：摘要取自 SignerInfo.digestAlgorithm
        hash_name = OID_HASHES.get(digest_alg or "")
        if not hash_name:
            return {"ok": False, "reason": "E_TSA_SIG_DIGEST_UNKNOWN: %s" % digest_alg}
    hash_alg = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
                "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hash_name]
    cert = x509.load_der_x509_certificate(cert_der)
    key = cert.public_key()
    try:
        if family == "rsa":
            if not isinstance(key, rsa.RSAPublicKey):
                return {"ok": False, "reason": "E_TSA_KEY_TYPE_MISMATCH: 期望 RSA"}
            key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_alg)
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return {"ok": False, "reason": "E_TSA_KEY_TYPE_MISMATCH: 期望 EC"}
            key.verify(signature, signed_bytes, ec.ECDSA(hash_alg))
    except InvalidSignature:
        return {"ok": False, "reason": "E_TSA_BAD_SIGNATURE: CMS 签名校验失败"}
    return {"ok": True, "reason": "", "alg": "%s-%s" % (family, hash_name)}


def _ess_cert_hash(values: list[_Node], default_hash: str) -> dict | None:
    """从 signingCertificate(V2) 属性里取 ESSCertID(v2) 的证书哈希。

    ``ESSCertID``（v1）是 ``SEQUENCE { certHash OCTET STRING, issuerSerial OPTIONAL }``，
    哈希固定 SHA-1；``ESSCertIDv2`` 多了可缺省的 ``hashAlgorithm``（缺省即 SHA-256）。
    两条结构不同，不能按「第一个子节点就是 AlgorithmIdentifier」硬套——v1 的第一个
    子节点就是哈希本身。层级上：属性值 = SigningCertificate{V2} SEQUENCE，
    其首个成员是 ``certs SEQUENCE OF ESSCertID``，真正的哈希在再下一层。
    """
    for value in values:
        if not value.constructed:
            continue
        candidates: list[_Node] = []
        for child in value.children():
            if child.tag != 0x30:
                continue
            subs = child.children()
            nested = [s for s in subs if s.tag == 0x30]
            candidates.extend(nested if nested else [child])
        for item in candidates:
            inner = item.children()
            if not inner:
                continue
            hash_name, hash_bytes = default_hash, None
            first = inner[0]
            if first.tag == 0x30:
                alg = first.children()
                if alg and alg[0].tag == 0x06 and len(inner) > 1:
                    hash_name = OID_HASHES.get(alg[0].as_oid(), "")
                    hash_bytes = inner[1].content if inner[1].tag == 0x04 else None
            elif first.tag == 0x04:
                hash_bytes = first.content
            if hash_bytes and hash_name:
                return {"hash_name": hash_name, "hex": hash_bytes.hex()}
    return None


def _cert_window(cert_der: bytes) -> dict:
    from cryptography import x509  # noqa: PLC0415

    cert = x509.load_der_x509_certificate(cert_der)
    now = datetime.now(timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - 老版本 cryptography
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {"subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": cert.serial_number,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "valid_now": not_before <= now <= not_after}


def _load_roots(trusted_roots: Iterable[bytes] | None) -> list:
    from cryptography import x509  # noqa: PLC0415

    out = []
    for item in trusted_roots or []:
        if isinstance(item, str):
            if os.path.isfile(item):
                with open(item, "rb") as fh:
                    item = fh.read()
            else:
                item = item.encode("utf-8")
        if b"-----BEGIN CERTIFICATE-----" in item:
            out.append(x509.load_pem_x509_certificate(item))
        else:
            out.append(x509.load_der_x509_certificate(item))
    return out


def _verify_chain(cert_der: bytes, roots: list) -> dict:
    """签发关系校验：签名证书的 issuer 与根证书 subject 一致，且根证书签得动它。"""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: PLC0415

    cert = x509.load_der_x509_certificate(cert_der)
    for root in roots:
        if root.subject != cert.issuer:
            continue
        key = root.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                key.verify(cert.signature, cert.tbs_certificate_bytes,
                           padding.PKCS1v15(), cert.signature_hash_algorithm)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(cert.signature, cert.tbs_certificate_bytes,
                           ec.ECDSA(cert.signature_hash_algorithm))
            else:  # pragma: no cover - 罕见算法
                continue
        except InvalidSignature:
            continue
        return {"ok": True, "root_subject": root.subject.rfc4514_string()}
    return {"ok": False, "reason": "E_TSA_CHAIN_UNTRUSTED: 签名证书并非由给定根证书签发"}


def verify_token(token_der: bytes, expected_digest: bytes, hash_name: str = "sha256",
                 expected_nonce: int | None = None,
                 trusted_roots: Iterable[bytes] | None = None) -> dict:
    """校验时间戳 token，返回结构化结论（``ok`` 为唯一判定字段）。

    校验项（全部通过才 ``ok=True``）：
    messageImprint 与本地 digest 一致 / nonce 回环 / CMS 签名（signedAttrs 重算）/
    ``messageDigest`` 属性与 eContent 摘要一致 / ``signingCertificateV2`` 的 ESSCertIDv2
    与签名证书哈希一致 / 证书在有效期内 / 若给了根证书则签发关系成立。
    """
    result: dict[str, Any] = {"ok": False, "schema": SCHEMA, "checks": {},
                             "trust_enforced": bool(trusted_roots)}
    try:
        signed = _parse_signed_data(token_der)
        tst = _parse_tst_info(signed["econtent"])
        info = _parse_signer_info(signed["signer_info"])
    except (TimestampError, ValueError) as exc:
        result["reason"] = "E_TSA_TOKEN_UNPARSABLE: %s" % exc
        return result

    result["tst"] = {k: v for k, v in tst.items() if k != "hashed_message"}
    result["tst"]["hashed_message_hex"] = tst["hashed_message"]
    result["econtent_type_is_tstinfo"] = signed["econtent_type"] == OID_TST_INFO

    checks = result["checks"]
    want = expected_digest.hex()
    checks["imprint_match"] = (tst["hash_alg"] == hash_name and tst["hashed_message"] == want)
    checks["nonce_match"] = (expected_nonce is None or tst["nonce"] == expected_nonce)
    checks["econtent_type"] = signed["econtent_type"] == OID_TST_INFO

    cert_der = _pick_cert(signed["certs"], info["issuer_der"], info["serial"])
    if cert_der is None:
        result["reason"] = "E_TSA_SIGNER_CERT_ABSENT: token 里没有签名证书（TSA 未回传 certReq）"
        return result
    window = _cert_window(cert_der)
    result["signer_cert"] = window
    checks["cert_valid_now"] = window["valid_now"]

    attrs = info["signed_attrs"]
    if attrs is None:
        # 无 signedAttrs 时签名直接覆盖 eContent，属合法但少见的分支
        signed_bytes = signed["econtent"]
        attr_map: dict[str, list[_Node]] = {}
    else:
        signed_bytes = b"\x31" + attrs.raw[1:]
        attr_map = _attr_values(attrs.children())

    sig = _verify_signature(cert_der, info["sig_alg"], signed_bytes, info["signature"],
                            digest_alg=info["digest_alg"])
    checks["cms_signature"] = sig["ok"]
    result["signature"] = sig
    result["digest_alg"] = OID_HASHES.get(info["digest_alg"], info["digest_alg"])

    md_values = attr_map.get(OID_ATTR_MESSAGE_DIGEST) or []
    if md_values:
        digest_actual = _hash_by_oid(info["digest_alg"], signed["econtent"])
        checks["message_digest"] = md_values[0].content == digest_actual
        result["message_digest_hex"] = digest_actual.hex()
    else:
        checks["message_digest"] = attrs is None
        result["message_digest_hex"] = None

    v2_vals = attr_map.get(OID_ATTR_SIGNING_CERT_V2) or []
    v1_vals = attr_map.get(OID_ATTR_SIGNING_CERT_V1) or []
    ess = _ess_cert_hash(v2_vals, "sha256") if v2_vals else _ess_cert_hash(v1_vals, "sha1")
    result["ess_cert_id"] = ess
    if ess:
        checks["ess_cert_binding"] = hashlib.new(
            ess["hash_name"], cert_der).hexdigest() == ess["hex"]
    else:
        checks["ess_cert_binding"] = False

    if trusted_roots:
        chain = _verify_chain(cert_der, _load_roots(trusted_roots))
        result["chain"] = chain
        checks["chain_trusted"] = chain["ok"]
    else:
        result["chain"] = {"ok": None, "reason": "no_roots_supplied"}
        checks["chain_trusted"] = True  # 未要求即不阻断，但 trust_enforced=false 已如实标注

    failed = [k for k, v in checks.items() if not v]
    result["ok"] = not failed
    result["reason"] = "" if result["ok"] else "E_TSA_CHECK_FAILED: %s" % ", ".join(failed)
    return result


# ---------------------------------------------------------------- 客户端
def stamp_digest(digest: bytes, url: str, hash_name: str = "sha256",
                 timeout: float = DEFAULT_TIMEOUT, trusted_roots: Iterable[bytes] | None = None,
                 nonce: int | None = None) -> dict:
    """向 ``url`` 索取 RFC 3161 时间戳并当场校验。失败抛 :class:`TimestampError`。

    返回值里 ``token_b64`` 是**可独立保存**的证据：任何持有者日后都能拿它 +
    ``verify_token`` 复核「这份 digest 在 gen_time 之前已存在」。
    """
    if nonce is None:
        nonce = secrets.randbits(63) or 1
    request = build_request(digest, hash_name=hash_name, nonce=nonce, cert_req=True)
    req = urllib.request.Request(
        url, data=request,
        headers={"Content-Type": "application/timestamp-query",
                 "Accept": "application/timestamp-reply",
                 "User-Agent": "swordholder-timestamp/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status_code = getattr(resp, "status", None)
    except urllib.error.HTTPError as exc:  # 4xx/5xx 也带响应体，尽量解析
        raw = exc.read() if hasattr(exc, "read") else b""
        if not raw:
            raise TimestampError("E_TSA_HTTP_%s: %s" % (exc.code, exc.reason)) from exc
        status_code = exc.code
    except (urllib.error.URLError, OSError) as exc:
        raise TimestampError("E_TSA_UNREACHABLE: %s" % exc) from exc

    parsed = parse_response(raw)
    if parsed["status"] not in (0, 1):
        raise TimestampError("E_TSA_REJECTED: status=%s fail_info=%s msg=%s"
                             % (parsed["status"], parsed["fail_info"],
                                "/".join(parsed["status_string"])))
    if not parsed["token_der"]:
        raise TimestampError("E_TSA_NO_TOKEN: 状态为授予但未返回 token")
    verified = verify_token(parsed["token_der"], digest, hash_name=hash_name,
                            expected_nonce=nonce, trusted_roots=trusted_roots)
    out = {
        "schema": SCHEMA,
        "url": url,
        "http_status": status_code,
        "response_status": parsed["status"],
        "digest_alg": hash_name,
        "digest_hex": digest.hex(),
        "nonce": nonce,
        "token_b64": base64.b64encode(parsed["token_der"]).decode("ascii"),
        "token_sha256": hashlib.sha256(parsed["token_der"]).hexdigest(),
        "verified": verified,
        "ok": bool(verified.get("ok")),
    }
    if not out["ok"]:
        raise TimestampError(verified.get("reason") or "E_TSA_VERIFY_FAILED")
    return out


def stamp_bytes(data: bytes, url: str, hash_name: str = "sha256",
                timeout: float = DEFAULT_TIMEOUT,
                trusted_roots: Iterable[bytes] | None = None) -> dict:
    """对任意字节串取时间戳。"""
    return stamp_digest(digest_of(data, hash_name), url, hash_name=hash_name,
                        timeout=timeout, trusted_roots=trusted_roots)


def probe_authorities(urls: Sequence[tuple[str, str]] | None = None,
                      timeout: float = 6.0) -> list[dict]:
    """逐个试公开 TSA，返回可达性与是否成功取到 token（用于如实登记「有没有网」）。"""
    out = []
    payload = b"swordholder-tsa-probe"
    for name, url in (urls or KNOWN_TSAS):
        try:
            got = stamp_bytes(payload, url, timeout=timeout)
            out.append({"name": name, "url": url, "ok": True,
                        "gen_time": got["verified"]["tst"]["gen_time"],
                        "signer": got["verified"]["signer_cert"]["subject"]})
        except (TimestampError, OSError) as exc:
            out.append({"name": name, "url": url, "ok": False, "error": str(exc)[:300]})
    return out


def save_evidence(stamp: dict, path: str) -> str:
    """把一次成功的时间戳（含 token 原文）原子写入证据文件。"""
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(stamp, fh, ensure_ascii=False, sort_keys=True, indent=1)
    os.replace(tmp, target)
    return target


def verify_evidence(path: str, data: bytes | None = None,
                    trusted_roots: Iterable[bytes] | None = None) -> dict:
    """离线复核一份时间戳证据文件（无需网络；``data`` 给了就重算 digest 比对）。"""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    digest = digest_of(data, doc.get("digest_alg", "sha256")) if data is not None \
        else bytes.fromhex(doc["digest_hex"])
    token = base64.b64decode(doc["token_b64"])
    out = verify_token(token, digest, hash_name=doc.get("digest_alg", "sha256"),
                       expected_nonce=doc.get("nonce"), trusted_roots=trusted_roots)
    out["evidence"] = os.path.abspath(path)
    out["token_sha256"] = hashlib.sha256(token).hexdigest()
    return out
