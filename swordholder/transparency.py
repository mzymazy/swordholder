# -*- coding: utf-8 -*-
"""外部透明日志锚定：把「这份证据在某时刻已存在」这条断言搬到公共只追加日志里。

要解决的缺口（S12.1 的 G4a）
--------------------------
S12 已经能向 RFC 3161 TSA 取到时间戳，所以「某摘要在某时刻已存在」有了外部证明。
但那枚戳躺在**持证方自己的磁盘**上：持钥者改写第 7 步、重算整链、重签、再重新去
TSA 打一枚新戳后，``verify_sealed_trace`` 依旧判 VALID，并且**没有任何第三方留存首枚
戳值**，所以「整册重做」在事后不可发现。

本模块把「首枚锚点摘要」提交到**公共只追加透明日志**（当前实现：Sigstore Rekor 公共
实例），换回一张可被任何人独立复核的回执：

1. 日志条目**不可删除、不可回填**：holder 删掉自己磁盘上的一切，日志里那条仍在；
2. 回执可**离线校验**：``entry_uuid`` → ``GET /api/v1/log/entries/<uuid>``，条目体里就是
   ``hashedrekord`` 的 ``data.hash.value``，与本地重算的锚点摘要逐字节比对即可；
3. 回执带 Rekor 的 ``signedEntryTimestamp``（SET），可用 Rekor 公钥验签——所以回执不是
   我们自己写的，是被日志签名背书的；
4. 由此得到一条**真实但有限**的能力：任何曾经留存过首枚回执的第三方，可以在事后证明
   「这份证据被整册重做过」。**首次核验者仍然无法发现重做**（他会看到的是一份全新的、
   自洽的凭证 + 一枚全新的合法回执）——这条边界写进 P11 证据，不粉饰。

为什么还要留「可插拔桩」
------------------------
内网 / 离线环境连不上公共日志，或者审计方要求走自家日志。``FileBackend``（本机只追加
文件，``external=False``）与 ``NullBackend``（禁用）就是桩：它们**照样产出回执**，但回执
里 ``external=False``，``verify_receipt`` 会把 ``externally_checkable`` 判为 False。
桩不会被伪装成成功——这是 S12.1 里 ``untracked_excluded`` 那类「自述」教训的直接延续。

边界
----
- 只锚定**摘要**，不锚定证据正文（正文仍留在持证方磁盘）；
- 不回传任何密钥材料到日志：只提交公钥与签名（Rekor ``hashedrekord`` 需要它们来验签）；
- 不做 Merkle 包含性证明的本地复算（``inclusionProof`` 原样保留在回执里，供需要时深查，
  但本模块的判据只依赖「按 uuid 取回 + 摘要一致 + SET 验签」这三件事）。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

SCHEMA = "swordholder.anchor_receipt/1"
REKOR_DEFAULT_URL = "https://rekor.sigstore.dev"
USER_AGENT = "swordholder-transparency/1"


class TransparencyError(ValueError):
    """锚定失败（网络 / 协议 / 验签）。"""


# ------------------------------------------------------------------ 锚点文档
def canonical_json(obj: Any) -> bytes:
    """稳定的 JSON 序列化：键排序、无多余空白。锚点摘要必须在两侧算出一个值。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def anchor_document(*, trace_id: str, seal_sha256: str, tsa_token_sha256: str | None,
                    tsa_gen_time: str | None, tsa_url: str | None = None,
                    extra: dict | None = None) -> dict:
    """构造「被锚定的那条断言」。

    刻意只放**能唯一确定这份凭证**的字段，不放正文：日志是公开的，正文可能是敏感内容。
    ``trace_id`` 让回执与具体 trace 绑定（防挪用别人的回执）；两个摘要把凭证内容与
    时间戳 token 一起钉死（改一个字节摘要就变）。
    """
    doc = {
        "schema": "swordholder.anchor_statement/1",
        "trace_id": trace_id,
        "seal_sha256": seal_sha256,
        "tsa_token_sha256": tsa_token_sha256,
        "tsa_gen_time": tsa_gen_time,
        "tsa_url": tsa_url,
        "purpose": "existence-at-time of a sealed forensic credential",
    }
    if extra:
        doc["extra"] = dict(extra)
    return doc


def anchor_bytes(doc: dict) -> bytes:
    return canonical_json(doc)


def anchor_digest(doc: dict) -> str:
    return hashlib.sha256(anchor_bytes(doc)).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for buf in iter(lambda: fh.read(1 << 20), b""):
            h.update(buf)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ 签名器
class AnchorSigner:
    """锚点签名器：RSA-2048 + PKCS#1 v1.5 + SHA-256。

    为什么是 RSA 而不是项目里到处用的 ed25519：Rekor 的 ``hashedrekord`` 对 ed25519 只接受
    SHA-512 预哈希（实测返回 ``unsupported hash algorithm: "SHA-256" not in [SHA-512]``），
    而锚点摘要本身是 SHA-256。RSA 路径实测被接受，故锚点专用一把 RSA 钥匙，**不复用**
    凭证签名钥（减少耦合，也让「锚点钥泄露」不至于直接毁掉凭证签名链）。
    """

    def __init__(self, private_key=None, public_key_pem: str | None = None):
        self._key = private_key
        self.public_key_pem = public_key_pem

    @classmethod
    def generate(cls) -> "AnchorSigner":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        return cls(key, pem)

    @classmethod
    def from_pem_file(cls, path: str) -> "AnchorSigner":
        from cryptography.hazmat.primitives import serialization

        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        return cls(key, pem)

    @property
    def public_key_sha256(self) -> str:
        return hashlib.sha256(self.public_key_pem.encode("ascii")).hexdigest()

    def sign(self, data: bytes) -> str:
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if self._key is None:
            raise TransparencyError("E_TLOG_NO_KEY: 未加载锚点私钥，无法签名")
        sig = self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode("ascii")


# ------------------------------------------------------------------ 后端
class Backend:
    """透明日志后端接口。子类必须如实声明 ``external``。"""

    name = "abstract"
    external = False
    log_url: str | None = None

    def submit(self, artifact: bytes, signer: AnchorSigner, *, trace_id: str) -> dict:
        raise NotImplementedError

    def fetch(self, entry_uuid: str) -> dict | None:
        raise NotImplementedError

    def search(self, digest_hex: str) -> list:
        raise NotImplementedError

    def probe(self) -> dict:
        return {"backend": self.name, "external": self.external,
                "log_url": self.log_url, "reachable": None}

    # -- 共用的回执封装
    def _receipt(self, artifact: bytes, signer: AnchorSigner, *, trace_id: str,
                 entry_uuid: str, log_index: int | None, integrated_time: int | None,
                 log_id: str | None, set_b64: str | None,
                 set_verified: bool | None) -> dict:
        return {
            "schema": SCHEMA,
            "backend": self.name,
            "external": bool(self.external),
            "immutable": bool(self.external),
            "log_url": self.log_url,
            "trace_id": trace_id,
            "entry_uuid": entry_uuid,
            "log_index": log_index,
            "integrated_time": integrated_time,
            "log_id": log_id,
            "artifact_sha256": sha256_bytes(artifact),
            "artifact_bytes": len(artifact),
            "signer_public_key_sha256": signer.public_key_sha256,
            "set_base64": set_b64,
            "set_verified": set_verified,
            "anchored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


class RekorBackend(Backend):
    """Sigstore Rekor 公共实例（只追加、公开可查、条目不可删除）。"""

    name = "rekor-public"
    external = True

    def __init__(self, base_url: str = REKOR_DEFAULT_URL, timeout: float = 25.0):
        self.log_url = base_url.rstrip("/")
        self.timeout = timeout
        self._rekor_pem: str | None = None

    # -- HTTP
    def _request(self, path: str, *, payload: dict | None = None,
                 method: str | None = None) -> tuple[int, bytes]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.log_url + path, data=data,
            method=method or ("POST" if data is not None else "GET"),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, (exc.read() or b"")
        except (urllib.error.URLError, OSError) as exc:
            raise TransparencyError("E_TLOG_NETWORK: %s: %s"
                                    % (type(exc).__name__, str(exc)[:200])) from exc

    def probe(self) -> dict:
        out = super().probe()
        try:
            status, body = self._request("/api/v1/log")
            doc = json.loads(body.decode("utf-8", "replace"))
            out.update({"reachable": status == 200,
                        "tree_size": (doc.get("treeSize") or
                                      _tree_size_from_checkpoint(doc)),
                        "root_hash": (doc.get("rootHash") or ""),
                        "note": "Rekor 只追加：条目写入后不可删除或改写"})
        except (TransparencyError, ValueError) as exc:
            out.update({"reachable": False, "error": str(exc)[:200]})
        return out

    # -- 写
    def submit(self, artifact: bytes, signer: AnchorSigner, *, trace_id: str) -> dict:
        import base64

        entry = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "signature": {
                    "content": signer.sign(artifact),
                    "publicKey": {"content": base64.b64encode(
                        signer.public_key_pem.encode("ascii")).decode("ascii")},
                },
                # Rekor 的 hashedrekord 要求签名**作用于被声明的 artifact 原文**，
                # 这里 artifact 就是锚点文档的规范字节，摘要自洽（实测签名对象写错
                # 会被日志 400 拒绝：crypto/rsa: verification error）。
                "data": {"hash": {"algorithm": "sha256", "value": sha256_bytes(artifact)}},
            },
        }
        status, body = self._request("/api/v1/log/entries", payload=entry)
        text = body.decode("utf-8", "replace")
        if status not in (200, 201, 409):
            raise TransparencyError("E_TLOG_REJECTED: HTTP %s: %s" % (status, text[:300]))
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise TransparencyError("E_TLOG_BAD_RESPONSE: %s" % text[:200]) from exc
        if not isinstance(doc, dict) or not doc:
            raise TransparencyError("E_TLOG_BAD_RESPONSE: 空响应 %s" % text[:200])
        entry_uuid = next(iter(doc))
        item = doc[entry_uuid] or {}
        verification = item.get("verification") or {}
        set_b64 = verification.get("signedEntryTimestamp")
        receipt = self._receipt(
            artifact, signer, trace_id=trace_id, entry_uuid=entry_uuid,
            log_index=item.get("logIndex"), integrated_time=item.get("integratedTime"),
            log_id=item.get("logID"), set_b64=set_b64,
            set_verified=None)
        # 回执当场自检：SET 必须在 Rekor 公钥下验得过，否则这张回执不该被采信
        receipt["set_verified"] = self.verify_set(item) if set_b64 else False
        receipt["already_existed"] = status == 409
        receipt["inclusion_proof"] = {
            "log_index": ((verification.get("inclusionProof") or {}).get("logIndex")),
            "tree_size": ((verification.get("inclusionProof") or {}).get("treeSize")),
            "root_hash": ((verification.get("inclusionProof") or {}).get("rootHash")),
        }
        return receipt

    # -- 读
    def fetch(self, entry_uuid: str) -> dict | None:
        status, body = self._request("/api/v1/log/entries/" + entry_uuid)
        if status == 404:
            return None
        if status != 200:
            raise TransparencyError("E_TLOG_FETCH: HTTP %s" % status)
        doc = json.loads(body.decode("utf-8", "replace"))
        return doc.get(entry_uuid) or (next(iter(doc.values())) if doc else None)

    def search(self, digest_hex: str) -> list:
        status, body = self._request("/api/v1/index/retrieve",
                                     payload={"hash": "sha256:%s" % digest_hex})
        if status != 200:
            raise TransparencyError("E_TLOG_SEARCH: HTTP %s: %s"
                                    % (status, body[:200].decode("utf-8", "replace")))
        doc = json.loads(body.decode("utf-8", "replace") or "[]")
        return list(doc) if isinstance(doc, list) else []

    # -- 验签
    def rekor_public_pem(self) -> str:
        if self._rekor_pem is None:
            status, body = self._request("/api/v1/log/publicKey")
            if status != 200:
                raise TransparencyError("E_TLOG_PUBKEY: HTTP %s" % status)
            # 响应是 JSON 字符串（内含 \n 转义），必须 json.loads 解开才能当 PEM 用
            self._rekor_pem = json.loads(body.decode("utf-8", "replace"))
        return self._rekor_pem

    def verify_set(self, entry: dict) -> bool:
        """用 Rekor 公钥验 ``signedEntryTimestamp``：证明这张回执由日志签发。"""
        import base64

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature

        verification = (entry or {}).get("verification") or {}
        set_b64 = verification.get("signedEntryTimestamp")
        if not set_b64:
            return False
        payload = json.dumps({"body": entry.get("body"),
                              "integratedTime": entry.get("integratedTime"),
                              "logID": entry.get("logID"),
                              "logIndex": entry.get("logIndex")},
                             separators=(",", ":")).encode("utf-8")
        try:
            pub = serialization.load_pem_public_key(
                self.rekor_public_pem().encode("ascii"))
            pub.verify(base64.b64decode(set_b64), payload, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except (ValueError, TransparencyError):
            return False


class FileBackend(Backend):
    """本机只追加文件（桩）。``external=False``：它救不了「持证方自己改」这个场景。"""

    name = "local-file"
    external = False

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.log_url = "file:///" + self.path.replace("\\", "/")

    def _read_all(self) -> list:
        if not os.path.isfile(self.path):
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def probe(self) -> dict:
        out = super().probe()
        out.update({"reachable": True, "entries": len(self._read_all()),
                    "note": "本机文件日志：只追加，但仍在持证方控制之下（external=False）"})
        return out

    def submit(self, artifact: bytes, signer: AnchorSigner, *, trace_id: str) -> dict:
        entries = self._read_all()
        digest = sha256_bytes(artifact)
        for item in entries:  # 同一锚点只记一次（幂等，与 Rekor 的 409 语义一致）
            if item["artifact_sha256"] == digest:
                return self._receipt(artifact, signer, trace_id=trace_id,
                                     entry_uuid=item["entry_uuid"],
                                     log_index=item["log_index"],
                                     integrated_time=item["integrated_time"],
                                     log_id="local-file", set_b64=None,
                                     set_verified=False)
        record = {"entry_uuid": hashlib.sha256(
                      (digest + str(len(entries))).encode()).hexdigest(),
                  "log_index": len(entries),
                  "integrated_time": int(time.time()),
                  "artifact_sha256": digest,
                  "trace_id": trace_id,
                  "signer_public_key_sha256": signer.public_key_sha256,
                  "signature": signer.sign(artifact)}
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return self._receipt(artifact, signer, trace_id=trace_id,
                             entry_uuid=record["entry_uuid"],
                             log_index=record["log_index"],
                             integrated_time=record["integrated_time"],
                             log_id="local-file", set_b64=None, set_verified=False)

    def fetch(self, entry_uuid: str) -> dict | None:
        for item in self._read_all():
            if item["entry_uuid"] == entry_uuid:
                return item
        return None

    def search(self, digest_hex: str) -> list:
        return [i["entry_uuid"] for i in self._read_all()
                if i["artifact_sha256"] == digest_hex]


class NullBackend(Backend):
    """显式禁用锚定。绝不返回假回执。"""

    name = "disabled"
    external = False

    def probe(self) -> dict:
        return {"backend": self.name, "external": False, "reachable": False,
                "note": "锚定被显式禁用"}

    def submit(self, artifact: bytes, signer: AnchorSigner, *, trace_id: str) -> dict:
        raise TransparencyError("E_TLOG_DISABLED: 透明日志锚定被禁用，不产出回执")

    def fetch(self, entry_uuid: str) -> dict | None:
        return None

    def search(self, digest_hex: str) -> list:
        return []


def _tree_size_from_checkpoint(doc: dict) -> int | None:
    shards = doc.get("inactiveShards") or []
    if shards and isinstance(shards[0], dict):
        text = shards[0].get("signedTreeHead") or ""
        for line in text.splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    tree = doc.get("treeSize")
    return int(tree) if isinstance(tree, int) else None


def make_backend(spec: str, *, file_path: str | None = None,
                 url: str = REKOR_DEFAULT_URL,
                 timeout: float = 25.0) -> Backend:
    """``rekor`` / ``file`` / ``none`` → 具体后端。未知值直接报错，不静默降级。"""
    spec = (spec or "none").strip().lower()
    if spec in ("rekor", "rekor-public"):
        return RekorBackend(url, timeout=timeout)
    if spec in ("file", "local", "local-file"):
        if not file_path:
            raise TransparencyError("E_TLOG_CONFIG: file 后端需要 file_path")
        return FileBackend(file_path)
    if spec in ("none", "disabled", "off", ""):
        return NullBackend()
    raise TransparencyError("E_TLOG_CONFIG: 未知后端 %r（支持 rekor / file / none）" % spec)


# ------------------------------------------------------------------ 校验
def verify_receipt(receipt: dict, artifact: bytes, *, backend: Backend | None = None,
                   fetch: bool = True) -> dict:
    """校验一张回执是否真的对应这份 artifact，并且在日志里查得到。

    判据四项：① 回执里的摘要 == 本地重算摘要；② 日志按 uuid 能取回条目；
    ③ 条目体里的 ``data.hash.value`` == 本地摘要（内容一致）；④ 回执 ``external=True``
    （只有外部日志才谈得上「离开持证方控制」）。SET 验签单独作为附加项。
    """
    import base64

    out = {"schema_ok": False, "digest_match": False, "present": False,
           "body_digest_match": False, "external": bool(receipt.get("external")),
           "set_verified": bool(receipt.get("set_verified")),
           # 先置 False：后面任何一条早退路径都必须带着「不可外部核验」这个结论，
           # 不能因为提前 return 就漏掉这个键（漏掉会被误读成「没说过不行」）。
           "externally_checkable": False, "index_match": False,
           "backend": receipt.get("backend"), "entry_uuid": receipt.get("entry_uuid"),
           "log_index": receipt.get("log_index"),
           "integrated_time": receipt.get("integrated_time"), "ok": False}
    if not isinstance(receipt, dict) or receipt.get("schema") != SCHEMA:
        out["error"] = "E_TLOG_RECEIPT_SCHEMA"
        return out
    out["schema_ok"] = True
    local = sha256_bytes(artifact)
    out["local_digest"] = local
    out["digest_match"] = receipt.get("artifact_sha256") == local
    if not (fetch and backend is not None and receipt.get("entry_uuid")):
        out["ok"] = bool(out["digest_match"] and out["external"])
        return out
    try:
        entry = backend.fetch(receipt["entry_uuid"])
    except TransparencyError as exc:
        out["error"] = str(exc)[:200]
        return out
    if not entry:
        out["error"] = "E_TLOG_ENTRY_MISSING"
        return out
    out["present"] = True
    try:
        body = json.loads(base64.b64decode(entry.get("body") or ""))
        value = ((body.get("spec") or {}).get("data") or {}).get("hash", {}).get("value")
        out["body_digest_match"] = value == local
    except (ValueError, TypeError):
        out["error"] = "E_TLOG_BODY_DECODE"
    out["log_index_fetched"] = entry.get("logIndex")
    out["integrated_time_fetched"] = entry.get("integratedTime")
    out["index_match"] = entry.get("logIndex") == receipt.get("log_index")
    if isinstance(backend, RekorBackend):
        out["set_verified"] = backend.verify_set(entry)
    out["externally_checkable"] = bool(out["external"] and out["present"]
                                       and out["body_digest_match"])
    out["ok"] = bool(out["digest_match"] and out["present"]
                     and out["body_digest_match"] and out["index_match"]
                     and out["external"])
    return out


def detect_rework(receipt: dict | None, current_artifact: bytes,
                  *, backend: Backend | None = None) -> dict:
    """事后核对：手里这张回执，与眼前这份凭证，是不是同一份东西？

    - ``receipt`` 为空 → ``undetectable``：首次核验者没有任何历史锚点可比，
      整册重做对他完全隐形（这是本机制的**真实边界**，写进 P11 证据）。
    - 回执在、摘要不符 → ``mismatch=True``：眼前这份凭证不是当初被锚定的那一份，
      即「整册重做」被检出；日志里那条旧条目仍然在（不可删），可作事后举证。
    """
    current = sha256_bytes(current_artifact)
    if not receipt:
        return {"detectable": False, "reason": "E_TLOG_NO_PRIOR_RECEIPT",
                "current_digest": current,
                "note": "首次核验者无历史回执可比，整册重做不可发现"}
    anchored = receipt.get("artifact_sha256")
    out = {"anchored_digest": anchored, "current_digest": current,
           "mismatch": anchored != current,
           "detectable": anchored != current,
           "entry_uuid": receipt.get("entry_uuid"),
           "integrated_time": receipt.get("integrated_time"),
           "external": bool(receipt.get("external"))}
    if backend is not None and receipt.get("entry_uuid"):
        try:
            out["prior_entry_still_present"] = bool(backend.fetch(receipt["entry_uuid"]))
        except TransparencyError as exc:
            out["prior_entry_still_present"] = None
            out["fetch_error"] = str(exc)[:160]
    if anchored == current:
        out["note"] = "回执与当前凭证同一份：未检出重做"
    else:
        out["note"] = ("回执锚定的是另一份凭证，日志条目不可删改，"
                       "故「整册重做」可被留存过回执的第三方证明")
    return out


def receipt_to_json(receipt: dict) -> str:
    return json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=1)


def save_receipt(receipt: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(receipt_to_json(receipt))
    return path


def load_receipt(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
