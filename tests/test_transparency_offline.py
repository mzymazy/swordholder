# -*- coding: utf-8 -*-
"""透明日志锚定的离线可测面：签名器、后端选择、回执校验、重做检出。

真实 Rekor 需要网络，跑 CI 不可依赖；但「回执对不对得上这份 artifact」这条判定
本身与网络无关——本文件用本地 file 后端和一个只回放固定条目的 stub 后端，把
① 摘要不符 ② 日志里查不到 ③ 条目体里不是这份东西 ④ 索引对不上 四种失败逐条钉死，
并确认只有「外部日志 + 查得到 + 内容一致 + 索引一致」才给 ok=True。
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from swordholder import transparency as tp


@pytest.fixture(scope="module")
def signer():
    return tp.AnchorSigner.generate()


@pytest.fixture()
def file_backend(tmp_path):
    return tp.FileBackend(str(tmp_path / "anchor_log.jsonl"))


class _StubBackend(tp.Backend):
    """只回放一条外部日志条目的后端；不联网，只验判定逻辑。"""

    name = "stub"
    external = True
    log_url = "https://stub.invalid"

    def __init__(self, entry):
        self._entry = entry
        self.fail_with: str | None = None

    def fetch(self, entry_uuid):
        if self.fail_with:
            raise tp.TransparencyError(self.fail_with)
        return self._entry

    def probe(self):
        return {"backend": self.name, "external": True, "log_url": self.log_url,
                "reachable": True}


def _entry_for(digest: str, *, index: int = 0, body_digest: str | None = None) -> dict:
    body = {"spec": {"data": {"hash": {"value": body_digest or digest}}}}
    return {"body": base64.b64encode(
                json.dumps(body).encode("utf-8")).decode("ascii"),
            "logIndex": index, "integratedTime": 1700000000}


def test_null_backend_never_fakes_receipt(signer):
    nb = tp.NullBackend()
    assert nb.probe()["reachable"] is False
    assert nb.fetch("whatever") is None
    assert nb.search("0" * 64) == []
    with pytest.raises(tp.TransparencyError, match="E_TLOG_DISABLED"):
        nb.submit(b"x", signer, trace_id="t-1")


def test_make_backend_selects_and_rejects(tmp_path):
    assert isinstance(tp.make_backend("none"), tp.NullBackend)
    assert isinstance(tp.make_backend("", file_path=None), tp.NullBackend)
    assert isinstance(tp.make_backend("rekor"), tp.RekorBackend)
    assert tp.make_backend("rekor").external is True
    fb = tp.make_backend("file", file_path=str(tmp_path / "l.jsonl"))
    assert isinstance(fb, tp.FileBackend) and fb.external is False
    with pytest.raises(tp.TransparencyError, match="E_TLOG_CONFIG"):
        tp.make_backend("file")  # 缺 file_path：不许悄悄降级成 none
    with pytest.raises(tp.TransparencyError, match="E_TLOG_CONFIG"):
        tp.make_backend("rekor-cloud-please")


def test_anchor_signer_generate_sign_and_pem_roundtrip(signer, tmp_path):
    assert signer.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    sig = signer.sign(b"payload")
    assert isinstance(sig, str) and len(base64.b64decode(sig)) == 256  # RSA-2048
    assert len(signer.public_key_sha256) == 64

    pem_path = tmp_path / "anchor_key.pem"
    pem_path.write_bytes(signer._key.private_bytes(  # noqa: SLF001
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    reloaded = tp.AnchorSigner.from_pem_file(str(pem_path))
    assert reloaded.public_key_sha256 == signer.public_key_sha256
    assert reloaded.sign(b"payload")  # 同一把钥，签得出来


def test_anchor_signer_without_key_refuses_to_sign():
    empty = tp.AnchorSigner()
    with pytest.raises(tp.TransparencyError, match="E_TLOG_NO_KEY"):
        empty.sign(b"payload")


def test_tree_size_from_checkpoint_reads_shard_then_top_level():
    shard = {"inactiveShards": [{"signedTreeHead": "stub\n12345\nbase64sig\n"}]}
    assert tp._tree_size_from_checkpoint(shard) == 12345  # noqa: SLF001
    assert tp._tree_size_from_checkpoint({"treeSize": 7}) == 7  # noqa: SLF001
    assert tp._tree_size_from_checkpoint({}) is None  # noqa: SLF001


def test_verify_receipt_rejects_bad_schema_and_digest_mismatch(signer):
    bad = tp.verify_receipt({"schema": "other/1"}, b"artifact")
    assert bad["ok"] is False and bad["error"] == "E_TLOG_RECEIPT_SCHEMA"
    assert bad["externally_checkable"] is False

    fb = tp.NullBackend()
    # 摘要不符：回执写的是另一份 artifact
    forged = {"schema": tp.SCHEMA, "artifact_sha256": "0" * 64, "external": True,
              "entry_uuid": "u-1"}
    res = tp.verify_receipt(forged, b"artifact", backend=fb)
    assert res["schema_ok"] is True and res["digest_match"] is False
    assert res["ok"] is False and res["externally_checkable"] is False


def test_verify_receipt_without_backend_only_checks_local_digest(signer):
    fb = tp.NullBackend()
    receipt = {"schema": tp.SCHEMA, "artifact_sha256": tp.sha256_bytes(b"a"),
               "external": True, "entry_uuid": "u-1"}
    res = tp.verify_receipt(receipt, b"a", backend=None, fetch=True)
    assert res["ok"] is True  # 不查日志时只保证"回执描述的就是这份东西"
    assert res["present"] is False and res["externally_checkable"] is False

    # 回执自称"外部"，但后端查不到这条条目：不许凭回执自述就给通过
    local_only = tp.verify_receipt(receipt, b"a", backend=fb)
    assert local_only["external"] is True
    assert local_only["present"] is False
    assert local_only["error"] == "E_TLOG_ENTRY_MISSING"
    assert local_only["ok"] is False


def test_verify_receipt_local_file_backend_is_not_external(tmp_path, signer):
    """file 后端能对上摘要，但它在持证方自己的磁盘上——不算"离开控制"，不给 ok。"""
    fb = tp.FileBackend(str(tmp_path / "log.jsonl"))
    receipt = fb.submit(b"artifact", signer, trace_id="t-file")
    assert receipt["external"] is False and receipt["schema"] == tp.SCHEMA
    res = tp.verify_receipt(receipt, b"artifact", backend=fb)
    assert res["present"] is True
    assert res["digest_match"] is True
    assert res["error"] == "E_TLOG_BODY_DECODE"  # 本地日志不存 rekor 条目体
    assert res["ok"] is False


def test_verify_receipt_full_match_requires_external_and_body_and_index():
    artifact = b"artifact"
    digest = tp.sha256_bytes(artifact)
    entry = _entry_for(digest, index=3)
    backend = _StubBackend(entry)
    receipt = {"schema": tp.SCHEMA, "artifact_sha256": digest, "external": True,
               "entry_uuid": "u-3", "log_index": 3, "integrated_time": 1700000000}
    ok = tp.verify_receipt(receipt, artifact, backend=backend)
    assert ok["ok"] is True, ok
    assert ok["body_digest_match"] is True and ok["index_match"] is True
    assert ok["externally_checkable"] is True

    # 索引对不上：条目不是当初那条
    wrong_index = dict(receipt, log_index=4)
    res = tp.verify_receipt(wrong_index, artifact, backend=backend)
    assert res["index_match"] is False and res["ok"] is False

    # 条目体里装的是别的东西
    foreign = _StubBackend(_entry_for("f" * 64, index=3))
    res = tp.verify_receipt(receipt, artifact, backend=foreign)
    assert res["body_digest_match"] is False and res["ok"] is False

    # 日志里查不到
    missing = _StubBackend(None)
    res = tp.verify_receipt(receipt, artifact, backend=missing)
    assert res["present"] is False and res["error"] == "E_TLOG_ENTRY_MISSING"

    # 后端自己报错
    broken = _StubBackend(entry)
    broken.fail_with = "E_TLOG_UNREACHABLE: 403"
    res = tp.verify_receipt(receipt, artifact, backend=broken)
    assert res["ok"] is False and "E_TLOG_UNREACHABLE" in res["error"]


def test_sha256_file_matches_sha256_bytes(tmp_path):
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"anchored-bytes")
    assert tp.sha256_file(str(path)) == tp.sha256_bytes(b"anchored-bytes")
    assert len(tp.sha256_file(str(path))) == 64


def test_abstract_backend_refuses_to_pretend(signer):
    """抽象后端必须抛 NotImplementedError：防止有人只实现一半就当外部日志用。"""
    base = tp.Backend()
    with pytest.raises(NotImplementedError):
        base.submit(b"x", signer, trace_id="t")
    with pytest.raises(NotImplementedError):
        base.fetch("u")
    with pytest.raises(NotImplementedError):
        base.search("0" * 64)
    # probe 有默认实现：没探过就是 None，绝不默认"通"
    probe = base.probe()
    assert probe["reachable"] is None
    assert probe["external"] is False and probe["backend"] == "abstract"


def test_detect_rework_three_outcomes(tmp_path, signer):
    fb = tp.FileBackend(str(tmp_path / "log.jsonl"))
    receipt = fb.submit(b"original", signer, trace_id="t-rw")

    none = tp.detect_rework(None, b"original")
    assert none["detectable"] is False and none["reason"] == "E_TLOG_NO_PRIOR_RECEIPT"

    same = tp.detect_rework(receipt, b"original", backend=fb)
    assert same["mismatch"] is False and same["detectable"] is False
    assert same["prior_entry_still_present"] is True

    redone = tp.detect_rework(receipt, b"redone-entirely", backend=fb)
    assert redone["mismatch"] is True and redone["detectable"] is True
    assert "整册重做" in redone["note"]

    broken = _StubBackend(None)
    broken.fail_with = "E_TLOG_UNREACHABLE"
    res = tp.detect_rework(receipt, b"redone-entirely", backend=broken)
    assert res["prior_entry_still_present"] is None
    assert res["fetch_error"].startswith("E_TLOG_UNREACHABLE")
