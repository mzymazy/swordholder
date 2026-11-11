# -*- coding: utf-8 -*-
"""封签里那段外部时间戳的离线行为：写入、读回、缺戳与坏戳的判定口径。

外部时间戳只在联网时才能取到，但「凭证里到底有没有戳、戳能不能用、要不要因为
没戳就判 INVALID」这三件事完全离线。本文件把这个口径钉死，避免以后为了「让测试
通过」而把 require_external_timestamp 悄悄放水。
"""

from __future__ import annotations

import json

import pytest

from swordholder import core, trace_ledger as tl, trust


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


@pytest.fixture()
def sealed(tmp_path, keys):
    led = tl.TraceLedger(trace_id="TR-EXT", actor="qwen3:8b")
    for i in range(4):
        led.append("tool_%d" % i, {"i": i}, {"ok": True},
                   ts="2026-11-13T10:0%d:00Z" % i)
    body = led.body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    res = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                        out_path=str(tmp_path / "trace.seal.json"))
    return body, res["seal_path"], anchor


def test_stamp_path_payload_requires_existing_seal(tmp_path):
    with pytest.raises(tl.TraceError, match="凭证文件不存在"):
        tl.stamp_path_payload(str(tmp_path / "ghost.seal.json"), {"trace_id": "x"},
                              "https://tsa.invalid")


def test_write_seal_ext_appends_segment_without_touching_payload(sealed):
    body, seal_path, _anchor = sealed
    before = tl._seal_payload(seal_path)  # noqa: SLF001
    record = {"schema": "swordholder.timestamp/1", "url": "https://tsa.invalid",
              "gen_time": "2026-11-13T10:00:00Z", "digest_alg": "sha256",
              "imprint_sha256": "a" * 64, "nonce": 1, "token_b64": "",
              "token_sha256": "b" * 64}
    tl._write_seal_ext(seal_path, record)  # noqa: SLF001
    doc = json.load(open(seal_path, encoding="utf-8"))
    assert doc[tl.EXT_TS_KEY] == record
    after = tl._seal_payload(seal_path)  # noqa: SLF001
    assert after == before  # 打戳只加段，不改被签名的 payload


def test_write_seal_ext_refuses_non_object_document(tmp_path):
    path = tmp_path / "broken.seal.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(tl.TraceError, match="结构非法"):
        tl._write_seal_ext(str(path), {"url": "x"})  # noqa: SLF001


def test_check_external_timestamp_absent_unreadable_and_missing_segment(sealed, tmp_path):
    _body, seal_path, _anchor = sealed
    absent = tl.check_external_timestamp(str(tmp_path / "ghost.seal.json"))
    assert absent["present"] is False and absent["reason"] == "E_TSA_ABSENT"

    broken = tmp_path / "broken.seal.json"
    broken.write_text("{not json", encoding="utf-8")
    res = tl.check_external_timestamp(str(broken))
    assert res["present"] is False
    assert res["reason"].startswith("E_TSA_SEAL_UNREADABLE")

    # 真凭证、但没打戳：present=False，不是错误
    plain = tl.check_external_timestamp(seal_path)
    assert plain["present"] is False and plain["ok"] is False


def test_check_external_timestamp_without_payload_reports_no_payload(tmp_path):
    """凭证里只有戳、取不回 payload：不能拿空摘要去比对，要如实说取不到。"""
    path = tmp_path / "only_ts.seal.json"
    path.write_text(json.dumps({tl.EXT_TS_KEY: {"url": "https://tsa.invalid",
                                                "token_b64": ""}}), encoding="utf-8")
    res = tl.check_external_timestamp(str(path))
    assert res["present"] is True
    assert res["reason"] == "E_TSA_NO_PAYLOAD"
    assert res["ok"] is False


def test_check_external_timestamp_unusable_token(sealed):
    body, seal_path, _anchor = sealed
    tl._write_seal_ext(seal_path, {  # noqa: SLF001
        "schema": "swordholder.timestamp/1", "url": "https://tsa.invalid",
        "gen_time": "2026-11-13T10:00:00Z", "digest_alg": "sha256",
        "imprint_sha256": "a" * 64, "nonce": 7,
        "token_b64": "@@@not-base64@@@", "token_sha256": "c" * 64})
    res = tl.check_external_timestamp(seal_path)
    assert res["present"] is True
    assert res["ok"] is False
    assert res["reason"].startswith("E_TSA_TOKEN_UNUSABLE")
    assert tl.verify_chain(body)["ok"] is True  # 加了个坏戳不影响轨迹链本身


def test_require_external_timestamp_turns_valid_seal_invalid(sealed):
    body, seal_path, anchor = sealed
    lenient = tl.verify_sealed_trace(body, seal_path, keys_path=anchor)
    assert lenient["verdict"] == "VALID"
    assert lenient["external_timestamp"]["present"] is False

    strict = tl.verify_sealed_trace(body, seal_path, keys_path=anchor,
                                    require_external_timestamp=True)
    assert strict["verdict"] == "INVALID"
    assert strict["reason"] == "E_TRACE_TSA_ABSENT"


def test_require_external_timestamp_rejects_unusable_token(sealed):
    body, seal_path, anchor = sealed
    tl._write_seal_ext(seal_path, {  # noqa: SLF001
        "schema": "swordholder.timestamp/1", "url": "https://tsa.invalid",
        "gen_time": "2026-11-13T10:00:00Z", "digest_alg": "sha256",
        "imprint_sha256": "a" * 64, "nonce": 7, "token_b64": "",
        "token_sha256": "c" * 64})
    strict = tl.verify_sealed_trace(body, seal_path, keys_path=anchor,
                                    require_external_timestamp=True)
    assert strict["verdict"] == "INVALID"
    assert strict["reason"].startswith("E_TRACE_TSA_INVALID")
    assert strict["external_timestamp"]["present"] is True
