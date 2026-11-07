# -*- coding: utf-8 -*-
"""动作轨迹账本回归测试。

守四条语义，任何一条破了这个模块就失去意义：
    1. 未篡改 → 不被误报（假阳性会毁掉可信度）
    2. 改值 / 插入 / 删除 / 换序 → 必须检出，且首断点定位准确
    3. 链自洽但头被截断 → 必须检出
    4. 拿 A 轨迹的凭证背书被改过的 B 轨迹 → 必须拒
"""

import copy

import pytest

from swordholder import core, trace_ledger as tl, trust


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _ledger(n=8):
    led = tl.TraceLedger(trace_id="TR-1", actor="qwen3:8b")
    for i in range(n):
        led.append("tool_%d" % i, {"host": "build-runner-07", "i": i},
                   {"severity": "low", "ok": True}, ts="2026-11-13T10:0%d:00Z" % i)
    return led


# ---------------------------------------------------------------- 不误报
def test_untampered_chain_is_consistent():
    body = _ledger().body()
    res = tl.verify_chain(body)
    assert res["ok"] is True, res["reason"]
    assert res["first_break"] is None
    assert res["expected_head"] == res["claimed_head"]


def test_empty_trace_head_is_genesis():
    led = tl.TraceLedger(trace_id="TR-E")
    assert led.head == tl.GENESIS
    assert tl.verify_chain(led.body())["ok"] is True


# ---------------------------------------------------------------- 四类篡改
def test_value_tamper_detected_at_step():
    body = _ledger().body()
    body["entries"][3]["observation"]["severity"] = "critical"
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 3
    assert "改值" in res["reason"]


def test_insert_tamper_detected():
    body = _ledger().body()
    forged = copy.deepcopy(body["entries"][2])
    forged["action"] = "tool_ghost"
    body["entries"].insert(3, forged)
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 3


def test_delete_tamper_detected():
    body = _ledger().body()
    del body["entries"][2]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 2


def test_reorder_tamper_detected():
    body = _ledger().body()
    e = body["entries"]
    e[2], e[5] = e[5], e[2]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 2


def test_truncate_tail_detected_despite_short_chain():
    """只删尾部若干步时，存活部分各自自洽，必须靠 head / step_count 拦住。"""
    body = _ledger().body()
    body["entries"] = body["entries"][:5]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] is None
    assert "step_count" in res["reason"] or "头部哈希" in res["reason"]


# ---------------------------------------------------------------- 与凭证串联
def test_seal_and_verify_roundtrip(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"))
    res = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "VALID", res["reason"]


def test_seal_refuses_inconsistent_body(tmp_path, keys):
    body = _ledger().body()
    body["entries"][1]["action"] = "swapped-to-something-else"
    with pytest.raises(tl.TraceError):
        tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                      out_path=str(tmp_path / "bad.seal.json"))


def test_tampered_body_against_valid_seal_rejected(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"))

    tampered = copy.deepcopy(body)
    tampered["entries"][4]["args"]["host"] = "exfil-01"
    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"].startswith("E_TRACE_BREAK")


def test_seal_from_other_trace_rejected(tmp_path, keys):
    """链自洽但凭证是另一条轨迹的 —— 必须靠 trace_id / head 比对拦住。"""
    body_a = _ledger(6).body()
    body_b = _ledger(9).body()
    body_b["trace_id"] = "TR-1"
    # body_b 步数不同，先伪装成与 A 一样的头，验证比对不靠巧合
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body_b, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "b.seal.json"))
    res = tl.verify_sealed_trace(body_a, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] in ("E_TRACE_HEAD_MISMATCH", "E_TRACE_DIGEST_MISMATCH")


def test_seal_binds_challenge(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"), challenge="nonce-42")
    ok = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                expected_challenge="nonce-42")
    assert ok["verdict"] == "VALID", ok["reason"]
    wrong = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                   expected_challenge="nonce-43")
    assert wrong["verdict"] == "INVALID"
