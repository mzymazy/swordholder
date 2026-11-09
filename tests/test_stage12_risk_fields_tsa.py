# -*- coding: utf-8 -*-
"""S12 回归：Art.12(2) 风险字段档位 + RFC 3161 外部时间戳。

守三条承诺：

1. **向后兼容**：不声明 ``profile="art12-2"`` 时条目键集合与 0.9.0 完全一致，
   历史轨迹的哈希不变——加字段不能让旧证据验不过。
2. **写入即强制、可直接筛取**：声明档位后 purpose / event_type / severity / risk_flag
   缺一项就拒写，并能按用途、按最低严重度、按风险标记直接筛出来。
3. **外部时间戳是真的**：fixture 里的 token 能被离线复核（CMS 签名、imprint、nonce、
   ESS 绑定、证书链），digest 或 nonce 对不上必须判假；未打戳的凭证在
   ``require_external_timestamp=True`` 下必须 INVALID，而默认口径不受影响。
"""

from __future__ import annotations

import base64
import copy
import json
import os

import pytest

from swordholder import core, timestamp as ts
from swordholder import trace_ledger as tl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "evidence", "stage12_tsa_fixture.json")
FREETSA_ROOT = os.path.join(REPO, "evidence", "stage12_tsa_freetsa_root.pem")

TRUST_TEMPLATE = {"trust_root": "test-s12", "keys": [{
    "key_id": "test-s12-001", "algorithm": "ed25519", "public_key_hex": None}]}


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _trust(tmp_path, pub_hex):
    doc = json.loads(json.dumps(TRUST_TEMPLATE))
    doc["keys"][0]["public_key_hex"] = pub_hex
    p = tmp_path / "trusted_keys.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _plain(n=3, trace_id="S12-PLAIN"):
    led = tl.TraceLedger(trace_id=trace_id, actor="test:s12")
    for i in range(n):
        led.append("tool_%02d" % i, {"i": i}, {"ok": True}, ts="2026-03-01T08:00:0%dZ" % i)
    return led


def _art12(n=3, trace_id="S12-ART12"):
    led = tl.TraceLedger(trace_id=trace_id, actor="test:s12", profile="art12-2")
    led.append("drift_check", None, {"drift": 0.4}, "2026-03-01T08:00:00Z",
               purpose="risk_identification", event_type="drift_detected",
               severity="high", risk_flag=True, monitor_tag="nightly")
    led.append("complaint", None, {"n": 2}, "2026-03-01T08:01:00Z",
               purpose="post_market_monitoring", event_type="complaint_cluster",
               severity="medium", risk_flag=True)
    led.append("review", None, {"outcome": "pass"}, "2026-03-01T08:02:00Z",
               purpose="deployer_evaluation", event_type="quarterly_review",
               severity="info", risk_flag=False)
    return led


# --------------------------------------------------------------- 1. 向后兼容
def test_default_profile_keys_unchanged():
    entry = _plain(1).body()["entries"][0]
    assert sorted(entry) == ["action", "args", "hash", "n", "observation", "prev", "ts"]


def test_default_and_art12_hashes_differ_only_by_fields():
    """同一动作在两种档位下的 entry_core 不同，说明字段确实进链，而不是旁挂。"""
    plain = _plain(1, "S12-H").body()["entries"][0]
    art = _art12(1).body()["entries"][0]
    assert plain["hash"] != art["hash"]


# --------------------------------------------------- 2. 字段齐备 + 写入强制
def test_art12_entry_carries_five_fields():
    entry = _art12(1).body()["entries"][0]
    for f in tl.ART12_2_FIELDS:
        assert f in entry, f
    assert entry["purpose"] == "risk_identification"
    assert entry["severity"] == "high"
    assert entry["risk_flag"] is True
    assert entry["monitor_tag"] == "nightly"


@pytest.mark.parametrize("kwargs,code", [
    ({}, "E_ART12_2_PURPOSE_MISSING"),
    ({"purpose": "risk_identification"}, "E_ART12_2_EVENT_TYPE_MISSING"),
    ({"purpose": "risk_identification", "event_type": "x"}, "E_ART12_2_SEVERITY_MISSING"),
    ({"purpose": "risk_identification", "event_type": "x", "severity": "high"},
     "E_ART12_2_RISK_FLAG_MISSING"),
])
def test_missing_field_is_rejected_with_precise_code(kwargs, code):
    led = tl.TraceLedger(trace_id="S12-MISS", actor="test:s12", profile="art12-2")
    with pytest.raises(tl.TraceError) as exc:
        led.append("x", None, None, "2026-03-01T08:00:00Z", **kwargs)
    assert str(exc.value).startswith(code)


def test_unknown_purpose_and_severity_rejected():
    led = tl.TraceLedger(trace_id="S12-BAD", actor="test:s12", profile="art12-2")
    with pytest.raises(tl.TraceError) as exc:
        led.append("x", None, None, "2026-03-01T08:00:00Z", purpose="whatever",
                   event_type="e", severity="high", risk_flag=True)
    assert str(exc.value).startswith("E_ART12_2_PURPOSE_INVALID")
    with pytest.raises(tl.TraceError) as exc2:
        led.append("x", None, None, "2026-03-01T08:00:00Z",
                   purpose="risk_identification", event_type="e",
                   severity="apocalyptic", risk_flag=True)
    assert str(exc2.value).startswith("E_ART12_2_SEVERITY_INVALID")


def test_unknown_profile_still_rejected():
    with pytest.raises(tl.TraceError):
        tl.TraceLedger(trace_id="S12-P", actor="t", profile="art12-99")


# ------------------------------------------------------------ 3. 可直接筛取
def test_select_entries_by_purpose():
    body = _art12().body()
    for purpose in tl.ART12_2_PURPOSES:
        hits = tl.select_entries(body, purpose=purpose)
        assert len(hits) == 1, purpose
        assert hits[0]["purpose"] == purpose


def test_select_entries_by_min_severity_and_flag():
    body = _art12().body()
    assert len(tl.select_entries(body, min_severity="high")) == 1
    assert len(tl.select_entries(body, min_severity="info")) == 3
    assert len(tl.select_entries(body, risk_flag=True)) == 2
    assert len(tl.select_entries(body, risk_flag=False)) == 1


def test_risk_summary_counts():
    summary = tl.risk_summary(_art12().body())
    assert summary["total"] == 3
    assert summary["risk_flagged"] == 2
    assert summary["unclassified"] == 0
    assert summary["by_severity"]["high"] == 1
    assert summary["by_purpose"]["deployer_evaluation"] == 1


def test_risk_field_tamper_breaks_chain_at_that_step():
    body = copy.deepcopy(_art12().body())
    body["entries"][1]["severity"] = "info"
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 1


# -------------------------------------------------------- 4. 外部时间戳（离线）
def _fixture():
    with open(FIXTURE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _roots():
    with open(FREETSA_ROOT, "rb") as fh:
        return [fh.read()]


def test_fixture_token_verifies_offline():
    doc = _fixture()
    token = base64.b64decode(doc["token_b64"])
    digest = bytes.fromhex(doc["payload_c14n_sha256"])
    res = ts.verify_token(token, digest, hash_name=doc["digest_alg"],
                          expected_nonce=doc["nonce"], trusted_roots=_roots())
    assert res["ok"] is True, res.get("reason")
    assert all(res["checks"].values())
    assert res["tst"]["gen_time"] == doc["gen_time"]


def test_wrong_digest_fails():
    doc = _fixture()
    token = base64.b64decode(doc["token_b64"])
    bad = bytes.fromhex("00" * 32)
    res = ts.verify_token(token, bad, expected_nonce=doc["nonce"],
                          trusted_roots=_roots())
    assert res["ok"] is False
    assert res["checks"]["imprint_match"] is False


def test_wrong_nonce_fails():
    doc = _fixture()
    token = base64.b64decode(doc["token_b64"])
    digest = bytes.fromhex(doc["payload_c14n_sha256"])
    res = ts.verify_token(token, digest, expected_nonce=12345, trusted_roots=_roots())
    assert res["ok"] is False
    assert res["checks"]["nonce_match"] is False


def test_payload_imprint_matches_fixture():
    doc = _fixture()
    assert tl.payload_imprint(doc["payload"]) == doc["payload_c14n_sha256"]


# --------------------------------------------- 5. 凭证层：缺戳必须被拒（默认放行）
def test_unstamped_seal_is_valid_by_default_but_rejected_when_required(tmp_path, keys):
    body = _plain(3, "S12-TS").body()
    trust = _trust(tmp_path, keys["public_key_hex"])
    seal = tl.seal_trace(body, keys["private_key_path"], issuer="test",
                         out_path=str(tmp_path / "s12.seal.json"))
    loose = tl.verify_sealed_trace(body, seal["seal_path"], keys_path=trust)
    assert loose["verdict"] == "VALID"
    assert loose["external_timestamp"]["present"] is False

    strict = tl.verify_sealed_trace(body, seal["seal_path"], keys_path=trust,
                                    require_external_timestamp=True)
    assert strict["verdict"] == "INVALID"
    assert str(strict["reason"]).startswith("E_TRACE_TSA_ABSENT")


def test_check_external_timestamp_absent_is_not_ok(tmp_path, keys):
    body = _plain(2, "S12-TS2").body()
    seal = tl.seal_trace(body, keys["private_key_path"], issuer="test",
                         out_path=str(tmp_path / "s12b.seal.json"))
    chk = tl.check_external_timestamp(seal["seal_path"])
    assert chk["present"] is False
    assert chk["ok"] is False
    assert chk["reason"] == "E_TSA_ABSENT"


def test_stamp_to_unreachable_tsa_raises_not_silently_passes():
    """桩就是桩：拿不到戳必须抛错，绝不能返回一个看起来成功的记录。"""
    with pytest.raises(ts.TimestampError):
        ts.stamp_digest(ts.digest_of(b"x"), "https://127.0.0.1:9/tsr", timeout=2.0)
