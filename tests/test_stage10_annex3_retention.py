# -*- coding: utf-8 -*-
"""S10 回归：Art.12(3) Annex III 字段与 Art.19/26 留存期。

这组测试守第十阶段新加的两块能力，破掉任何一条都会让对应条文从 PASS 退回 FAIL：

1. **向后兼容**：不启用档位时条目键集合与哈希必须和 0.7.x 一模一样——加字段不能让
   历史轨迹验不过（那等于给旧证据判死刑）。
2. **字段齐备 + 写入即强制**：``profile="annex3-1a"`` 下四项缺一项就拒写，且错误码能
   分辨缺的是哪一项，不是一句笼统的"参数错误"。
3. **字段进链**：改 ``period.end`` 不重算哈希必须在**该步**断链，封章校验判 INVALID。
   只存字段不入链＝字段可被悄悄改而链照过，那是假合规。
4. **留存期下限是硬约束**：声明低于六个月直接拒，不给"默认 180 天"的模糊空间。
5. **归档只写副本**：到期前不许归档、副本可校验、副本被改要能发现；模块不提供任何
   删除接口——"到期可归档"≠"到期可销毁"。
"""

import copy
import json

import pytest

from swordholder import core, retention as rt
from swordholder import trace_ledger as tl

TRUST_TEMPLATE = {"trust_root": "test-s10", "keys": [{
    "key_id": "test-s10-001", "algorithm": "ed25519", "public_key_hex": None}]}


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _trust(tmp_path, pub_hex):
    doc = json.loads(json.dumps(TRUST_TEMPLATE))
    doc["keys"][0]["public_key_hex"] = pub_hex
    p = tmp_path / "trusted_keys.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _plain(n=4, trace_id="S10-PLAIN"):
    led = tl.TraceLedger(trace_id=trace_id, actor="test:s10")
    for i in range(n):
        led.append("tool_%02d" % i, {"i": i}, {"ok": True}, ts="2026-03-01T08:00:%02dZ" % i)
    return led


def _annex(n=3, trace_id="S10-A3", start="2026-03-01T08:00:00Z"):
    led = tl.TraceLedger(trace_id=trace_id, actor="test:s10", profile="annex3-1a",
                         start_ts=start)
    for i in range(n):
        led.append(
            "biometric_search_%02d" % i, {"probe_id": "P-%03d" % i}, {"match": True},
            ts="2026-03-01T08:00:%02dZ" % (i * 5),
            period={"start": "2026-03-01T08:00:%02dZ" % (i * 5),
                    "end": "2026-03-01T08:00:%02dZ" % (i * 5 + 3)},
            db_ref="mugshot-db@2026.02.28", matched=True,
            matched_input={"sha256": "%064x" % (i + 1)},
            verified_by="op:7721", verify_method="two_person_review")
    return led


# ---------------------------------------------------------------- 1. 向后兼容
def test_plain_entry_keys_unchanged():
    """不启用档位时键集合必须仍是 0.7.x 那七个，一个不多一个不少。"""
    entry = _plain(1).entries[0]
    assert sorted(entry.keys()) == ["action", "args", "hash", "n", "observation", "prev", "ts"]
    assert "profile" not in _plain(1).body()


def test_plain_hash_matches_070_algorithm():
    """手工按 0.7.x 算法重算第一步哈希，必须与 append 内部算出的一致。"""
    led = _plain(1)
    entry = led.entries[0]
    core_dict = {"n": 0, "ts": "2026-03-01T08:00:00Z", "action": "tool_00",
                 "args": {"i": 0}, "observation": {"ok": True}}
    assert entry["hash"] == tl.entry_hash(core_dict, tl.GENESIS)
    assert tl.verify_chain(led.body())["ok"] is True


def test_repr_fallback_keeps_extras():
    """不可 JSON 化的 args 走 repr 降级时，合规字段不得被一起丢掉。"""
    led = tl.TraceLedger(trace_id="S10-REPR", profile="annex3-1a")
    entry = led.append("weird", {"bad": object()}, {"ok": True},
                       period={"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:02Z"},
                       db_ref="db@1", verified_by="op:1")
    assert entry["serialization"] == "repr"
    assert entry["period"]["end"] == "2026-03-01T08:00:02Z"
    assert entry["identity_check"]["verifier"] == "op:1"
    assert tl.verify_chain(led.body())["ok"] is True


# ---------------------------------------------------------------- 2. 字段齐备 + 拒写
def test_annex3_entry_carries_four_required_fields():
    entry = _annex(1).entries[0]
    assert entry["period"]["start"] == "2026-03-01T08:00:00Z"
    assert entry["period"]["end"] == "2026-03-01T08:00:03Z"
    assert entry["db_ref"] == "mugshot-db@2026.02.28"
    assert entry["matched_input"]["sha256"].startswith("0000")
    assert entry["identity_check"]["verifier"] == "op:7721"
    assert entry["identity_check"]["method"] == "two_person_review"
    assert entry["identity_check"]["at"] == "2026-03-01T08:00:00Z"


def test_annex3_body_records_profile():
    assert _annex(1).body()["profile"] == "annex3-1a"


@pytest.mark.parametrize("kwargs,code", [
    ({}, "E_ANNEX3_PERIOD_MISSING"),
    ({"period": {"start": "2026-03-01T08:00:00Z"}}, "E_ANNEX3_PERIOD_INVALID"),
    ({"period": {"start": "2026-03-01T08:00:05Z", "end": "2026-03-01T08:00:00Z"}},
     "E_ANNEX3_PERIOD_INVALID"),
    ({"period": "2026-03-01T08:00:00Z/2026-03-01T08:00:03Z"}, "E_ANNEX3_PERIOD_INVALID"),
    ({"period": {"start": "not-a-time", "end": "2026-03-01T08:00:03Z"}},
     "E_ANNEX3_PERIOD_INVALID"),
    ({"period": {"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:03Z"}},
     "E_ANNEX3_DB_REF_MISSING"),
    ({"period": {"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:03Z"},
      "db_ref": "db@1", "matched": True}, "E_ANNEX3_MATCHED_INPUT_MISSING"),
    ({"period": {"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:03Z"},
      "db_ref": "db@1"}, "E_ANNEX3_IDENTITY_MISSING"),
])
def test_annex3_rejects_incomplete_record(kwargs, code):
    led = tl.TraceLedger(trace_id="S10-NEG", profile="annex3-1a")
    with pytest.raises(tl.TraceError) as exc:
        led.append("biometric_search", {"probe_id": "P-1"}, {"match": True}, **kwargs)
    assert str(exc.value).startswith(code), str(exc.value)
    assert led.entries == [], "拒写后账本必须仍为空，不能留半条记录"


def test_annex3_identity_accepts_plain_string():
    entry = tl.TraceLedger(trace_id="S10-ID", profile="annex3-1a").append(
        "a", None, None,
        period={"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:01Z"},
        db_ref="db@1", identity_check="op:9001")
    assert entry["identity_check"]["verifier"] == "op:9001"


def test_unknown_profile_rejected():
    with pytest.raises(tl.TraceError):
        tl.TraceLedger(trace_id="S10-X", profile="annex3-9z")


def test_non_matched_step_may_omit_input():
    """未命中的步骤 Art.12(3)(c) 无输入可记，允许缺省。"""
    entry = tl.TraceLedger(trace_id="S10-NM", profile="annex3-1a").append(
        "biometric_search", {"probe_id": "P-2"}, {"match": False},
        period={"start": "2026-03-01T08:00:00Z", "end": "2026-03-01T08:00:02Z"},
        db_ref="db@1", matched=False, verified_by="op:7721")
    assert "matched_input" not in entry
    assert entry["period"]["end"] == "2026-03-01T08:00:02Z"
