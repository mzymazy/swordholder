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


# ---------------------------------------------------------------- 3. 字段进链
def test_period_end_tamper_breaks_chain_at_that_step():
    body = copy.deepcopy(_annex(3).body())
    body["entries"][1]["period"]["end"] = "2031-01-01T00:00:00Z"
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 1


def test_db_ref_and_identity_tamper_both_break_chain():
    for field, value in (("db_ref", "other-db@2026.09.01"),
                         ("identity_check", {"verifier": "op:0000", "method": "none",
                                             "at": "2026-03-01T08:00:00Z"})):
        body = copy.deepcopy(_annex(3).body())
        body["entries"][2][field] = value
        res = tl.verify_chain(body)
        assert res["ok"] is False, field
        assert res["first_break"] == 2, field


def test_sealed_annex_trace_reports_invalid_with_step_segment(tmp_path, keys):
    body = _annex(3).body()
    trust = _trust(tmp_path, keys["public_key_hex"])
    seal = tl.seal_trace(body, keys["private_key_path"], issuer="test",
                         out_path=str(tmp_path / "a3.seal.json"))
    assert tl.verify_sealed_trace(body, seal["seal_path"], keys_path=trust)["verdict"] == "VALID"

    tampered = copy.deepcopy(body)
    tampered["entries"][1]["period"]["end"] = "2031-01-01T00:00:00Z"
    bad = tl.verify_sealed_trace(tampered, seal["seal_path"], keys_path=trust)
    assert bad["verdict"] == "INVALID"
    assert bad["reason"].startswith("E_TRACE_BREAK")
    assert bad["localization"]["mode"] == "chain"
    assert bad["localization"]["segment"] == [1, 1]


def test_profile_downgrade_breaks_digest(tmp_path, keys):
    """把 profile 键删掉冒充普通轨迹，摘要必须对不上——档位声明也被凭证锁住。"""
    body = _annex(2).body()
    trust = _trust(tmp_path, keys["public_key_hex"])
    seal = tl.seal_trace(body, keys["private_key_path"], issuer="test",
                         out_path=str(tmp_path / "a3d.seal.json"))
    downgraded = copy.deepcopy(body)
    downgraded.pop("profile")
    assert tl.verify_chain(downgraded)["ok"] is True, "档位不在链里，链本身仍自洽"
    bad = tl.verify_sealed_trace(downgraded, seal["seal_path"], keys_path=trust)
    assert bad["verdict"] == "INVALID"
    assert bad["reason"] == "E_TRACE_DIGEST_MISMATCH"


# ---------------------------------------------------------------- 4. 留存期下限
def test_floor_constant_is_at_least_six_months():
    assert rt.MIN_RETENTION_DAYS >= 180


@pytest.mark.parametrize("days", [0, 30, 179, 180])
def test_policy_below_floor_rejected(days):
    with pytest.raises(rt.RetentionError) as exc:
        rt.RetentionPolicy(days=days)
    assert "E_RETENTION_BELOW_FLOOR" in str(exc.value)


def test_policy_ttl_seconds():
    pol = rt.RetentionPolicy(days=190)
    assert pol.ttl_seconds == 190 * 86400
    assert pol.to_dict()["min_days_floor"] == rt.MIN_RETENTION_DAYS


def test_policy_rejects_bad_rotation_and_empty_subdir():
    with pytest.raises(rt.RetentionError):
        rt.RetentionPolicy(days=190, rotation="week")
    with pytest.raises(rt.RetentionError):
        rt.RetentionPolicy(days=190, archive_subdir="  ")


def test_classify_retained_vs_archive_due():
    pol = rt.RetentionPolicy(days=190)
    now = "2026-11-09T00:00:00Z"
    fresh = rt.classify("2026-10-11T00:00:00Z", pol, now=now)   # 29 天
    mature = rt.classify("2026-02-10T00:00:00Z", pol, now=now)  # 272 天
    assert fresh["state"] == "retained"
    assert fresh["meets_legal_floor"] is False
    assert mature["state"] == "archive_due"
    assert mature["meets_legal_floor"] is True
    assert mature["age_days"] > pol.days


def test_classify_rejects_missing_or_future_ts():
    pol = rt.RetentionPolicy(days=190)
    with pytest.raises(rt.RetentionError):
        rt.classify(None, pol)
    with pytest.raises(rt.RetentionError):
        rt.classify("2026-11-09T00:00:00Z", pol, now="2026-01-01T00:00:00Z")


def test_plan_splits_two_groups():
    pol = rt.RetentionPolicy(days=190)
    head64 = "0" * 64
    bodies = [{"trace_id": "T-FRESH", "start_ts": "2026-10-11T00:00:00Z",
               "step_count": 1, "head": head64, "entries": []},
              {"trace_id": "T-OLD", "start_ts": "2026-02-10T00:00:00Z",
               "step_count": 2, "head": "1" * 64, "entries": []}]
    res = rt.plan(bodies, pol, now="2026-11-09T00:00:00Z")
    assert res["total"] == 2 and res["retained"] == 1 and res["archive_due"] == 1
    states = {r["trace_id"]: r["state"] for r in res["records"]}
    assert states == {"T-FRESH": "retained", "T-OLD": "archive_due"}
    assert res["records"][1]["rotation"] == "2026-02"


# ---------------------------------------------------------------- 5. 归档只写副本
def test_archive_writes_verifiable_copy_and_keeps_original(tmp_path):
    pol = rt.RetentionPolicy(days=190)
    body = _plain(3, trace_id="S10-ARCH").body()
    body["start_ts"] = "2026-02-10T00:00:00Z"
    before = copy.deepcopy(body)
    res = rt.archive_record(body, str(tmp_path / "store"), pol, now="2026-11-09T00:00:00Z")
    assert res["verified"]["ok"] is True
    assert res["verified"]["chain_ok"] is True
    assert res["verified"]["digest_match"] is True
    assert body == before, "归档不得改动原轨迹体"
    assert res["state"]["state"] == "archive_due"


def test_archive_copy_tamper_detected(tmp_path):
    pol = rt.RetentionPolicy(days=190)
    body = _plain(3, trace_id="S10-ARCH-T").body()
    body["start_ts"] = "2026-02-10T00:00:00Z"
    res = rt.archive_record(body, str(tmp_path / "store"), pol, now="2026-11-09T00:00:00Z")
    doc = json.loads(open(res["path"], encoding="utf-8").read())
    doc["body"]["entries"][2]["args"]["i"] = 99
    with open(res["path"], "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, sort_keys=True, indent=1)
    bad = rt.verify_archive(res["path"])
    assert bad["ok"] is False
    assert "E_RETENTION_ARCHIVE_CHAIN" in bad["reason"]


def test_archive_too_early_rejected(tmp_path):
    pol = rt.RetentionPolicy(days=190)
    body = _plain(2, trace_id="S10-ARCH-EARLY").body()
    body["start_ts"] = "2026-10-11T00:00:00Z"
    with pytest.raises(rt.RetentionError) as exc:
        rt.archive_record(body, str(tmp_path / "store"), pol, now="2026-11-09T00:00:00Z")
    assert "E_RETENTION_TOO_EARLY" in str(exc.value)


def test_archive_refuses_broken_chain(tmp_path):
    pol = rt.RetentionPolicy(days=190)
    body = _plain(2, trace_id="S10-ARCH-BROKEN").body()
    body["start_ts"] = "2026-02-10T00:00:00Z"
    body["entries"][0]["observation"]["ok"] = False
    with pytest.raises(rt.RetentionError):
        rt.archive_record(body, str(tmp_path / "store"), pol, now="2026-11-09T00:00:00Z")


def test_module_exposes_no_delete_api():
    """留存模块只负责保留与归档，不提供任何删除入口——到期可归档 ≠ 可销毁。"""
    banned = ("delete", "purge", "destroy", "remove", "unlink", "prune", "shred")
    names = [n for n in dir(rt) if not n.startswith("_")]
    offenders = [n for n in names if any(b in n.lower() for b in banned)]
    assert offenders == [], "retention 模块不应暴露删除类接口，发现：%r" % (offenders,)


def test_archive_record_never_unlinks_source(tmp_path):
    """归档后原轨迹体必须仍在原处：函数只写副本。"""
    pol = rt.RetentionPolicy(days=190)
    body = _plain(2, trace_id="S10-KEEP").body()
    body["start_ts"] = "2026-02-10T00:00:00Z"
    src = tmp_path / "live_trace.json"
    src.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    rt.archive_record(body, str(tmp_path / "store"), pol, now="2026-11-09T00:00:00Z")
    assert src.exists()
