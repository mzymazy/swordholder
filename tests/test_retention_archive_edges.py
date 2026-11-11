# -*- coding: utf-8 -*-
"""归档副本的边角：重复归档必须拒、副本校验的失败原因必须能分清。

归档是「拷出去之后仍能证明是不是当初那份」的唯一凭据。若重复归档被静默覆盖，
或者 chain / digest / body 三种损坏被同一句话带过，事后就无从追责。
"""

from __future__ import annotations

import json

import pytest

from swordholder import retention as rt, trace_ledger as tl

POLICY = rt.RetentionPolicy(label="参赛留档", days=400, rotation="year",
                            archive_subdir="archive")
NOW = "2028-01-01T00:00:00Z"


@pytest.fixture()
def body():
    led = tl.TraceLedger(trace_id="TR-ARC", actor="qwen3:8b")
    for i in range(3):
        led.append("tool_%d" % i, {"i": i}, {"ok": True},
                   ts="2026-11-13T10:0%d:00Z" % i)
    return led.body()


def test_archive_twice_is_refused(tmp_path, body):
    first = rt.archive_record(body, str(tmp_path / "root"), POLICY, now=NOW)
    assert first["verified"]["ok"] is True
    with pytest.raises(rt.RetentionError, match="E_RETENTION_ARCHIVE_EXISTS"):
        rt.archive_record(body, str(tmp_path / "root"), POLICY, now=NOW)


def test_archive_requires_start_ts_and_right_policy(tmp_path, body):
    with pytest.raises(rt.RetentionError, match="E_RETENTION_POLICY_INVALID"):
        rt.archive_record(body, str(tmp_path), object(), now=NOW)  # type: ignore[arg-type]
    with pytest.raises(rt.RetentionError, match="E_RETENTION_POLICY_INVALID"):
        rt.classify("2026-11-13T10:00:00Z", object())  # type: ignore[arg-type]

    empty = tl.TraceLedger(trace_id="TR-EMPTY").body()
    empty.pop("start_ts", None)
    with pytest.raises(rt.RetentionError, match="E_RETENTION_TS_INVALID"):
        rt.archive_record(empty, str(tmp_path / "r2"), POLICY, now=NOW)


def test_rotation_keys():
    assert POLICY.rotation_key("2026-11-13T10:00:00Z") == "2026"
    monthly = rt.RetentionPolicy(label="m", days=400, rotation="month")
    assert monthly.rotation_key("2026-11-13T10:00:00Z") == "2026-11"
    single = rt.RetentionPolicy(label="n", days=400, rotation="none")
    assert single.rotation_key("2026-11-13T10:00:00Z") == "all"


def test_verify_archive_missing_unreadable_schema(tmp_path):
    missing = rt.verify_archive(str(tmp_path / "ghost.json"))
    assert missing["ok"] is False and missing["reason"] == "E_RETENTION_ARCHIVE_MISSING"

    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    res = rt.verify_archive(str(broken))
    assert res["reason"].startswith("E_RETENTION_ARCHIVE_UNREADABLE")

    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"schema": "other/1"}), encoding="utf-8")
    assert rt.verify_archive(str(wrong))["reason"].startswith(
        "E_RETENTION_ARCHIVE_SCHEMA")

    nobody = tmp_path / "nobody.json"
    nobody.write_text(json.dumps({"schema": rt.ARCHIVE_SCHEMA}), encoding="utf-8")
    assert rt.verify_archive(str(nobody))["reason"].endswith("缺少 body")


def test_verify_archive_distinguishes_chain_digest_and_body_breaks(tmp_path, body):
    rec = rt.archive_record(body, str(tmp_path / "root"), POLICY, now=NOW)
    good = rt.verify_archive(rec["path"])
    assert good["ok"] is True and good["chain_ok"] is True
    assert good["digest_match"] is True and good["body_sha256_match"] is True

    def _mutate(fn):
        doc = json.load(open(rec["path"], encoding="utf-8"))
        fn(doc)
        bad = tmp_path / ("bad_%d.json" % abs(hash(fn.__name__)))
        bad.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        return rt.verify_archive(str(bad))

    def break_chain(doc):
        doc["body"]["entries"][1]["observation"]["ok"] = False

    def break_digest(doc):
        doc["digest"] = "0" * 64

    def break_body_sha(doc):
        doc["body_sha256"] = "f" * 64

    assert _mutate(break_chain)["reason"].startswith("E_RETENTION_ARCHIVE_CHAIN")
    assert _mutate(break_digest)["reason"] == "E_RETENTION_ARCHIVE_DIGEST_MISMATCH"
    assert _mutate(break_body_sha)["reason"] == "E_RETENTION_ARCHIVE_BODY_MISMATCH"
