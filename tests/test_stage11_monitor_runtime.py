# -*- coding: utf-8 -*-
"""monitor 运行期分支回归：坏文件、形状错误、摘要篡改、日志链与 CLI 入口。

``test_stage11_resume_monitor_repro.py`` 覆盖的是主干承诺（干净树能扫到数、篡改能被抓、
日志链能拒写）。本文件补的是同一批承诺的**异常与边界分支**，部署现场真正会撞上的那些：

- 轨迹目录里混进半截文件、非轨迹 JSON、已被删掉的文件；
- 有人把 entries 改完顺手把 step_count / head 也改齐（链自洽但摘要对不上）；
- 监控日志自身带空行、或第 n 条被换掉时能否定位到具体行；
- ``watch`` / ``report`` / CLI 三个公开入口的周期、切片与返回码。

其中 sealed 轨迹一个用例挂 ``xfail(strict=True)``：monitor 调 ``verify_sealed_trace`` 时
没有传 ``seal_path``，任何带封签的轨迹当前都会被判成 ``E_MON_SEAL_INVALID``。这是
**已知缺陷**，不该被"补测"悄悄固化成正确行为——修好后该用例会 XPASS 转红，提醒更新断言。
"""

from __future__ import annotations

import json

import pytest

from swordholder import monitor as mn
from swordholder import trace_ledger as tl


def _body(path: str, steps: int = 3, trace_id: str = "T-MON") -> dict:
    led = tl.TraceLedger(trace_id=trace_id, actor="agent:test")
    for i in range(steps):
        led.append("step_%02d" % i, {"i": i}, {"ok": True})
    led.save(path)
    return led.body()


def _write(path: str, payload) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False))
    return path


def _codes(result: dict) -> list[str]:
    return [p["code"] for p in result["problems"]]


# --------------------------------------------------------------------------- #
# 1. 单文件判定：坏输入一律给固定码，不抛异常
# --------------------------------------------------------------------------- #

def test_evaluate_trace_reports_missing_file(tmp_path):
    res = mn.evaluate_trace(str(tmp_path / "gone.trace.json"))
    assert res["ok"] is False
    assert _codes(res) == ["E_MON_UNREADABLE"]
    assert res["problems"][0]["detail"] == "文件不存在"


def test_evaluate_trace_reports_unparsable_json(tmp_path):
    path = _write(str(tmp_path / "half.trace.json"), '{"entries": [')
    res = mn.evaluate_trace(path)
    assert _codes(res) == ["E_MON_UNREADABLE"]
    assert res["problems"][0]["detail"].startswith("无法解析 JSON")


def test_evaluate_trace_rejects_non_trace_document(tmp_path):
    """不是轨迹的 JSON（缺 trace_id）必须被单独标成形状错误，而不是混进链断裂。"""
    path = _write(str(tmp_path / "other.trace.json"), {"hello": "world"})
    res = mn.evaluate_trace(path)
    assert _codes(res) == ["E_MON_SHAPE"]
    assert res["trace_id"] is None
    assert res["ok"] is False


def test_evaluate_trace_accepts_wrapped_document(tmp_path):
    """带外壳的交付物（body 嵌在 doc.body）要看内层轨迹体，且外壳无封签即 sealed=False。"""
    body = _body(str(tmp_path / "t.json"), steps=4)
    path = _write(str(tmp_path / "wrapped.trace.json"), {"body": body})
    res = mn.evaluate_trace(path)
    assert res["ok"] is True
    assert res["sealed"] is False
    assert res["trace_id"] == "T-MON"
    assert res["step_count"] == 4


def test_evaluate_trace_detects_digest_mismatch(tmp_path):
    """链自洽但 body_digest 与重算值不符——改完顺手改齐 step_count/head 的那种。"""
    body = _body(str(tmp_path / "t.json"), steps=3)
    body["body_digest"] = "0" * 64
    path = _write(str(tmp_path / "dig.trace.json"), body)
    res = mn.evaluate_trace(path)
    assert _codes(res) == ["E_MON_DIGEST_MISMATCH"]


def test_evaluate_trace_flags_inline_seal_as_invalid(tmp_path):
    """内联封签、旁边没有 .seal.json 时，当前实现只能给 E_MON_SEAL_INVALID。"""
    body = _body(str(tmp_path / "t.json"), steps=2)
    path = _write(str(tmp_path / "sealed.trace.json"),
                  {"body": body, "seal": {"alg": "ed25519", "sig": "00"}})
    res = mn.evaluate_trace(path)
    assert res["sealed"] is True
    assert "E_MON_SEAL_INVALID" in _codes(res)


@pytest.mark.xfail(strict=True,
                   reason="monitor 调 tl.verify_sealed_trace(doc) 时没传 seal_path，"
                          "带封签的轨迹一律走参数异常分支而被判无效（待修）")
def test_sealed_trace_not_failed_by_missing_seal_path_argument(tmp_path):
    body = _body(str(tmp_path / "t.json"), steps=2)
    path = _write(str(tmp_path / "sealed2.trace.json"),
                  {"body": body, "seal": {"alg": "ed25519", "sig": "00"}})
    res = mn.evaluate_trace(path)
    details = " ".join(p["detail"] for p in res["problems"])
    assert "seal_path" not in details


# --------------------------------------------------------------------------- #
# 2. 目录扫描：问题分类计数与目录不存在
# --------------------------------------------------------------------------- #

def test_scan_dir_missing_root_raises(tmp_path):
    with pytest.raises(mn.MonitorError) as exc:
        mn.scan_dir(str(tmp_path / "nope"))
    assert str(exc.value).startswith("E_MON_DIR_MISSING")


def test_scan_dir_counts_every_problem_class(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "ok.trace.json"), trace_id="T-OK")
    _write(str(root / "half.trace.json"), "{oops")
    _write(str(root / "other.trace.json"), {"hello": 1})

    dig = _body(str(tmp_path / "dig.json"), trace_id="T-DIG")
    dig["body_digest"] = "0" * 64
    _write(str(root / "dig.trace.json"), dig)

    sealed = _body(str(tmp_path / "seal.json"), trace_id="T-SEAL")
    _write(str(root / "seal.trace.json"), {"body": sealed, "seal": {"alg": "ed25519"}})

    broken = _body(str(tmp_path / "broken.json"), trace_id="T-BRK")
    broken["entries"][1]["observation"]["ok"] = False
    _write(str(root / "chain.trace.json"), broken)

    metrics = mn.scan_dir(str(root))["metrics"]
    assert metrics["traces_total"] == 6
    assert metrics["verified_ok"] == 1
    assert metrics["failed"] == 5
    assert metrics["chain_break"] == 1
    assert metrics["digest_mismatch"] == 1
    assert metrics["seal_invalid"] == 1
    assert metrics["unreadable"] == 2
    assert metrics["error_rate"] == round(5 / 6, 6)

    # 失败率超阈值也要单独成一条告警，不能只报具体类别
    codes = [a["code"] for a in mn.Monitor(str(root))._alerts(metrics)]
    assert "E_MON_ERROR_RATE" in codes
    assert codes.index("E_MON_ERROR_RATE") > 0


# --------------------------------------------------------------------------- #
# 3. 监控日志自身的链
# --------------------------------------------------------------------------- #

def test_verify_log_missing_file(tmp_path):
    ver = mn.verify_log(str(tmp_path / "nope.jsonl"))
    assert ver["ok"] is False
    assert ver["records"] == 0
    assert ver["reason"].startswith("日志不存在")


def test_verify_log_tolerates_blank_lines(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "T0.trace.json"))
    mon = mn.Monitor(str(root))
    mon.scan_once(now="2026-11-10T00:00:00Z")
    mon.scan_once(now="2026-11-10T01:00:00Z")

    lines = open(mon.log_path, "r", encoding="utf-8").read().splitlines()
    with open(mon.log_path, "w", encoding="utf-8") as fh:
        fh.write(lines[0] + "\n\n" + lines[1] + "\n\n")

    ver = mn.verify_log(mon.log_path)
    assert ver["ok"] is True
    assert ver["records"] == 2


def test_verify_log_locates_replaced_record(tmp_path):
    """第 2 条被换成另一条（prev 不接上）时，first_break 必须指到第 2 行。"""
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "T0.trace.json"))
    mon = mn.Monitor(str(root))
    mon.scan_once(now="2026-11-10T00:00:00Z")
    mon.scan_once(now="2026-11-10T01:00:00Z")

    lines = open(mon.log_path, "r", encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["prev"] = "1" * 64
    lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    with open(mon.log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    ver = mn.verify_log(mon.log_path)
    assert ver["ok"] is False
    assert ver["first_break"] == 2
    assert "prev" in ver["reason"]


def test_verify_log_reports_read_failure(tmp_path):
    """把目录当日志传进来：不许抛裸异常，要返回结构化失败。"""
    ver = mn.verify_log(str(tmp_path))
    assert ver["ok"] is False
    assert ver["records"] == 0
    assert ver["reason"].startswith("读取失败")


def test_read_log_handles_absent_and_blank_lines(tmp_path):
    assert mn.read_log(str(tmp_path / "nope.jsonl")) == []
    path = tmp_path / "log.jsonl"
    path.write_text('{"n": 1}\n\n{"n": 2}\n', encoding="utf-8")
    assert [r["n"] for r in mn.read_log(str(path))] == [1, 2]


# --------------------------------------------------------------------------- #
# 4. Monitor 配置与周期
# --------------------------------------------------------------------------- #

def test_monitor_requires_root(tmp_path):
    with pytest.raises(mn.MonitorError) as exc:
        mn.Monitor("")
    assert str(exc.value).startswith("E_MON_DIR_MISSING")


def test_monitor_applies_known_thresholds(tmp_path):
    mon = mn.Monitor(str(tmp_path), thresholds={"error_rate": 0.5, "unreadable": 2})
    assert mon.thresholds["error_rate"] == 0.5
    assert mon.thresholds["unreadable"] == 2
    assert mon.thresholds["chain_break"] == 0


def test_watch_rejects_non_positive_cycles(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    with pytest.raises(mn.MonitorError) as exc:
        mn.Monitor(str(root)).watch(cycles=0)
    assert str(exc.value).startswith("E_MON_CYCLES_INVALID")


def test_watch_scans_each_cycle_and_sleeps_between(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "T0.trace.json"))
    slept: list[float] = []
    records = mn.Monitor(str(root)).watch(cycles=3, interval=7.5,
                                          sleep=lambda s: slept.append(s))
    assert [r["n"] for r in records] == [1, 2, 3]
    assert records[1]["prev"] == records[0]["hash"]
    assert slept == [7.5, 7.5]


# --------------------------------------------------------------------------- #
# 5. 汇总与 CLI
# --------------------------------------------------------------------------- #

def test_report_on_empty_log(tmp_path):
    rep = mn.Monitor(str(tmp_path)).report()
    assert rep["records"] == 0
    assert rep["log_ok"] is False
    assert rep["alerts_total"] == 0
    assert rep["by_code"] == {}
    assert rep["latest"] is None


def test_report_slices_window_and_counts_alert_codes(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "T0.trace.json"))
    _write(str(root / "bad.trace.json"), "{oops")
    mon = mn.Monitor(str(root))
    mon.scan_once(now="2026-11-10T00:00:00Z")
    mon.scan_once(now="2026-11-10T01:00:00Z")

    rep = mon.report(last=1)
    assert rep["records"] == 1
    assert rep["log_ok"] is True
    assert rep["first_ts"] == "2026-11-10T01:00:00Z"
    assert rep["by_code"]["E_MON_UNREADABLE"] == 1
    assert rep["by_code"]["E_MON_ERROR_RATE"] == 1
    assert rep["alerts_total"] == 2
    assert rep["latest_metrics"]["failed"] == 1

    full = mon.report()
    assert full["records"] == 2
    assert full["by_code"]["E_MON_UNREADABLE"] == 2


def test_cli_scan_report_and_verify_log(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _body(str(root / "T0.trace.json"))

    scan_out = tmp_path / "scan.json"
    assert mn.main(["scan", "--dir", str(root), "--json-out", str(scan_out)]) == 0
    doc = json.loads(scan_out.read_text(encoding="utf-8"))
    assert doc["schema"] == mn.MONITOR_SCHEMA
    assert doc["report"]["log_ok"] is True

    log = str(root / "monitor_log.jsonl")
    rep_out = tmp_path / "rep.json"
    assert mn.main(["report", "--log", log, "--last", "1",
                    "--json-out", str(rep_out)]) == 0
    assert json.loads(rep_out.read_text(encoding="utf-8"))["records"] == 1

    # 只给 --dir 时日志路径由目录推导
    assert mn.main(["report", "--dir", str(root)]) == 0
    # 日志不存在 → payload.ok=False → 返回码 2
    assert mn.main(["verify-log", "--log", str(tmp_path / "nope.jsonl")]) == 2
    assert mn.main(["verify-log", "--log", log]) == 0
