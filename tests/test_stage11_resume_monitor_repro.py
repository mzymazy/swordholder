# -*- coding: utf-8 -*-
"""第十一阶段回归测试：跨进程续写、部署期监控、外部可复现清单。

覆盖用户可感知的三个承诺：
1. 轨迹能跨进程接着写，且**脏历史不得被接着写**（否则新步等于替旧篡改背书）；
2. 部署期能按周期量到「链断了」，且监控日志自己也是链（改一行就拒写）；
3. 交付树能被第三方离线复算，改一个字节 / 改一个计数都必须判失败。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from swordholder import monitor as mn
from swordholder import reproduce as rp
from swordholder import trace_ledger as tl

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ledger(path: str, steps: int = 5, trace_id: str = "T-STAGE11") -> tl.TraceLedger:
    led = tl.TraceLedger(trace_id=trace_id, actor="agent:test")
    for i in range(steps):
        led.append("tool_call_%02d" % i, {"i": i}, {"ok": True})
    led.save(path)
    return led


# --------------------------------------------------------------------------- #
# 1. 跨会话续写：公开入口 from_body / load / save
# --------------------------------------------------------------------------- #

def test_load_restores_body_without_mutation(tmp_path):
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=4)
    again = tl.TraceLedger.load(path)
    assert again.body() == led.body()
    assert again.head == led.head


def test_from_body_accepts_own_body(tmp_path):
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=3)
    clone = tl.TraceLedger.from_body(led.body())
    assert clone.body() == led.body()


def test_from_body_rejects_tampered_history(tmp_path):
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=4)
    body = led.body()
    body["entries"][1]["observation"]["ok"] = False
    with pytest.raises(tl.TraceError) as exc:
        tl.TraceLedger.from_body(body)
    assert str(exc.value).startswith("E_TRACE_LOAD_BROKEN")


def test_load_accepts_wrapped_document(tmp_path):
    """带外壳的凭证文档（body + seal）也要能读回轨迹体——外部交付物常是这种形态。"""
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=3)
    doc = {"body": led.body(), "seal": {"alg": "ed25519", "sig": "00"}}
    doc_path = str(tmp_path / "doc.json")
    with open(doc_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    loaded = tl.TraceLedger.load(doc_path)
    assert loaded.body()["trace_id"] == "T-STAGE11"
    assert loaded.body()["step_count"] == 3


def test_cross_process_resume_keeps_chain(tmp_path):
    """真·另一个进程续写：子进程 load→append→save，父进程复验。"""
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=6)
    head6 = led.head
    code = (
        "import sys\n"
        "from swordholder import trace_ledger as tl\n"
        "l = tl.TraceLedger.load(sys.argv[1])\n"
        "l.append('after_restart', {'i': 6}, {'ok': True})\n"
        "l.save(sys.argv[1])\n"
        "print(l.body()['step_count'])\n"
    )
    res = subprocess.run([sys.executable, "-c", code, path], cwd=REPO,
                         capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "7"
    body = tl.TraceLedger.load(path).body()
    assert body["step_count"] == 7
    assert body["entries"][5]["hash"] == head6
    assert tl.verify_chain(body)["ok"] is True


def test_save_is_atomic_on_existing_file(tmp_path):
    path = str(tmp_path / "t.json")
    led = _ledger(path, steps=2)
    led.append("more", {"i": 2}, {"ok": True})
    led.save(path)
    assert not os.path.exists(path + ".tmp")
    assert tl.TraceLedger.load(path).body()["step_count"] == 3


# --------------------------------------------------------------------------- #
# 2. 部署期持续跟踪：monitor
# --------------------------------------------------------------------------- #

def test_scan_dir_counts_and_no_alert_on_clean_tree(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    for k in range(3):
        _ledger(str(root / ("T%d.trace.json" % k)), trace_id="T-%d" % k)
    res = mn.scan_dir(str(root))
    assert res["metrics"]["traces_total"] == 3
    assert res["metrics"]["verified_ok"] == 3
    assert res["metrics"]["error_rate"] == 0.0
    assert mn.Monitor(str(root))._alerts(res["metrics"]) == []


def test_scan_dir_detects_tamper_and_raises_alert(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    for k in range(3):
        _ledger(str(root / ("T%d.trace.json" % k)), trace_id="T-%d" % k)
    victim = root / "T0.trace.json"
    body = json.loads(victim.read_text(encoding="utf-8"))
    body["entries"][1]["observation"]["ok"] = False
    victim.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    mon = mn.Monitor(str(root))
    rec = mon.scan_once(now="2026-11-09T00:00:00Z")
    assert rec["metrics"]["chain_break"] == 1
    assert "E_MON_CHAIN_BREAK" in [a["code"] for a in rec["alerts"]]
    assert rec["worst_level"] == "critical"


def test_monitor_log_is_chained_and_detects_edit(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _ledger(str(root / "T0.trace.json"), trace_id="T-0")
    mon = mn.Monitor(str(root))
    mon.scan_once(now="2026-11-09T00:00:00Z")
    mon.scan_once(now="2026-11-09T01:00:00Z")
    assert mn.verify_log(mon.log_path)["ok"] is True
    assert mn.verify_log(mon.log_path)["records"] == 2

    lines = open(mon.log_path, "r", encoding="utf-8").read().splitlines()
    rec = json.loads(lines[0])
    rec["metrics"]["traces_total"] = 999
    lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    with open(mon.log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    ver = mn.verify_log(mon.log_path)
    assert ver["ok"] is False
    assert ver["first_break"] == 1
    with pytest.raises(mn.MonitorError) as exc:
        mon.scan_once(now="2026-11-09T02:00:00Z")
    assert str(exc.value).startswith("E_MON_LOG_BROKEN")


def test_monitor_unknown_threshold_rejected(tmp_path):
    with pytest.raises(mn.MonitorError) as exc:
        mn.Monitor(str(tmp_path), thresholds={"chain_braek": 1})  # 拼错必须报错
    assert str(exc.value).startswith("E_MON_THRESHOLD_UNKNOWN")


def test_cli_scan_outputs_json(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    _ledger(str(root / "T0.trace.json"), trace_id="T-0")
    res = subprocess.run([sys.executable, "-m", "swordholder.monitor", "scan",
                          "--dir", str(root)], cwd=REPO,
                         capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0, res.stderr
    doc = json.loads(res.stdout)
    assert doc["schema"] == mn.MONITOR_SCHEMA
    assert doc["records"][0]["metrics"]["verified_ok"] == 1
    assert doc["report"]["log_ok"] is True


# --------------------------------------------------------------------------- #
# 3. 外部可复现：manifest + 纯标准库离线复算
# --------------------------------------------------------------------------- #

def _tree(tmp_path):
    base = tmp_path / "deliver"
    (base / "sub").mkdir(parents=True)
    (base / "a.txt").write_text("alpha\n", encoding="utf-8")
    (base / "sub" / "b.json").write_text('{"b": 1}', encoding="utf-8")
    files = [str(base / "a.txt"), str(base / "sub" / "b.json")]
    return base, files


def test_build_and_verify_manifest_roundtrip(tmp_path):
    base, files = _tree(tmp_path)
    manifest = rp.build_manifest(str(base), files, include_git=False)
    assert manifest["file_count"] == 2
    assert len(manifest["tree_digest"]) == 64
    assert rp.verify_manifest(manifest, str(base))["ok"] is True


def test_verify_manifest_detects_one_byte_change(tmp_path):
    base, files = _tree(tmp_path)
    manifest = rp.build_manifest(str(base), files, include_git=False)
    with open(str(base / "a.txt"), "a", encoding="utf-8") as fh:
        fh.write("x")
    res = rp.verify_manifest(manifest, str(base))
    assert res["ok"] is False
    assert [m["path"] for m in res["mismatched"]] == ["a.txt"]


def test_verify_manifest_detects_missing_file(tmp_path):
    base, files = _tree(tmp_path)
    manifest = rp.build_manifest(str(base), files, include_git=False)
    os.remove(str(base / "sub" / "b.json"))
    res = rp.verify_manifest(manifest, str(base))
    assert res["ok"] is False
    assert res["missing"] == ["sub/b.json"]


def test_path_escape_rejected(tmp_path):
    base, _files = _tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(rp.ReproduceError) as exc:
        rp.file_fingerprint(str(base), str(outside))
    assert str(exc.value).startswith("E_REPRO_PATH_ESCAPE")


def test_compare_expected_flags_divergence():
    res = rp.compare_expected({"PASS": 9}, {"PASS": 7})
    assert res["ok"] is False
    assert res["diverged"][0]["expected"] == 9
    assert rp.compare_expected({"PASS": 9}, {"PASS": 9})["ok"] is True
    assert rp.compare_expected({"PASS": 9}, {})["missing"] == ["PASS"]


def test_external_verify_script_is_stdlib_only():
    """第三方脚本不得引用本包，否则「外部复算」就成了自己验自己。"""
    import ast

    path = os.path.join(REPO, "scripts", "stage11", "external_verify.py")
    mods = set()
    for node in ast.walk(ast.parse(open(path, "r", encoding="utf-8").read())):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    assert "swordholder" not in mods


def test_external_verify_cli_end_to_end(tmp_path):
    base, files = _tree(tmp_path)
    manifest = rp.build_manifest(str(base), files, expected={"PASS": 2}, include_git=False)
    mpath = str(tmp_path / "m.json")
    rp.dump(manifest, mpath)
    actual = str(tmp_path / "actual.json")
    with open(actual, "w", encoding="utf-8") as fh:
        json.dump({"PASS": 2}, fh)
    script = os.path.join(REPO, "scripts", "stage11", "external_verify.py")

    ok = subprocess.run([sys.executable, "-I", script, "--manifest", mpath,
                         "--root", str(base), "--actual", actual],
                        capture_output=True, text=True, encoding="utf-8")
    assert ok.returncode == 0, ok.stdout + ok.stderr

    with open(actual, "w", encoding="utf-8") as fh:
        json.dump({"PASS": 1}, fh)
    bad = subprocess.run([sys.executable, "-I", script, "--manifest", mpath,
                          "--root", str(base), "--actual", actual],
                         capture_output=True, text=True, encoding="utf-8")
    assert bad.returncode == 1
