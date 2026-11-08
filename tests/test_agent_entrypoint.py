# -*- coding: utf-8 -*-
"""agent_loop 命令行入口与落盘失败分支的测试。

为什么要有这一层：
    run_agent 的判定路径已被 test_agent_loop / test_agent_ledger 覆盖，但"人怎么
    真的跑起来"（main 的 argv 解析、告警文件读取、trace 落盘、摘要打印）一直没测。
    命令行是陌生人接触这个项目的第一入口，它坏掉时库层面的 400 多个用例全绿也没用。

同时钉住三条"失败不静默"的口径：
    - 会话状态写不进去 → trace["session_save_error"]；
    - 账本签章写不进去 → trace["ledger"]["seal_error"]；
    - 告警既不是已知 EDR 格式、也不是规范 JSON → 必须报错退出，不能猜。
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import agent_loop as al  # noqa: E402

ALERT = {
    "alert_id": "ALRT-E-0001",
    "title": "Build runner made outbound TLS to unknown ASN",
    "asset": "build-runner-07",
    "severity": "high",
    "signal": "unexpected outbound TLS to unknown ASN 215199",
    "description": "构建机向未登记 ASN 建立长连接。",
    "observed": {"first_seen": "2026-11-02T03:14:00Z"},
}

PROBES = [
    {"thought": "先看资产画像", "action": "get_asset_profile", "args": {"asset": "build-runner-07"}},
    {"thought": "再看主机外联", "action": "get_process_tree", "args": {"host": "build-runner-07"}},
]
SUBMIT = {"thought": "证据充分，提交判定", "action": "submit_verdict", "args": {
    "verdict": "true_positive", "severity": "high", "confidence": 0.86,
    "hypothesis": "构建机向基线外 ASN 发起 TLS 并持有 CI token，疑似凭据外泄后的外联。",
    "actions": ["阻断目标 ASN 出站", "吊销并轮换 CI token"],
    "evidence_refs": ["step.1", "step.2"],
}}


@pytest.fixture()
def scripted(monkeypatch):
    """把 LLM 换成本地脚本序列，命令行用例不得真的去连模型服务。"""
    seq = list(PROBES + [SUBMIT])

    def fake(system, prompt, cfg=None, timeout=90):
        item = seq.pop(0) if seq else {}
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    monkeypatch.setattr(al, "call_llm", fake)
    monkeypatch.setenv("SWORDHOLDER_LLM_PROVIDER", "ollama")
    return seq


def _alert_file(tmp_path, name="alert.json"):
    p = tmp_path / name
    p.write_text(json.dumps(ALERT, ensure_ascii=False), encoding="utf-8")
    return str(p)


# --------------------------------------------------------------- 正常跑通一遍
def test_main_writes_trace_and_prints_summary(tmp_path, scripted, capsys):
    out = str(tmp_path / "out" / "trace.json")
    rc = al.main([_alert_file(tmp_path), "--out", out])
    assert rc == 0
    assert os.path.exists(out)
    with open(out, encoding="utf-8") as f:
        trace = json.load(f)
    assert trace["verdict"] == "true_positive"
    assert trace["alert_id"] == "ALRT-E-0001"
    # trace 里必须有账本自校验结论，否则"这次运行自洽"只是口头声明
    assert trace["ledger"]["check"]["ok"] is True
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert set(summary) == {"alert_id", "verdict", "engine", "sealed"}
    assert summary["sealed"] is False


def test_main_without_out_only_prints_summary(tmp_path, scripted, capsys):
    rc = al.main([_alert_file(tmp_path)])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["verdict"] == "true_positive"


def test_main_accepts_max_steps_flag(tmp_path, scripted, capsys):
    rc = al.main([_alert_file(tmp_path), "--max-steps", "2"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    # 只给 2 步时模型来不及提交判定，必须回落规则层而不是硬凑结论
    assert summary["engine"].endswith("(agent-fallback)")


def test_main_reads_conversation_and_writes_session(tmp_path, scripted, capsys):
    conv = tmp_path / "conv.json"
    conv.write_text(json.dumps([{"role": "user", "content": "这台构建机我上周刚重装过。"}],
                               ensure_ascii=False), encoding="utf-8")
    sess_out = str(tmp_path / "sess.json")
    rc = al.main([_alert_file(tmp_path), "--conversation", str(conv), "--session-out", sess_out])
    assert rc == 0
    assert os.path.exists(sess_out)
    body = json.loads(open(sess_out, encoding="utf-8").read())
    assert body["session_id"]
    assert body["turns"]


def test_main_rejects_non_list_conversation(tmp_path, scripted):
    conv = tmp_path / "conv.json"
    conv.write_text(json.dumps({"role": "user"}), encoding="utf-8")
    with pytest.raises(SystemExit):
        al.main([_alert_file(tmp_path), "--conversation", str(conv)])


def test_main_continues_an_existing_session(tmp_path, scripted, capsys):
    """--session 指向已有会话文件时，新一轮判定必须接着同一个会话往下走。"""
    from swordholder import session as session_mod

    sess = session_mod.SessionState()
    sess_path = str(tmp_path / "prev.json")
    sess.save(sess_path)
    rc = al.main([_alert_file(tmp_path), "--session", sess_path])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["verdict"] == "true_positive"


def test_main_falls_back_to_plain_json_alert(tmp_path, scripted, capsys):
    """非 EDR 原始格式的裸告警 JSON 也要能跑（normalize 兜底路径）。"""
    rc = al.main([_alert_file(tmp_path, "plain.json")])
    assert rc == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["alert_id"] == "ALRT-E-0001"


# ------------------------------------------------------- 失败必须留痕而非静默
def _run_agent(monkeypatch, **kw):
    seq = list(PROBES + [SUBMIT])

    def fake(system, prompt, cfg=None, timeout=90):
        item = seq.pop(0) if seq else {}
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    monkeypatch.setattr(al, "call_llm", fake)
    from swordholder.alert import normalize
    return al.run_agent(normalize(ALERT),
                        cfg={"provider": "scripted", "model": "s", "base": "", "api_key": ""}, **kw)


def test_session_save_failure_is_reported(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    trace = _run_agent(monkeypatch, session_out=str(blocker / "sub" / "sess.json"))
    assert trace["verdict"] == "true_positive"
    assert trace["session_save_error"]
    assert "session_path" not in trace


def test_ledger_seal_failure_is_reported(monkeypatch, tmp_path):
    """账本要盖章但目标目录建不出来：判定结论不受影响，失败原因必须写进 trace。"""
    from swordholder import core

    keys = core.keygen(str(tmp_path / "keys"))
    blocker = tmp_path / "blocker2"
    blocker.write_text("not a dir", encoding="utf-8")
    trace = _run_agent(monkeypatch, key_path=keys["private_key_path"],
                       ledger_seal_out=str(blocker / "x.seal.json"))
    assert trace["verdict"] == "true_positive"
    assert trace["sealed"] is True
    assert trace["ledger"]["seal_error"]
    assert "seal" not in trace["ledger"]


def test_executed_export_is_replayable(monkeypatch):
    """同一轨迹 replay 的前提：executed 必须落进 trace 且能原样 JSON 化。"""
    trace = _run_agent(monkeypatch)
    assert set(trace["executed"]) == {"1", "2"}
    json.dumps(trace["executed"], ensure_ascii=False)
