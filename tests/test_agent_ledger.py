# -*- coding: utf-8 -*-
"""动作账本「接入 agent_loop 真实执行路径」的回归测试。

与 tests/test_trace_ledger.py 的分工：
    - 那边测的是账本**模块本身**（链算法、四类篡改、盖章三段式）；
    - 这边测的是**接线**：run_agent 真跑一遍，链里到底有没有每一步动作、
      数得对不对、能不能离线复核、被拒收的提交有没有留下痕迹。

守五条：
    1. 实跑轨迹每一步都入链，且顺序与 trace["steps"] 一一对应；
    2. 账本自身在运行结束时就通过 verify_chain（不是"看起来对"）；
    3. 改一条观测 / 删一步 → 首断点定位到那一步；
    4. 模型没能给判定（走规则兜底）时，轨迹同样完整、同样可验；
    5. 落盘账本可离线复核，盖章后可被 verify_sealed_trace 判 VALID。
"""

import copy
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import agent_loop as al  # noqa: E402
from swordholder import core, trace_ledger as tl, trust  # noqa: E402
from swordholder.alert import normalize  # noqa: E402

# 两次取证的固定脚本：账本要证明的是"这两次工具调用真的发生过且被记下"，
# 所以驱动脚本必须与断言一一对应，不能靠模型随机性。
TWO_PROBES = [
    {"thought": "先看资产画像", "action": "get_asset_profile", "args": {"asset": "build-runner-07"}},
    {"thought": "再看主机外联", "action": "get_process_tree", "args": {"host": "build-runner-07"}},
]


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _alert(**over):
    base = {
        "alert_id": "ALRT-L-0001",
        "title": "Build runner made outbound TLS to unknown ASN",
        "asset": "build-runner-07",
        "severity": "high",
        "signal": "unexpected outbound TLS to unknown ASN 215199",
        "tags": ["egress", "ci"],
        "description": "构建机向未登记 ASN 建立长连接。",
        "observed": {"first_seen": "2026-11-02T03:14:00Z", "connections": 6},
    }
    base.update(over)
    return normalize(base)


def _submit(**over):
    args = {
        "verdict": "true_positive",
        "severity": "high",
        "confidence": 0.86,
        "hypothesis": "构建机向基线外 ASN 发起 TLS 并持有 CI token，疑似凭据外泄后的外联。",
        "actions": ["阻断目标 ASN 出站", "吊销并轮换 CI token", "回溯 7 天该 token 调用记录"],
        "evidence_refs": ["step.1", "step.2"],
    }
    args.update(over)
    return {"thought": "证据充分，提交判定", "action": "submit_verdict", "args": args}


def _run(monkeypatch, script, **kw):
    seq = list(script)

    def fake_call_llm(system, prompt, cfg=None, timeout=90):
        if not seq:
            return "{}"
        item = seq.pop(0)
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    monkeypatch.setattr(al, "call_llm", fake_call_llm)
    cfg = {"provider": "scripted", "model": "scripted-1", "base": "", "api_key": ""}
    return al.run_agent(_alert(), cfg=cfg, **kw)


def _actions(trace):
    return [e["action"] for e in trace["ledger"]["entries"]]


# ------------------------------------------------------------------ 入链完整性
def test_every_step_of_a_real_run_is_in_the_chain(monkeypatch):
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    led = trace["ledger"]
    assert trace["verdict"] == "true_positive"
    # 账本条目 = 两步环境动作（策略解析 / 会话开启）+ 模型每一步；
    # 给了 -k 时末尾再多一条 agent:seal（见 test_sealed_ledger_passes_three_stage_verification）
    assert _actions(trace)[:2] == ["policy_resolve", "session_open"]
    assert _actions(trace)[2:] == [s["action"] for s in trace["steps"]]
    assert led["step_count"] == len(led["entries"])
    assert led["trace_id"] == "ALRT-L-0001"
    assert led["actor"] == trace["engine"]
    assert tl.verify_chain(led)["ok"] is True, led["check"]["reason"]
    assert tl.verify_chain(led)["first_break"] is None


def test_step_numbering_and_hash_links_are_consistent(monkeypatch):
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    entries = trace["ledger"]["entries"]
    prev = tl.GENESIS
    for i, e in enumerate(entries):
        assert e["n"] == i
        assert e["prev"] == prev
        assert e["hash"] == tl.entry_hash(e, prev)   # 逐项重算，不靠"存下来就是对的"
        prev = e["hash"]
    assert trace["ledger"]["head"] == prev


def test_ledger_observation_digest_matches_the_real_tool_result(monkeypatch):
    """账本存的是摘要：摘要必须能对上 trace["steps"] 里的全文。"""
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    entries = trace["ledger"]["entries"]
    probes = [s for s in trace["steps"] if s["action"] == "get_asset_profile"]
    assert probes, trace["steps"]
    step = probes[0]
    idx = 2 + [s["action"] for s in trace["steps"]].index("get_asset_profile")
    obs = entries[idx]["observation"]
    text = json.dumps(step["result"], ensure_ascii=False, sort_keys=True)
    assert obs["observation_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert obs["observation_chars"] == len(text)
    assert len(obs["preview"]) <= al.OBS_PREVIEW_CHARS
    assert obs["ok"] is True


# ------------------------------------------------------------------ 篡改可发现
def test_editing_one_observation_breaks_chain_at_that_step(monkeypatch):
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    body = copy.deepcopy(trace["ledger"])
    body["entries"][3]["observation"]["ok"] = False
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 3


def test_deleting_a_step_is_detected(monkeypatch):
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    body = copy.deepcopy(trace["ledger"])
    del body["entries"][2]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 2


def test_violating_step_order_is_detected(monkeypatch):
    trace = _run(monkeypatch, TWO_PROBES + [_submit()])
    body = copy.deepcopy(trace["ledger"])
    body["entries"][2]["n"] = 5          # 谎报步号
    assert tl.verify_chain(body)["ok"] is False


# ------------------------------------------------------------------ 兜底路径
def test_rule_fallback_run_also_records_a_full_trail(monkeypatch):
    """模型始终不给判定 → 走规则兜底；"没判定"也是终态，链里必须有 fallback 这一步。"""
    trace = _run(monkeypatch, list(TWO_PROBES))
    assert trace.get("fallback") is not None
    assert _actions(trace)[-1] == "fallback"
    assert trace["ledger"]["step_count"] == len(trace["steps"]) + 3
    assert tl.verify_chain(trace["ledger"])["ok"] is True
    last = trace["ledger"]["entries"][-1]
    assert last["observation"]["verdict"] == trace["verdict"]


def test_rejected_submission_stays_in_the_ledger(monkeypatch):
    """被护栏拒收的提交也要留痕：否则"试了几次、卡在哪"会被抹掉。"""
    bad = _submit(verdict="false_positive", authorization_ref=None)
    trace = _run(monkeypatch, TWO_PROBES + [bad])
    subs = [e for e in trace["ledger"]["entries"] if e["action"] == "submit_verdict"]
    assert subs, _actions(trace)
    assert subs[0]["observation"]["ok"] is False
    assert subs[0]["observation"]["reason"]
    assert tl.verify_chain(trace["ledger"])["ok"] is True


def test_unparseable_output_and_unknown_tool_are_recorded(monkeypatch):
    trace = _run(monkeypatch, ["not-json-at-all",
                               {"thought": "调个不存在的工具", "action": "rm_rf", "args": {}},
                               _submit()])
    acts = _actions(trace)
    assert "PARSE_ERROR" in acts
    assert "rm_rf" in acts
    assert trace["ledger"]["step_count"] == len(trace["steps"]) + 3


# ------------------------------------------------------------------ 落盘与盖章
def test_ledger_file_is_offline_verifiable(monkeypatch, tmp_path):
    out = str(tmp_path / "run" / "ledger.json")
    trace = _run(monkeypatch, TWO_PROBES + [_submit()], ledger_out=out)
    with open(out, encoding="utf-8") as f:
        body = json.load(f)
    assert body["head"] == trace["ledger"]["head"]
    assert body["step_count"] == trace["ledger"]["step_count"]
    assert tl.verify_chain(body)["ok"] is True


def test_sealed_ledger_passes_three_stage_verification(monkeypatch, tmp_path, keys):
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    out = str(tmp_path / "ledger.json")
    seal_out = str(tmp_path / "ledger.seal.json")
    trace = _run(monkeypatch, TWO_PROBES + [_submit()],
                 key_path=keys["private_key_path"],
                 seal_out_dir=str(tmp_path / "seals"),
                 ledger_out=out, ledger_seal_out=seal_out)
    assert trace["sealed"] is True, trace.get("seal_error")
    assert trace["ledger"]["seal"]["seal_path"] == seal_out
    with open(out, encoding="utf-8") as f:
        body = json.load(f)
    res = tl.verify_sealed_trace(body, seal_out, keys_path=anchor)
    assert res["verdict"] == "VALID", res["reason"]


def test_tampered_file_cannot_carry_the_seal(monkeypatch, tmp_path, keys):
    """落盘后被人改了一格：链断 → 盖章校验必须 INVALID（不是只看签名有效）。"""
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    out = str(tmp_path / "ledger.json")
    seal_out = str(tmp_path / "ledger.seal.json")
    _run(monkeypatch, TWO_PROBES + [_submit()],
         key_path=keys["private_key_path"],
         seal_out_dir=str(tmp_path / "seals"),
         ledger_out=out, ledger_seal_out=seal_out)
    with open(out, encoding="utf-8") as f:
        body = json.load(f)
    body["entries"][2]["args"]["asset"] = "another-host"
    res = tl.verify_sealed_trace(body, seal_out, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"].startswith("E_TRACE_BREAK")


# ------------------------------------------------------------------ CLI 接线
def test_cli_exposes_and_forwards_the_ledger_flags(tmp_path, monkeypatch, capsys):
    """命令行不给这两个开关，接线就只存在于库调用里——所以这里验的是参数真的传下去了。"""
    from swordholder import cli

    alert_path = tmp_path / "alert.json"
    alert_path.write_text(json.dumps({
        "alert_id": "ALRT-L-CLI", "title": "t", "asset": "build-runner-07",
        "severity": "high", "signal": "s",
    }, ensure_ascii=False), encoding="utf-8")
    ledger_out = str(tmp_path / "a.ledger.json")
    seal_out = str(tmp_path / "a.ledger.seal.json")

    ns = cli.build_parser().parse_args(
        ["agent", str(alert_path), "--ledger-out", ledger_out, "--ledger-seal-out", seal_out])
    assert (ns.ledger_out, ns.ledger_seal_out) == (ledger_out, seal_out)

    seen = {}

    def fake_run_agent(alert, **kw):
        seen.update(kw)
        return {"verdict": "true_positive", "engine": "scripted", "steps": [],
                "ledger": {"trace_id": "ALRT-L-CLI", "step_count": 0,
                           "head": tl.GENESIS, "check": {"ok": True, "first_break": None}}}

    monkeypatch.setattr(al, "run_agent", fake_run_agent)
    rc = cli.cmd_agent(ns)
    assert rc == 0
    assert seen["ledger_out"] == ledger_out
    assert seen["ledger_seal_out"] == seal_out

    payload = json.loads(capsys.readouterr().out)
    assert payload["ledger"]["chain_ok"] is True
    assert payload["ledger"]["head"] == tl.GENESIS
