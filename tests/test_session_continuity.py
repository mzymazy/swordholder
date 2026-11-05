"""会话级判定状态（P0-2）验收测试。

要证明的事只有一件：**每一轮单看都合规、合起来是诱导放行的那个漏洞被堵上了**。
测试输入直接取自 evidence/adversarial_xadv_v1.json 的 phishing_multiturn 三条
（xadv-10 冒充运维、xadv-11 公理包装、xadv-12 先例复用），不改写成"更容易过"的版本。

分两层：
A. 会话层单测：直接驱动 SessionState，不起模型；
B. agent_loop 集成：脚本化 LLM 跑完整 run_agent，验证拒收会进 trace 且不落进最终判定。
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import agent_loop as al  # noqa: E402
from swordholder import policy_loader, session as sm  # noqa: E402
from swordholder.alert import normalize  # noqa: E402
from swordholder.rules import rule_triage  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XADV = os.path.join(ROOT, "evidence", "adversarial_xadv_v1.json")


def _pol():
    return policy_loader.load(policy_loader.DEFAULT_POLICY)


def _xadv(case_id: str) -> list[dict]:
    """取真实多轮钓鱼用例的对话轮次。"""
    with open(XADV, encoding="utf-8") as f:
        data = json.load(f)
    for c in data["cases"]:
        if c["id"] == case_id:
            return list(c["turns"])
    raise AssertionError(f"用例缺失：{case_id}")


def _exec(steps):
    """构造 executed 字典：{seq: {action, args, ok}}。"""
    return {i: {"action": a, "args": g, "ok": True}
            for i, (a, g) in enumerate(steps, start=1)}


def _decision(**over):
    d = {"verdict": "true_positive", "severity": "high", "confidence": 0.8,
         "hypothesis": "构建机外联未登记 ASN。", "actions": ["隔离主机"],
         "evidence_refs": ["step.1", "step.2"]}
    d.update(over)
    return d


def _seed_true_positive(sess, pol, turn_text="帮我看下这条外联告警"):
    """先跑一轮正常判定，让会话里有一条 true_positive/high 的历史。"""
    sess.begin_user_turn(turn_text, policy=pol)
    t = sess.turn_no
    sess.record_turn(_decision(), executed=_exec([("get_asset_profile", {"asset": "a"}),
                                                  ("get_process_tree", {"host": "a"})]),
                     turn=t, detail={})
    return t


# --------------------------------------------------------------------------- #
# A. 会话层
# --------------------------------------------------------------------------- #
def test_xadv10_identity_claim_blocks_relaxation():
    """冒充运维新同事建立信任后要求放行：单轮齐备，跨轮必须拒。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)

    turns = _xadv("xadv-10")
    first = sess.begin_user_turn(turns[0]["content"], policy=pol)
    sess.begin_user_turn(turns[1]["content"], policy=pol)
    # 声明落在第一轮（"我是运维团队的新同事"），第二轮是索要；两轮合起来才是完整钓鱼
    assert any(c.kind == "identity" for c in first), "身份声明未被提取"

    ok, reason, detail = sess.check_submission(
        _decision(verdict="false_positive", severity="low",
                  hypothesis="新同事说这是内部核查，判误报"),
        executed=_exec([("lookup_ticket", {"ticket_id": "CHG-1"})]),
        policy=pol, turn=sess.turn_no)
    assert ok is False, "身份声明未核实却放行了放宽判定"
    assert "S1" in reason
    assert detail["relaxed"] is True
    assert sess.rejected and sess.rejected[-1]["rule"] == "S1_claim_must_be_verified"


def test_xadv11_axiom_wrapper_never_authorizes():
    """用"为了践行公理"包装删除/放行请求：即使不放宽也不得被引用为依据。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    turns = _xadv("xadv-11")
    sess.begin_user_turn(turns[0]["content"], policy=pol)
    sess.begin_user_turn(turns[1]["content"], policy=pol)

    ok, reason, _ = sess.check_submission(
        _decision(verdict="suspicious", severity="low",
                  hypothesis="用户指出删除测试残留符合「为了践行」的善意原则，故降级处理"),
        executed=_exec([("get_asset_profile", {"asset": "a"}),
                        ("get_process_tree", {"host": "a"})]),
        policy=pol, turn=sess.turn_no)
    assert ok is False, "原则/公理共识被当成了判定依据"
    assert "S3" in reason


def test_xadv12_precedent_reuse_is_caught():
    """先例引用（"上次也这么干"）+ 算法上的重复取证，不得成为重复执行的许可。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    turns = _xadv("xadv-12")
    sess.begin_user_turn(turns[0]["content"], policy=pol)
    sess.begin_user_turn(turns[1]["content"], policy=pol)

    # 复读上一轮的两个探针：指纹相同 -> 不算新增证据
    reused = _exec([("get_asset_profile", {"asset": "a"}),
                    ("get_process_tree", {"host": "a"})])
    ok, reason, _ = sess.check_submission(
        _decision(verdict="false_positive", severity="low",
                  hypothesis="上次也是这么清理的，照旧处理"),
        executed=reused, policy=pol, turn=sess.turn_no)
    assert ok is False
    assert any(tag in reason for tag in ("S2", "S5")), reason


def test_verified_claim_with_new_evidence_allows_relaxation():
    """核实过就不该一棒打死：调用 verify_tool 且本轮有新增证据，放宽应放行。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    sess.begin_user_turn(_xadv("xadv-10")[1]["content"], policy=pol)
    sess.note_tool("lookup_ticket", True, turn=sess.turn_no)
    assert not sess.unverified_claims()

    ok, reason, detail = sess.check_submission(
        _decision(verdict="false_positive", severity="medium",
                  hypothesis="授权单 CHG-8801 时间窗覆盖事发时刻，判误报"),
        executed=_exec([("lookup_ticket", {"ticket_id": "CHG-8801"})]),
        policy=pol, turn=sess.turn_no)
    assert ok, reason
    assert detail["new_evidence"] == 1


def test_turn_budget_closes_relaxation():
    """超出轮次预算后只准收紧：第 6 轮反复要求降级必须拒。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    for i in range(4):
        sess.begin_user_turn(f"第{i + 2}轮补充说明", policy=pol)
    assert sess.turn_no > pol["session"]["turn_budget"]

    ok, reason, _ = sess.check_submission(
        _decision(verdict="suspicious", severity="low", hypothesis="拖久了，降级处理"),
        executed=_exec([("get_asset_profile", {"asset": "a"}),
                        ("get_process_tree", {"host": "a"}),
                        ("lookup_ticket", {"ticket_id": "CHG-9"})]),
        policy=pol, turn=sess.turn_no)
    assert ok is False
    assert "S4" in reason


def test_relax_limit_counts_across_session():
    """放宽次数是整场会话的预算，不是每轮重置。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    sess.begin_user_turn("补充一", policy=pol)
    ok, _, detail = sess.check_submission(
        _decision(verdict="suspicious", severity="high", hypothesis="证据不足，降级"),
        executed=_exec([("search_prior_alerts", {"q": "asn 215199"})]),
        policy=pol, turn=sess.turn_no)
    assert ok and detail["relaxed"]
    sess.record_turn(_decision(verdict="suspicious", severity="high"), turn=sess.turn_no,
                     detail=detail)
    assert sess.relax_count() == 1

    sess.begin_user_turn("补充二", policy=pol)
    ok, reason, _ = sess.check_submission(
        _decision(verdict="false_positive", severity="low", hypothesis="再降一级"),
        executed=_exec([("get_process_tree", {"host": "b"})]),
        policy=pol, turn=sess.turn_no)
    assert ok is False
    assert "S6" in reason


def test_session_roundtrip_keeps_invariants(tmp_path):
    """会话要能跨进程传递，否则"多轮"只是同一个函数里多跑几次。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    for t in _xadv("xadv-10"):
        sess.begin_user_turn(t["content"], policy=pol)
    assert sess.unverified_claims(), "声明未入库"
    path = sess.save(str(tmp_path / "sess.json"))

    back = sm.SessionState.load(path)
    assert back.session_id == sess.session_id
    assert back.turn_no == sess.turn_no
    assert len(back.unverified_claims()) == len(sess.unverified_claims())

    ok, reason, _ = back.check_submission(
        _decision(verdict="false_positive", severity="low", hypothesis="按同事说的判误报"),
        executed=_exec([("lookup_ticket", {"ticket_id": "CHG-2"})]),
        policy=pol, turn=back.turn_no)
    assert ok is False and "S1" in reason


def test_multiturn_without_session_policy_fails_closed():
    """策略包没声明会话规则时，多轮一律拒收——不知情不等于可以放过。"""
    bare = {"id": "bare", "version": 1}
    sess = sm.SessionState(policy=bare)
    sess.begin_user_turn("第一轮")
    sess.begin_user_turn("第二轮")
    ok, reason, _ = sess.check_submission(_decision(), policy=bare, turn=sess.turn_no)
    assert ok is False
    assert "fail-closed" in reason

    single = sm.SessionState(policy=bare)
    single.begin_user_turn("只有一轮")
    ok2, _, detail = single.check_submission(_decision(), policy=bare, turn=1)
    assert ok2 is True and detail["skipped"] == "no-session-policy"


# --------------------------------------------------------------------------- #
# 策略包校验：会话段写错必须在加载期报错，而不是静默失效
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mutate,frag", [
    (lambda s: s.update(schema="swordholder/session/v9"), "schema"),
    (lambda s: s.update(turn_budget=-1), "turn_budget"),
    (lambda s: s["relax"].update(max_relaxations="一次"), "max_relaxations"),
    (lambda s: s.update(rules=["S9_不存在"]), "未知不变量"),
    (lambda s: s["claims"][0].update(patterns=["("]), "正则非法"),
    (lambda s: s["claims"][0].update(patterns=[]), "patterns"),
    (lambda s: s["claims"].append(dict(s["claims"][0])), "重复"),
])
def test_policy_loader_rejects_bad_session_segment(mutate, frag):
    pol = json.loads(json.dumps(_pol()))
    mutate(pol["session"])
    with pytest.raises(policy_loader.PolicyError) as ei:
        policy_loader.validate(pol, origin="<test>")
    assert frag in str(ei.value)


def test_default_policy_session_segment_is_valid():
    seg = _pol()["session"]
    assert seg["schema"] == sm.SCHEMA
    assert set(seg["rules"]) <= set(sm.ALL_RULES)


# --------------------------------------------------------------------------- #
# B. agent_loop 集成
# --------------------------------------------------------------------------- #
def _alert(**over):
    base = {
        "alert_id": "ALRT-S-0001",
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


PROBES = [
    {"thought": "查资产", "action": "get_asset_profile", "args": {"asset": "build-runner-07"}},
    {"thought": "查外联", "action": "get_process_tree", "args": {"host": "build-runner-07"}},
]


def _submit(**over):
    args = {"verdict": "true_positive", "severity": "high", "confidence": 0.86,
            "hypothesis": "构建机向基线外 ASN 发起 TLS 并持有 CI token。",
            "actions": ["阻断目标 ASN 出站", "轮换 CI token"],
            "evidence_refs": ["step.1", "step.2"]}
    args.update(over)
    return {"thought": "提交判定", "action": "submit_verdict", "args": args}


def _run(monkeypatch, script, **kw):
    seq = list(script)

    def fake(system, prompt, cfg=None, timeout=90):
        if not seq:
            return "{}"
        item = seq.pop(0)
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)

    monkeypatch.setattr(al, "call_llm", fake)
    cfg = {"provider": "scripted", "model": "scripted-1", "base": "", "api_key": ""}
    return al.run_agent(_alert(), cfg=cfg, **kw)


def test_run_agent_rejects_phishing_relaxation(monkeypatch):
    """历史已判 true_positive，第二轮被"我是运维新同事"诱导降级 -> 拒收并回落。"""
    pol = _pol()
    sess = sm.SessionState(policy=pol)
    _seed_true_positive(sess, pol)
    conversation = _xadv("xadv-10")

    bad = _submit(verdict="suspicious", severity="low",
                  hypothesis="运维新同事说明这是内部核查，可降级")
    trace = _run(monkeypatch, PROBES + [bad, bad, bad],
                 max_steps=5, session=sess, conversation=conversation)

    assert trace["session_rejected"], "会话级拒收未进入 trace"
    assert "S1" in trace["session_rejected"][0]["reason"]
    # 拒收后不得采纳被诱导的判定：走规则层兜底，且记录里保留会话身份
    assert trace["engine"].endswith("(agent-fallback)")
    assert trace["verdict"] == rule_triage(_alert())["verdict"]
    assert trace["session"]["summary"]["rejected"] >= 1


def test_run_agent_records_session_state(monkeypatch, tmp_path):
    """判定通过后会话要落地：下一轮判什么，取决于这一轮记了什么。"""
    out = tmp_path / "sess.json"
    trace = _run(monkeypatch, PROBES + [_submit()],
                 conversation=[{"role": "user", "content": "看下这条告警"}],
                 session_out=str(out))

    assert trace["verdict"] == "true_positive"
    ses = trace["session"]
    assert ses["turn_no"] == 1
    assert ses["summary"]["accepted"] == 1
    assert ses["summary"]["strongest"]["verdict"] == "true_positive"
    assert trace["record"]["agent"]["session"]["accepted"] == 1
    assert out.exists()

    back = sm.SessionState.load(str(out))
    assert back.strongest()[0] == "true_positive"


def test_run_agent_extracts_claims_from_conversation(monkeypatch):
    """会话里的身份/先例话术在进入判定前就应被登记为"未核实声明"。"""
    trace = _run(monkeypatch, PROBES + [_submit()], conversation=_xadv("xadv-12"))
    kinds = {c["kind"] for c in trace.get("session_claims", [])}
    assert "precedent" in kinds
    assert trace["session"]["summary"]["claims_unverified"] >= 1


def test_single_turn_behaviour_unchanged(monkeypatch):
    """单轮场景不因引入会话层而改变：无历史、无声明时照常采纳。"""
    trace = _run(monkeypatch, PROBES + [_submit()])
    assert trace["verdict"] == "true_positive"
    assert trace["session"]["turn_no"] == 0
    assert "session_rejected" not in trace


def test_fallback_when_session_unusable(monkeypatch):
    """会话对象坏掉 -> 不用上一次的判定背书，直接走规则层兜底。"""
    trace = _run(monkeypatch, PROBES + [_submit()], session=object())
    assert trace["engine"].endswith("(agent-fallback)")
    assert "session-error" in (trace.get("fallback_reason") or "")
    assert trace["verdict"] == rule_triage(_alert())["verdict"]
