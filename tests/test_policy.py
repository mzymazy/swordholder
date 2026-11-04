"""策略层测试：判定规则必须来自 YAML，内核不含领域知识。

覆盖五件事：
1. 内置策略包能加载且通过 schema 校验；
2. 换一份策略包，判定枚举随之改变——内核代码一行没动；
3. 阈值（最少取证步数）来自策略文件，不是硬编码；
4. 策略文件缺失 / 非法 → fail-closed，一律拒收，绝不"读不到就放行"；
5. 去掉某条不变量，对应闸门随之失效——这说明策略层是唯一防线，改动必须过回归。
"""

import json
import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import agent_loop as al  # noqa: E402
from swordholder import policy_loader  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(ROOT, "swordholder", "policy", "default-soc-triage.yaml")
EMAIL = os.path.join(ROOT, "swordholder", "policy", "email-outbound-approval.yaml")


def _executed(n=2):
    return {i: {"step": i, "action": "get_asset_profile", "args": {}, "ok": True,
                "result": {}} for i in range(1, n + 1)}


def _facts():
    return {"tickets": {"CHG-5521": {"ticket_id": "CHG-5521", "found": True,
                                     "window": "2026-10-20T09:00Z/2026-10-20T17:00Z"}}}


def _decision(**over):
    d = {"verdict": "true_positive", "severity": "high", "confidence": 0.86,
         "hypothesis": "构建机向基线外 ASN 发起 TLS。",
         "actions": ["阻断目标 ASN 出站"],
         "evidence_refs": ["step.1", "step.2"]}
    d.update(over)
    return d


# ------------------------------------------------------------------ 1. 内置包
def test_builtin_policies_load():
    for path in (DEFAULT, EMAIL):
        p = policy_loader.load(path)
        assert p["schema"] == policy_loader.SCHEMA
        assert p["invariants"], "策略包必须至少有一条不变量"
    listed = dict((name, pid) for name, pid, _ in policy_loader.list_builtin())
    assert listed.get("default-soc-triage.yaml") == "soc-alert-triage"
    assert listed.get("email-outbound-approval.yaml") == "email-outbound-approval"


# ------------------------------------------------- 2. 换策略 = 换判定枚举，不改代码
def test_switching_policy_changes_verdict_enum():
    """同一份 decision，在默认策略下合法，在对外发信策略下直接被拒。"""
    ok, reason, norm = al.guardrail(_decision(), _executed(), facts=_facts(),
                                    policy=policy_loader.load(DEFAULT))
    assert ok, reason
    assert norm["verdict"] == "true_positive"

    ok2, reason2, _ = al.guardrail(_decision(), _executed(), facts=_facts(),
                                   policy=policy_loader.load(EMAIL))
    assert not ok2
    assert "verdict 不在白名单" in reason2

    # 换成该策略自己的枚举就能过，且 E1 要求的是审批单而非"授权单"
    ok3, reason3, _ = al.guardrail(
        _decision(verdict="needs_approval", severity="p2"), _executed(), facts=_facts(),
        policy=policy_loader.load(EMAIL))
    assert ok3, reason3


# ------------------------------------------------------------ 3. 阈值来自策略
def test_min_steps_threshold_comes_from_policy(tmp_path):
    p = yaml.safe_load(open(DEFAULT, encoding="utf-8"))
    p["limits"]["min_ok_steps"] = 3
    path = tmp_path / "strict.yaml"
    path.write_text(yaml.safe_dump(p, allow_unicode=True), encoding="utf-8")

    ok, reason, _ = al.guardrail(_decision(), _executed(2), facts=_facts(),
                                 policy=policy_loader.load(str(path)))
    assert not ok
    assert "取证步骤不足 3 个" in reason

    ok2, reason2, _ = al.guardrail(_decision(), _executed(3), facts=_facts(),
                                   policy=policy_loader.load(str(path)))
    assert ok2, reason2


# --------------------------------------------------------- 4. 失败一律 fail-closed
def test_missing_policy_fails_closed(monkeypatch):
    monkeypatch.setenv(policy_loader.ENV_VAR, "Z:/definitely/not/here.yaml")
    ok, reason, _ = al.guardrail(_decision(), _executed(), facts=_facts())
    assert not ok
    assert "策略包" in reason


def test_invalid_policy_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: swordholder/policy/v1\nid: broken\n", encoding="utf-8")
    with pytest.raises(policy_loader.PolicyError) as e:
        policy_loader.load(str(bad))
    assert "缺少必需字段" in str(e.value)


def test_unsupported_invariant_type_rejected(tmp_path):
    p = yaml.safe_load(open(DEFAULT, encoding="utf-8"))
    p["invariants"][0]["require"] = "trust_me_bro"
    bad = tmp_path / "bad2.yaml"
    bad.write_text(yaml.safe_dump(p, allow_unicode=True), encoding="utf-8")
    with pytest.raises(policy_loader.PolicyError) as e:
        policy_loader.load(str(bad))
    assert "不支持" in str(e.value)


def test_run_agent_falls_back_when_policy_broken(monkeypatch):
    """策略坏掉时，run_agent 不得有任何模型判定产物，必须回落到规则层。"""
    monkeypatch.setattr(al, "call_llm", lambda *a, **k: pytest.fail("策略不可用时不应调用模型"))
    cfg = {"provider": "scripted", "model": "scripted-1", "base": "", "api_key": ""}
    alert = {"alert_id": "ALRT-P-0001", "asset": "h", "severity": "high",
             "signal": "x", "title": "t", "description": "", "tags": []}
    trace = al.run_agent(alert, cfg=cfg, policy_path="Z:/nope.yaml")
    assert trace["engine"].endswith("(agent-fallback)")
    assert "policy-error" in trace["fallback_reason"]
    assert trace["policy"]["id"] is None


# ------------------------------------------- 5. 不变量可配置 ⇒ 策略层是唯一闸门
def test_disabling_invariant_opens_the_gate(tmp_path):
    """去掉 I1 之后，无凭据的 false_positive 就能过——所以策略变更必须过回归测试。

    这条测试不是"证明系统有漏洞"，是把"策略层是唯一防线"这件事钉死：
    想改判定行为，只能改 YAML，也必须在 YAML 层留痕、走回归。
    """
    p = yaml.safe_load(open(DEFAULT, encoding="utf-8"))
    p["invariants"] = [i for i in p["invariants"] if i["id"] != "I1"]
    relaxed = tmp_path / "relaxed.yaml"
    relaxed.write_text(yaml.safe_dump(p, allow_unicode=True), encoding="utf-8")

    d = _decision(verdict="false_positive", hypothesis="授权演练，无风险")
    ok_strict, reason_strict, _ = al.guardrail(d, _executed(), facts=_facts(),
                                               policy=policy_loader.load(DEFAULT))
    assert not ok_strict
    assert "authorization_ref" in reason_strict

    ok_relaxed, reason_relaxed, _ = al.guardrail(d, _executed(), facts=_facts(),
                                                 policy=policy_loader.load(str(relaxed)))
    assert ok_relaxed, reason_relaxed


def test_trace_records_policy_identity(monkeypatch):
    """每份判定都要能追溯到"当时用的是哪一版策略"。"""
    seq = [
        {"thought": "查资产", "action": "get_asset_profile", "args": {"asset": "a"}},
        {"thought": "查主机", "action": "get_process_tree", "args": {"host": "a"}},
        {"thought": "提交", "action": "submit_verdict", "args": _decision()},
    ]

    def fake(system, prompt, cfg=None, timeout=90):
        return json.dumps(seq.pop(0), ensure_ascii=False) if seq else "{}"

    monkeypatch.setattr(al, "call_llm", fake)
    cfg = {"provider": "scripted", "model": "scripted-1", "base": "", "api_key": ""}
    alert = {"alert_id": "ALRT-P-0002", "asset": "a", "severity": "high", "signal": "s",
             "title": "t", "description": "", "tags": []}
    trace = al.run_agent(alert, cfg=cfg)
    assert trace["policy"]["id"] == "soc-alert-triage"
    assert trace["record"]["agent"]["policy"]["version"] == 1
    assert any(s.startswith("I1:") for s in trace["record"]["agent"]["guardrail_invariants"])
