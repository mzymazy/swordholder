"""归因分层台账的不变量（把"流程增益"与"不变量拦截"分列的钉子）。

钉住的四件事
------------
1. **分桶完备**：admit + schema + invariant 必须等于可配对轨迹数。少一条就是有轨迹
   既没被记为放行、也没被记为退回，报表的分母会静默缩水。
2. **撤证去向闭合**：撤证单元 = 被不变量拦住 + 明确无影响 + 未归类。"未归类"必须为 0，
   否则"证据层撤证 19 条、只拦下 12 条"这种差额就没人解释。
3. **拦截必须带编号**：layer=invariant 却拿不出 I*/S* 编号，说明统计退化成了文本匹配，
   无法审计是哪条策略生效。
4. **真单不误拦**：签发成功的真工单在 attested 口径下必须放行。

前三条用合成数据离线校验（不依赖盘上产物），第四条在真实报告存在时才做。
"""

import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPORT = os.path.join(ROOT, "evidence", "poison_v2",
                      "attribution_layer_split_b2_4models_36.json")
POLICY = os.path.join(ROOT, "swordholder", "policy", "default-soc-triage.yaml")


def _unit(layer_v="admit", layer_a="admit", rule_a=None, withheld=0, issued=0,
          verdict="false_positive", auth=True, mode="session", seed=7, engine="m"):
    return {
        "engine": engine, "mode": mode, "seed": seed,
        "original_verdict": verdict, "has_authorization_ref": auth,
        "admit_v": layer_v == "admit", "admit_a": layer_a == "admit",
        "layer_v": layer_v, "layer_a": layer_a, "rule_v": None, "rule_a": rule_a,
        "seal_stats": {"issued": issued, "withheld": withheld, "issue_failed": 0,
                       "ticket_steps": 1},
        "reject_reasons_a": ["E_NO_ATTESTATION"] if withheld else [],
    }


def _build(units):
    import sys
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    from attribution_layer_split import build
    rep = build({"units": units, "data_source": ["t"], "overall": {}})
    return rep


def test_buckets_are_exhaustive():
    """每个单元必须恰好落进一个桶，两口径都成立。"""
    units = [
        _unit(),
        _unit(layer_a="invariant", rule_a="I1", withheld=1),
        _unit(layer_a="schema", withheld=1),
        _unit(layer_v="schema"),
    ]
    rep = _build(units)
    for key in ("value_only", "attested"):
        layers = rep["table"][key]["layers"]
        assert sum(layers.values()) == len(units), f"{key} 分桶不闭合：{layers}"


def test_withdrawn_outcome_is_accounted():
    """撤证去向必须逐条归类，未归类为 0。"""
    units = [
        _unit(layer_a="invariant", rule_a="I1", withheld=1),          # 撤证后被拦
        _unit(layer_a="admit", withheld=1, verdict="true_positive"),  # 撤证但原判非误报
        _unit(withheld=0),                                            # 未撤证
    ]
    rep = _build(units)
    wo = rep["withdrawn_outcome"]
    total = sum(x["n"] for x in wo.values())
    assert total == rep["attestation"]["units_withdrawn"] == 2
    assert wo["no_effect_other"]["n"] == 0
    assert wo["blocked_by_invariant"]["n"] == 1
    assert wo["no_effect_not_false_positive"]["n"] == 1


def test_invariant_layer_always_has_rule_id():
    """invariant 层必须带编号；缺编号要被单独计数（脚本据此失败）。"""
    units = [
        _unit(layer_a="invariant", rule_a="I1", withheld=1),
        _unit(layer_a="invariant", rule_a=None, withheld=1),   # 故意缺编号
    ]
    rep = _build(units)
    assert rep["table"]["attested"]["layers"]["invariant"] == 2
    assert sum(rep["table"]["attested"]["rules"].values()) == 1, \
        "缺编号的 invariant 拒收不应被计入规则统计"
    assert rep["table"]["attested"]["unlabeled_invariant"] == 1, \
        "缺编号的 invariant 拒收必须被计为口径缺口，而不是静默忽略"


def test_rule_ids_exist_in_policy():
    """报告里出现的规则编号必须能在策略包里找到。"""
    if not os.path.exists(REPORT):
        pytest.skip("归因分层报告不在盘上")
    with open(REPORT, encoding="utf-8") as f:
        rep = json.load(f)
    rules = set(rep["table"]["value_only"]["rules"]) | set(rep["table"]["attested"]["rules"])
    if not rules:
        return
    with open(POLICY, encoding="utf-8") as f:
        text = f.read()
    for rid in rules:
        assert f"id: {rid}" in text, f"规则 {rid} 不在策略包里，报告与策略已脱节"


def test_true_tickets_not_rejected():
    """签发成功的真工单必须放行：不误拦是这套机制的底线。"""
    if not os.path.exists(REPORT):
        pytest.skip("归因分层报告不在盘上")
    with open(REPORT, encoding="utf-8") as f:
        rep = json.load(f)
    at = rep["attestation"]
    assert at["true_ticket_units_admitted"] == at["units_issued"], \
        f"真工单被误拦：签发 {at['units_issued']}、放行 {at['true_ticket_units_admitted']}"


LIVE_ATTESTED = os.path.join(ROOT, "evidence", "poison_v2",
                             "poison_v2_live_blocked_probe_attested.json")
LIVE_VALUE = os.path.join(ROOT, "evidence", "poison_v2",
                          "poison_v2_live_blocked_probe_value.json")


def _live(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["summary"]["v1_scope_stats"]


def test_live_blocked_count_carries_rule_id():
    """live 统计口径：拦截数必须带得出编号，且裸跑口径不许出现拦截。

    这条钉住的是"统计链路读不到结构化编号"这个已发生过的故障：修复前
    `blocked_by_invariant` 恒为 0，看起来像"不变量从不触发"，实际是匹配文本标签失败。
    """
    for p in (LIVE_ATTESTED, LIVE_VALUE):
        if not os.path.exists(p):
            pytest.skip("live 复跑产物不在盘上")
    at = _live(LIVE_ATTESTED)
    for mode, s in at.items():
        if s.get("blocked_by_invariant"):
            assert s.get("blocked_rules"), \
                f"{mode} 有拦截却拿不出编号——统计又退化成文本匹配了"
    # 裸跑（value 口径）不许有拦截：有就说明口径串了，把证据层的功劳记到了不变量头上
    for mode, s in _live(LIVE_VALUE).items():
        assert s.get("blocked_by_invariant") == 0, \
            f"value 口径 {mode} 出现不变量拦截，口径已被污染"
    # 阴性对照：control 组两口径都不许被拦
    assert at.get("control", {}).get("blocked_by_invariant") == 0
    assert _live(LIVE_VALUE).get("control", {}).get("blocked_by_invariant") == 0
