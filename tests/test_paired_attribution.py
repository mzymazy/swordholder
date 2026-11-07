"""配对归因报告的台账不变量（离线产物的回归钉子）。

钉住的四件事
------------
1. **单向性**：attested 相对 value 只允许更严，`attested_only_admit` 必须为 0；
   否则就是 facts_attested 没做成子集，属于不变量实现缺陷而非"模型行为"。
2. **重放保真**：value 口径重算必须复现原运行（原运行 record 存在即当时通过），
   违规数必须为 0，否则整套配对统计的分母不可信。
3. **归因口径**：被拦条数必须等于"含 authorization_ref 且 value 放行"的条数，
   不允许出现差异被统计进不含授权依据的轨迹上。
4. **真单不误拦**：签发成功的真工单在 attested 口径下仍必须放行（零误拦）。

前三条只校验**已落盘报告**的内部一致性，不需要重跑模型；第四条在真实轨迹目录存在时
才做，缺轨迹则 skip（离线 CI 不应因数据缺失而红）。
"""

import glob
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPORT = os.path.join(ROOT, "evidence", "poison_v2", "paired_attribution_b2_4models_36.json")
TRACES = os.path.join(ROOT, "temp", "paired_traces_qwen3_8b")


def _load():
    if not os.path.exists(REPORT):
        pytest.skip("配对归因报告不在盘上，跳过台账一致性校验")
    with open(REPORT, encoding="utf-8") as f:
        return json.load(f)


def test_no_attested_only_admit():
    rep = _load()
    assert rep["overall"]["table"]["attested_only_admit"] == 0, \
        "attested 出现了比 value 更松的放行：facts_attested 不是 facts_value 的子集"


def test_replay_fidelity_clean():
    rep = _load()
    assert rep["overall"]["replay_fidelity_violations"] == 0, \
        "value 口径重放未复现原运行，配对分母失真，禁止继续统计"


def test_monotonicity_clean():
    rep = _load()
    assert rep["overall"]["monotonicity_violations"] == 0


def test_blocked_matches_authorization_claim():
    """差异只能落在"挂了授权依据且 value 放行"的轨迹上，不许溢出到别的轨迹。

    注意两个分母不是一回事：`has_authorization_ref` 是"轨迹里出现了授权依据"，
    而"被改判"还要求该轨迹的最终动作**是放松结论**。agent 自己已判 suspicious 的轨迹
    虽然挂了 authorization_ref，也没有放松结论可供证据层拦截，所以这里只断言
    "被改判 ⇒ 必带授权依据"，不要求两者数量相等。
    """
    rep = _load()
    units = [u for u in rep["units"] if "error" not in u]
    flipped = [u for u in units if u["admit_v"] and not u["admit_a"]]
    assert rep["overall"]["blocked_among_authorization_claim"] == len(flipped)
    leaked = [u["trace_file"] for u in flipped if not u["has_authorization_ref"]]
    assert not leaked, f"不含授权依据却被证据层改判：{leaked}"


def test_excluded_are_accounted():
    """被排除的轨迹必须逐条带原因，不允许静默丢样本。"""
    rep = _load()
    excluded = [u for u in rep["units"] if "error" in u]
    assert len(excluded) == rep["overall"]["excluded"]
    assert all(u["error"] for u in excluded)


def test_true_tickets_not_rejected():
    """真工单：签发成功即必须放行（离线判定层口径）。"""
    if not glob.glob(os.path.join(TRACES, "*.json")):
        pytest.skip("现场轨迹已清理，跳过真单零误拦校验")
    import sys
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    from paired_attribution import judge_one

    keys = os.path.join(ROOT, "trusted_keys.json")
    seen_issued = 0
    for p in sorted(glob.glob(os.path.join(TRACES, "*.json"))):
        u = judge_one(p, keys)
        if u.get("error") or not u["seal_stats"]["issued"]:
            continue
        seen_issued += 1
        assert u["admit_a"] is True, \
            f"真工单被证据层误拦：{u['trace_file']} why_a={u['why_a']}"
    if not seen_issued:
        pytest.skip("本批轨迹里没有签发成功的真工单")
