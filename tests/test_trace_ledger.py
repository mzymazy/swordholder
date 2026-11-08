# -*- coding: utf-8 -*-
"""动作轨迹账本回归测试。

守四条语义，任何一条破了这个模块就失去意义：
    1. 未篡改 → 不被误报（假阳性会毁掉可信度）
    2. 改值 / 插入 / 删除 / 换序 → 必须检出，且首断点定位准确
    3. 链自洽但头被截断 → 必须检出
    4. 拿 A 轨迹的凭证背书被改过的 B 轨迹 → 必须拒
"""

import copy
import os

import pytest

from swordholder import core, trace_ledger as tl, trust


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _ledger(n=8):
    led = tl.TraceLedger(trace_id="TR-1", actor="qwen3:8b")
    for i in range(n):
        led.append("tool_%d" % i, {"host": "build-runner-07", "i": i},
                   {"severity": "low", "ok": True}, ts="2026-11-13T10:0%d:00Z" % i)
    return led


# ---------------------------------------------------------------- 不误报
def test_untampered_chain_is_consistent():
    body = _ledger().body()
    res = tl.verify_chain(body)
    assert res["ok"] is True, res["reason"]
    assert res["first_break"] is None
    assert res["expected_head"] == res["claimed_head"]


def test_empty_trace_head_is_genesis():
    led = tl.TraceLedger(trace_id="TR-E")
    assert led.head == tl.GENESIS
    assert tl.verify_chain(led.body())["ok"] is True


# ---------------------------------------------------------------- 四类篡改
def test_value_tamper_detected_at_step():
    body = _ledger().body()
    body["entries"][3]["observation"]["severity"] = "critical"
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 3
    assert "改值" in res["reason"]


def test_insert_tamper_detected():
    body = _ledger().body()
    forged = copy.deepcopy(body["entries"][2])
    forged["action"] = "tool_ghost"
    body["entries"].insert(3, forged)
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 3


def test_delete_tamper_detected():
    body = _ledger().body()
    del body["entries"][2]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 2


def test_reorder_tamper_detected():
    body = _ledger().body()
    e = body["entries"]
    e[2], e[5] = e[5], e[2]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] == 2


def test_truncate_tail_detected_despite_short_chain():
    """只删尾部若干步时，存活部分各自自洽，必须靠 head / step_count 拦住。"""
    body = _ledger().body()
    body["entries"] = body["entries"][:5]
    res = tl.verify_chain(body)
    assert res["ok"] is False
    assert res["first_break"] is None
    assert "step_count" in res["reason"] or "头部哈希" in res["reason"]


# ---------------------------------------------------------------- 与凭证串联
def test_seal_and_verify_roundtrip(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"))
    res = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "VALID", res["reason"]


def test_seal_refuses_inconsistent_body(tmp_path, keys):
    body = _ledger().body()
    body["entries"][1]["action"] = "swapped-to-something-else"
    with pytest.raises(tl.TraceError):
        tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                      out_path=str(tmp_path / "bad.seal.json"))


def test_tampered_body_against_valid_seal_rejected(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"))

    tampered = copy.deepcopy(body)
    tampered["entries"][4]["args"]["host"] = "exfil-01"
    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"].startswith("E_TRACE_BREAK")


def test_seal_from_other_trace_rejected(tmp_path, keys):
    """链自洽但凭证是另一条轨迹的 —— 必须靠 trace_id / head 比对拦住。"""
    body_a = _ledger(6).body()
    body_b = _ledger(9).body()
    body_b["trace_id"] = "TR-1"
    # body_b 步数不同，先伪装成与 A 一样的头，验证比对不靠巧合
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body_b, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "b.seal.json"))
    res = tl.verify_sealed_trace(body_a, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] in ("E_TRACE_HEAD_MISMATCH", "E_TRACE_DIGEST_MISMATCH")


def test_seal_binds_challenge(tmp_path, keys):
    body = _ledger().body()
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / "trace.seal.json"), challenge="nonce-42")
    ok = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                expected_challenge="nonce-42")
    assert ok["verdict"] == "VALID", ok["reason"]
    wrong = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                   expected_challenge="nonce-43")
    assert wrong["verdict"] == "INVALID"


# ------------------------------------------------- 步级定位（0.7.5 步级锚点回归）
# 背景：0.7.4 的凭证只封 head + digest，遇到「改完把该步及之后哈希连同 head 全部重算」
# 的强篡改时链会自洽，只能判 INVALID、说不出改在第几步。0.7.5 用随凭证一起签名的步级
# 锚点补上这个承诺。以下用例锁死三件事：能定位、不误报、旧凭证不被静默降级。


def _rebuild(body):
    """模拟持有写权限的攻击者：改内容后把整链连同 head / step_count 一起重算。"""
    prev = tl.GENESIS
    for i, e in enumerate(body["entries"]):
        e["n"] = i
        e["prev"] = prev
        e["hash"] = tl.entry_hash(e, prev)
        prev = e["hash"]
    body["step_count"] = len(body["entries"])
    body["head"] = prev
    return body


def _seal(tmp_path, keys, body, name="trace.seal.json", **kw):
    anchor = str(tmp_path / "trusted_keys.json")
    if not os.path.exists(anchor):
        trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                           out_path=str(tmp_path / name), **kw)
    return anchor, sealed


@pytest.mark.parametrize("step", [0, 7, 19])
def test_strong_tamper_localized_to_exact_step(tmp_path, keys, step):
    """改值 + 整链重算（链自洽）→ 仍须点名具体步，且区间退化为单点。"""
    body = _ledger(20).body()
    anchor, sealed = _seal(tmp_path, keys, body)

    tampered = copy.deepcopy(body)
    tampered["entries"][step]["observation"]["severity"] = "critical"
    _rebuild(tampered)

    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_TRACE_HEAD_MISMATCH"
    loc = res["localization"]
    assert loc["mode"] == "anchor"
    assert loc["segment"] == [step, step]
    assert loc["exact"] is True


@pytest.mark.parametrize("how", ["insert", "delete", "reorder"])
def test_structural_tamper_localized_with_rebuild(tmp_path, keys, how):
    body = _ledger(20).body()
    anchor, sealed = _seal(tmp_path, keys, body)
    tampered = copy.deepcopy(body)
    entries = tampered["entries"]
    if how == "insert":
        forged = copy.deepcopy(entries[8])
        forged["action"] = "tool_ghost"
        entries.insert(8, forged)
        first = 8
    elif how == "delete":
        del entries[8]
        first = 8
    else:
        entries[8], entries[19] = entries[19], entries[8]
        first = 8
    _rebuild(tampered)

    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    loc = res["localization"]
    assert loc["mode"] == "anchor"
    assert loc["segment"][0] <= first <= loc["segment"][1], loc


def test_appended_step_localized_after_last_original(tmp_path, keys):
    body = _ledger(12).body()
    anchor, sealed = _seal(tmp_path, keys, body)
    tampered = copy.deepcopy(body)
    extra = copy.deepcopy(tampered["entries"][-1])
    extra["action"] = "tool_appended"
    tampered["entries"].append(extra)
    _rebuild(tampered)

    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["localization"]["segment"] == [12, 12]


def test_truncated_tail_localized_to_cut_point(tmp_path, keys):
    """截尾后重算：头部对不上，且须报出「从第几步开始没了」。"""
    body = _ledger(20).body()
    anchor, sealed = _seal(tmp_path, keys, body)
    tampered = copy.deepcopy(body)
    tampered["entries"] = tampered["entries"][:13]
    _rebuild(tampered)

    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    loc = res["localization"]
    assert loc["mode"] == "anchor"
    assert loc["segment"][0] == 13, loc


def test_weak_tamper_still_localized_by_chain(tmp_path, keys):
    """未重算哈希的弱篡改仍走链定位，且不被锚点逻辑改写结论。"""
    body = _ledger(10).body()
    anchor, sealed = _seal(tmp_path, keys, body)
    tampered = copy.deepcopy(body)
    tampered["entries"][4]["observation"]["severity"] = "critical"

    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"].startswith("E_TRACE_BREAK")
    assert res["localization"] == {"mode": "chain", "first_break": 4,
                                  "segment": [4, 4], "exact": True}


def test_anchor_points_always_cover_last_step():
    for n in (1, 2, 5, 64, 65, 200, 1000):
        stride = tl.anchor_stride(n)
        pts = tl.anchor_points(n, stride)
        assert pts[-1] == n - 1, (n, stride, pts)
        assert len(pts) <= max(1, tl.ANCHOR_MAX) + 1
        assert pts == sorted(set(pts))


def test_anchor_stride_capped_but_localization_still_hits(tmp_path, keys):
    """N 超过锚点上限时步距自动放大：体积有界，定位退化为「一段」但必须命中。"""
    body = _ledger(200).body()
    anchor, sealed = _seal(tmp_path, keys, body)
    payload = tl._seal_payload(sealed["seal_path"])
    anc = payload["anchors"]
    assert anc["stride"] >= 2
    assert len(anc["points"]) <= tl.ANCHOR_MAX + 1

    tampered = copy.deepcopy(body)
    tampered["entries"][140]["observation"]["severity"] = "critical"
    _rebuild(tampered)
    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    seg = res["localization"]["segment"]
    assert seg[0] <= 140 <= seg[1], seg
    assert seg[1] - seg[0] + 1 == anc["stride"], seg


def test_anchor_stride_zero_falls_back_to_head_only(tmp_path, keys):
    """显式关掉锚点 = 0.7.4 行为：仍能判 INVALID，但定位能力归零（供体积敏感场景选择）。"""
    body = _ledger(20).body()
    anchor, sealed = _seal(tmp_path, keys, body, anchor_stride=0)
    assert "anchors" not in (tl._seal_payload(sealed["seal_path"]) or {})

    tampered = copy.deepcopy(body)
    tampered["entries"][9]["observation"]["severity"] = "critical"
    _rebuild(tampered)
    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["localization"]["mode"] == "none"
    assert res["localization"]["segment"] is None


def test_require_anchors_rejects_downgraded_legacy_seal(tmp_path, keys):
    """默认策略向后兼容（旧凭证仍可验），显式要求锚点时旧凭证必须被拒。"""
    body = _ledger(16).body()
    anchor, sealed = _seal(tmp_path, keys, body, anchor_stride=0)

    lenient = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor)
    assert lenient["verdict"] == "VALID", lenient["reason"]

    strict = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                    require_anchors=True)
    assert strict["verdict"] == "INVALID"
    assert strict["reason"] == "E_TRACE_ANCHORS_ABSENT"


def test_inconsistent_anchors_blocked_even_if_head_matches(tmp_path, keys):
    """防御性拦截：签发方给出一致 head/digest 但锚点取自另一条轨迹 → E_TRACE_ANCHOR_MISMATCH。"""
    from swordholder import exit_guard

    body = _ledger(8).body()
    alien = tl.TraceLedger(trace_id="TR-1", actor="qwen3:8b")
    for i in range(8):
        alien.append("tool_%d" % i, {"host": "build-runner-99", "i": i},
                     {"severity": "high", "ok": False}, ts="2026-11-13T10:0%d:00Z" % i)

    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    payload = {"record_id": body["trace_id"], "trace_id": body["trace_id"],
               "actor": body["actor"], "step_count": body["step_count"],
               "head": body["head"], "digest": tl.body_digest(body),
               "anchors": tl.build_anchors(alien.body(), stride=1)}
    out = str(tmp_path / "malicious.seal.json")
    exit_guard.judge("cli:seal", payload, basis="attested")
    exit_guard.issue_credential(payload, keys["private_key_path"], "soc-agent",
                               exit_name="cli:seal", subject=body["trace_id"],
                               out_path=out)

    res = tl.verify_sealed_trace(body, out, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_TRACE_ANCHOR_MISMATCH"


def test_divergence_from_step0_flags_unbounded_span(tmp_path, keys):
    """边界诚实性：分叉点落在第 0 步时，改动跨度不可收窄，必须显式标 span_unbounded。

    「只改第 0 步并整链重算」与「整条根本是另一条轨迹」在锚点向量上完全等价，
    所以此时 segment=[0,0] 只能当**分叉点**读，不能被当成「改动范围就是一步」。
    """
    body = _ledger(12).body()
    anchor, sealed = _seal(tmp_path, keys, body)

    tampered = copy.deepcopy(body)
    tampered["entries"][0]["observation"]["severity"] = "critical"
    _rebuild(tampered)
    res = tl.verify_sealed_trace(tampered, sealed["seal_path"], keys_path=anchor)
    loc = res["localization"]
    assert res["verdict"] == "INVALID"
    assert loc["mode"] == "anchor"
    assert loc["segment"] == [0, 0]
    assert loc.get("span_unbounded") is True
    assert loc.get("note") == "divergence_from_step0"

    # 非第 0 步的篡改不该带这个标记，避免「一律降级为不可定位」
    mid = copy.deepcopy(body)
    mid["entries"][7]["observation"]["severity"] = "critical"
    _rebuild(mid)
    loc2 = tl.verify_sealed_trace(mid, sealed["seal_path"], keys_path=anchor)["localization"]
    assert loc2["segment"] == [7, 7]
    assert not loc2.get("span_unbounded")


def test_no_false_positive_across_sizes_with_anchors(tmp_path, keys):
    """零误报是最高优先级性质：带上锚点后 1..48 步逐一盖章+验签都必须 VALID。"""
    anchor = str(tmp_path / "trusted_keys.json")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-trace")
    for n in range(1, 49):
        body = _ledger(n).body()
        sealed = tl.seal_trace(body, keys["private_key_path"], issuer="soc-agent",
                               out_path=str(tmp_path / ("n%02d.seal.json" % n)))
        res = tl.verify_sealed_trace(body, sealed["seal_path"], keys_path=anchor,
                                     require_anchors=True)
        assert res["verdict"] == "VALID", (n, res["reason"])
        assert res["localization"]["segment"] is None
        assert res["localization"]["exact"] is True
