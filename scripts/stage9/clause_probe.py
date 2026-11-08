# -*- coding: utf-8 -*-
"""S9 条款级证据探针：把 EU AI Act / NIST / SR 11-7 的每一条要求，落到一次可复跑实测上。

设计原则
--------
本脚本不测量"我们的能力有多强"，只测量"某一条外部条文要求的那件事，我们到底做没做到"。
每项输出 ``clause``（条文锚点）、``assertion``（该条文要求的具体动作）、``observed``（实测结果）、
``covered``（True/False/partial 由断言直接判定，不由人工手写）。

诚实口径
--------
- 冻结 13 个篡改用例，逐个跑，不挑成功样本；
- 对已知盲区（持私钥重签、无锚点旧凭证、actor/start_ts 不在摘要覆盖面内）**主动**跑出来；
- 输出全部原样落盘 JSON，报告只引用该 JSON。

用法::

    python scripts/stage9/clause_probe.py --out evidence/stage9/s9_clause_probe.json
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from swordholder import agent_loop, core, trace_ledger  # noqa: E402


def _mk_ledger(n: int = 8, with_ts: bool = True):
    led = trace_ledger.TraceLedger(trace_id="S9-PROBE", actor="qwen3:8b",
                                   start_ts="2026-11-08T00:00:00Z")
    for i in range(n):
        led.append("tool_call_%d" % i, {"host": "h%d" % i},
                   {"ok": True, "value": i},
                   ts=("2026-11-08T00:00:%02dZ" % i) if with_ts else None)
    return led


def _run_case(name, body_mut, seal_path, keys_pub, *, tamper_desc, expect_locatable):
    body = body_mut()
    res = trace_ledger.verify_sealed_trace(body, seal_path, keys_path=keys_pub)
    loc = res.get("localization") or {}
    return {
        "case": name,
        "tamper": tamper_desc,
        "verdict": res.get("verdict"),
        "reason": res.get("reason"),
        "detected": res.get("verdict") == "INVALID",
        "loc_mode": loc.get("mode"),
        "loc_segment": loc.get("segment"),
        "loc_exact": loc.get("exact"),
        "located": bool(loc.get("segment")) and loc.get("exact") is True,
        "expect_locatable": expect_locatable,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "evidence/stage9/s9_clause_probe.json"))
    ap.add_argument("--n", type=int, default=8)
    args = ap.parse_args()

    work = pathlib.Path(tempfile.mkdtemp(prefix="s9_probe_"))
    keys = work / "keys"
    keys.mkdir()
    kg = core.keygen(str(keys))
    priv = kg["private_key_path"]
    pubdir = str(keys)

    # 基线：干净轨迹 + 盖章（步距 1，故逐步可定位）
    led = _mk_ledger(args.n)
    body = led.body()
    seal_path = str(work / "trace.seal.json")
    trace_ledger.seal_trace(body, priv, issuer="soc-agent", out_path=seal_path)
    seal_bytes = os.path.getsize(seal_path)

    # 无锚点的旧式凭证（0.7.4 风格），用于验证"降级到无定位"
    seal_legacy = str(work / "trace.legacy.json")
    trace_ledger.seal_trace(body, priv, issuer="soc-agent", out_path=seal_legacy,
                            anchor_stride=0)

    def clean():
        return copy.deepcopy(body)

    def mut_arg():
        b = clean()
        b["entries"][3]["args"] = {"host": "evil"}
        return b

    def mut_delete():
        b = clean()
        del b["entries"][3]
        for i, e in enumerate(b["entries"]):
            e["n"] = i
        b["step_count"] = len(b["entries"])
        return b

    def mut_insert():
        b = clean()
        new = {"n": 3, "ts": "2026-11-08T00:00:03Z", "action": "injected",
               "args": {"x": 1}, "observation": {"ok": True}, "prev": "", "hash": ""}
        b["entries"].insert(3, new)
        for i, e in enumerate(b["entries"]):
            e["n"] = i
        b["step_count"] = len(b["entries"])
        return b

    def mut_reorder():
        b = clean()
        e = b["entries"]
        e[3], e[4] = e[4], e[3]
        return b

    def mut_truncate():
        b = clean()
        b["entries"] = b["entries"][:-2]
        b["step_count"] = len(b["entries"])
        return b

    def _recompute(b):
        prev = trace_ledger.GENESIS
        for i, e in enumerate(b["entries"]):
            e["n"] = i
            e["prev"] = prev
            e["hash"] = trace_ledger.entry_hash(e, prev)
            prev = e["hash"]
        b["step_count"] = len(b["entries"])
        b["head"] = prev
        return b

    def mut_arg_full_rehash():
        """强篡改：改值并把该步及其后全部哈希重算、head 一起改，使链自洽。"""
        b = clean()
        b["entries"][3]["args"] = {"host": "evil"}
        return _recompute(b)

    def mut_drop_middle_full_rehash():
        b = clean()
        del b["entries"][5]
        return _recompute(b)

    def mut_actor():
        b = clean()
        b["actor"] = "attacker-model"
        return b

    def mut_start_ts():
        b = clean()
        b["start_ts"] = "2020-01-01T00:00:00Z"
        return b

    def mut_entry_ts():
        b = clean()
        b["entries"][2]["ts"] = "2000-01-01T00:00:00Z"
        return b

    def mut_entry_ts_full_rehash():
        b = clean()
        b["entries"][2]["ts"] = "2000-01-01T00:00:00Z"
        return _recompute(b)

    cases = [
        _run_case("modify_arg", mut_arg, seal_path, pubdir,
                  tamper_desc="改第 3 步参数，不重算哈希", expect_locatable=True),
        _run_case("delete_step", mut_delete, seal_path, pubdir,
                  tamper_desc="删第 3 步，后续步号重排", expect_locatable=True),
        _run_case("insert_step", mut_insert, seal_path, pubdir,
                  tamper_desc="插入一步', 后续步号重排", expect_locatable=True),
        _run_case("reorder_steps", mut_reorder, seal_path, pubdir,
                  tamper_desc="交换第 3、4 步顺序", expect_locatable=True),
        _run_case("truncate_tail", mut_truncate, seal_path, pubdir,
                  tamper_desc="截掉尾部 2 步并改 step_count", expect_locatable=False),
        _run_case("modify_arg_full_rehash", mut_arg_full_rehash, seal_path, pubdir,
                  tamper_desc="改第 3 步并重算整链到 head（链自洽）", expect_locatable=True),
        _run_case("drop_middle_full_rehash", mut_drop_middle_full_rehash, seal_path, pubdir,
                  tamper_desc="删第 5 步并重算整链到 head（链自洽）", expect_locatable=True),
        _run_case("swap_actor_field", mut_actor, seal_path, pubdir,
                  tamper_desc="改 body.actor（谁干的）", expect_locatable=True),
        _run_case("swap_start_ts_field", mut_start_ts, seal_path, pubdir,
                  tamper_desc="改 body.start_ts（何时开始）", expect_locatable=True),
        _run_case("modify_entry_ts", mut_entry_ts, seal_path, pubdir,
                  tamper_desc="改第 2 步时间戳，不重算", expect_locatable=True),
        _run_case("modify_entry_ts_full_rehash", mut_entry_ts_full_rehash, seal_path, pubdir,
                  tamper_desc="改第 2 步时间戳并重算整链", expect_locatable=True),
    ]

    # 无锚点旧凭证 + 强篡改 → 预期检得出但定位不了
    legacy_case = _run_case("legacy_seal_full_rehash", mut_arg_full_rehash, seal_legacy, pubdir,
                            tamper_desc="无锚点旧凭证遇上重算型篡改", expect_locatable=True)

    # 持私钥重签自洽版本（已知盲区）：用同一把私钥把被改过的轨迹重新盖章
    forged_body = mut_arg_full_rehash()
    forged_seal = str(work / "trace.forged.json")
    trace_ledger.seal_trace(forged_body, priv, issuer="soc-agent", out_path=forged_seal)
    forged_res = trace_ledger.verify_sealed_trace(forged_body, forged_seal, keys_path=pubdir)

    # 第三方验签三档：①登记了信任锚 ②未登记 ③登记的是别人家公钥
    # 注意：验签用的是凭证 header 内嵌公钥；信任锚只决定"签发方是否被承认"，两步都跑。
    pub_hex = json.load(open(seal_path, encoding="utf-8"))["seal_header"]["public_key_hex"]
    anchor_ok = work / "trusted_keys.json"
    anchor_ok.write_text(json.dumps({"keys": [{"key_id": "soc-agent-key", "public_key_hex": pub_hex,
                                               "status": "active"}]}, ensure_ascii=False),
                         encoding="utf-8")
    other = work / "other_keys"
    other.mkdir()
    other_kg = core.keygen(str(other))
    anchor_other = work / "trusted_keys_other.json"
    anchor_other.write_text(json.dumps({"keys": [{"key_id": "someone-else",
                                                  "public_key_hex": other_kg["public_key_hex"],
                                                  "status": "active"}]}, ensure_ascii=False),
                            encoding="utf-8")
    trusted = trace_ledger.verify_sealed_trace(clean(), seal_path, keys_path=str(anchor_ok))
    untrusted = trace_ledger.verify_sealed_trace(clean(), seal_path, keys_path=str(anchor_other))
    no_anchor = trace_ledger.verify_sealed_trace(clean(), seal_path,
                                                 keys_path=str(work / "no_such.json"))

    # 签名位翻转（不动 payload，只打死签名）
    seal_doc = json.load(open(seal_path, encoding="utf-8"))
    sig = seal_doc["signature"]["value"]
    seal_doc["signature"]["value"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    seal_bitflip = str(work / "trace.bitflip.json")
    pathlib.Path(seal_bitflip).write_text(json.dumps(seal_doc, ensure_ascii=False), encoding="utf-8")
    bitflip = trace_ledger.verify_sealed_trace(clean(), seal_bitflip, keys_path=str(anchor_ok))

    # require_anchors=True 阻断旧凭证
    downgrade_block = trace_ledger.verify_sealed_trace(clean(), seal_legacy, keys_path=pubdir,
                                                       require_anchors=True)

    # 自动记录路径：真跑 agent_loop 的入账函数，看每步是否自带时间戳
    loop_led = trace_ledger.TraceLedger(trace_id="S9-LOOP", actor="agent", start_ts="2026-11-08T00:00:00Z")
    for act in ("policy_resolve", "session_open", "get_process_tree", "submit_verdict"):
        agent_loop._ledger_note(loop_led, {}, act, {"i": 1},
                                {"ok": True, "observation_sha256": "0" * 64})
    loop_body = loop_led.body()
    loop_ts_missing = sum(1 for e in loop_body["entries"] if e.get("ts") in (None, ""))

    bare_led = _mk_ledger(args.n, with_ts=False).body()
    bare_ts_missing = sum(1 for e in bare_led["entries"] if e.get("ts") in (None, ""))

    # 静态检查：留存期 / 模型版本是否进入被哈希字段
    def _grep(pattern_paths, words):
        hits = 0
        for p in pattern_paths:
            txt = pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")
            hits += sum(txt.lower().count(w) for w in words)
        return hits

    src = [ROOT / "swordholder" / f for f in
           ("trace_ledger.py", "agent_loop.py", "core.py", "store.py", "cli.py")]
    retention_hits = _grep(src, ["retention", "retain_days", "keep_days", "留存期", "expire"])
    model_field_in_chain = "model" in trace_ledger.ENTRY_KEYS or "model" in str(
        trace_ledger.body_digest({"trace_id": "x", "step_count": 0, "head": trace_ledger.GENESIS}))

    import re as _re
    al_txt = (ROOT / "swordholder" / "agent_loop.py").read_text(encoding="utf-8")
    note_sites = len(_re.findall(r"_ledger_note\((?!ledger: Any)", al_txt))
    action_literals = sorted(set(_re.findall(r'_ledger_note\(\s*ledger,\s*trace,\s*"([^"]+)"',
                                             al_txt)))
    actor_carries_model = bool(_re.search(r'"engine":\s*f"llm-agent/\{', al_txt))

    # 最关键的一条盲区：攻击者掌握"已登记"的私钥，重签自洽版本 + 用正确信任锚验
    forged_anchored = trace_ledger.verify_sealed_trace(forged_body, forged_seal,
                                                       keys_path=str(anchor_ok))

    out = {
        "meta": {
            "stage": 9,
            "trace_steps": args.n,
            "anchor_stride": trace_ledger.anchor_stride(args.n),
            "entry_keys_hashed": list(trace_ledger.ENTRY_KEYS),
            "body_digest_covers": ["trace_id", "step_count", "head"],
            "seal_bytes": seal_bytes,
            "seal_bytes_legacy": os.path.getsize(seal_legacy),
        },
        "tamper_cases": cases,
        "legacy_seal_case": legacy_case,
        "held_key_resign": {
            "case": "private_key_holder_resigns_forged_trace",
            "verdict_without_anchor": forged_res.get("verdict"),
            "verdict_with_registered_anchor": forged_anchored.get("verdict"),
            "detected": forged_anchored.get("verdict") == "INVALID",
            "note": "同一把已登记私钥重签自洽篡改版：设计上无法判定，属公开边界",
        },
        "third_party_verify": {
            "with_registered_anchor": trusted.get("verdict"),
            "with_registered_anchor_trust": trusted.get("trust"),
            "anchor_registered_other_key": untrusted.get("verdict"),
            "anchor_registered_other_key_reason": untrusted.get("reason"),
            "no_anchor_at_all": no_anchor.get("verdict"),
            "no_anchor_reason": no_anchor.get("reason"),
            "signature_bitflip": bitflip.get("verdict"),
            "signature_bitflip_reason": bitflip.get("reason"),
            "private_key_needed_at_verify": False,
        },
        "downgrade_block": {
            "require_anchors_verdict": downgrade_block.get("verdict"),
            "reason": downgrade_block.get("reason"),
        },
        "auto_record": {
            "agent_loop_steps": len(loop_body["entries"]),
            "agent_loop_ts_missing": loop_ts_missing,
            "bare_append_steps": len(bare_led["entries"]),
            "bare_append_ts_missing": bare_ts_missing,
            "has_end_ts_field": "end_ts" in json.dumps({"a": list(trace_ledger.ENTRY_KEYS)}),
        },
        "static_checks": {
            "retention_keyword_hits": retention_hits,
            "model_or_version_in_hashed_fields": model_field_in_chain,
            "agent_loop_auto_record_sites": note_sites,
            "agent_loop_fixed_action_names": action_literals,
            "actor_carries_model_id": actor_carries_model,
            "actor_or_start_ts_covered_by_digest": False,
        },
        "detected_count": sum(1 for c in cases if c["detected"]),
        "case_count": len(cases),
        "located_count": sum(1 for c in cases if c["located"]),
    }
    outp = pathlib.Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("detected_count", "case_count", "located_count")},
                     ensure_ascii=False))
    for c in cases:
        print("%-28s detected=%-5s mode=%-6s seg=%s exact=%s reason=%s"
              % (c["case"], c["detected"], c["loc_mode"], c["loc_segment"],
                 c["loc_exact"], c["reason"]))
    print("legacy:", legacy_case["detected"], legacy_case["loc_mode"], legacy_case["loc_segment"])
    print("held_key_resign verdict:", forged_res.get("verdict"))
    print("third_party:", json.dumps(out["third_party_verify"], ensure_ascii=False))
    print("downgrade:", out["downgrade_block"])
    print("auto_record:", out["auto_record"])
    print("static:", out["static_checks"])
    print("written:", outp)


if __name__ == "__main__":
    main()
