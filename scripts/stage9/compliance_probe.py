# -*- coding: utf-8 -*-
"""S9：把"条文要求"逐条变成可执行探针，避免用形容词回答合规。

设计原则
--------
1. 一条条文对应一个探针，探针只回答"能不能做到"，不回答"做得好不好"。
2. 结果只有三档：PASS（有实测支撑的满足）/ PARTIAL（有能力但缺机制或需上层约定）/
   FAIL（不具备）。**不存在"基本满足"这种档位**——那是把缺口写成成绩的常见手法。
3. 每条探针都要带一个可复算的数字或可复核的代码事实（键集合、grep 命中数、检出计数）。

输出 ``evidence/stage9/s9_probes.json``。

用法::

    python scripts/stage9/compliance_probe.py --out evidence/stage9/s9_probes.json
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
_VENV_SP = os.path.join(REPO, ".venv", "Lib", "site-packages")
if os.path.isdir(_VENV_SP):
    sys.path.insert(0, _VENV_SP)

from swordholder import core, trace_ledger as tl  # noqa: E402

LEDGER = os.path.join(REPO, "swordholder", "trace_ledger.py")


# ------------------------------------------------------------------ 工具
def keygen(workdir: str) -> dict:
    os.makedirs(workdir, exist_ok=True)
    keys = core.keygen(out_dir=workdir)
    trust = os.path.join(workdir, "trusted_keys.json")
    with open(trust, "w", encoding="utf-8") as fh:
        json.dump({"trust_root": "s9-probe",
                   "keys": [{"key_id": "s9-probe-001", "algorithm": "ed25519",
                             "public_key_hex": keys["public_key_hex"]}]},
                  fh, ensure_ascii=False, indent=1)
    keys["trust_path"] = trust
    return keys


def build(n: int, trace_id: str = "S9-PROBE") -> dict:
    led = tl.TraceLedger(trace_id=trace_id, actor="agent:s9-probe")
    for i in range(n):
        led.append("tool_call_%02d" % i, {"i": i}, {"ok": True})
    return led.body()


def rechain(body: dict) -> dict:
    """攻击者视角：改内容后把整链重算到 head（有能力改写记录的一方都能做）。"""
    prev = tl.GENESIS
    for i, e in enumerate(body["entries"]):
        e["n"] = i
        e["prev"] = prev
        e["hash"] = tl.entry_hash(e, prev)
        prev = e["hash"]
    body["step_count"] = len(body["entries"])
    body["head"] = prev
    return body


def probe_pid(pid: str, clause: str, requirement: str, result: str,
              evidence: dict, note: str) -> dict:
    assert result in ("PASS", "PARTIAL", "FAIL"), result
    return {"id": pid, "clause": clause, "requirement": requirement,
            "result": result, "evidence": evidence, "note": note}


# ------------------------------------------------------------------ 探针
def p_auto_record(keys: dict, tmp: str) -> dict:
    """Art.12(1) 自动记录：调用方只管 append，哈希与前后链接由记录器自己算。"""
    led = tl.TraceLedger(trace_id="S9-AUTO", actor="agent:s9-probe")
    for i in range(20):
        led.append("step_%02d" % i, {"i": i}, {"ok": True})
    body = led.body()
    chain = tl.verify_chain(body)
    # 独立重算：不依赖库内部状态，按 entry_hash 规则从 GENESIS 重走一遍
    prev, recomputed = tl.GENESIS, 0
    for e in body["entries"]:
        if tl.entry_hash(e, prev) == e["hash"]:
            recomputed += 1
        prev = e["hash"]
    return probe_pid(
        "P01", "EU AI Act Art.12(1)",
        "High-risk AI systems shall technically allow for the automatic recording of events "
        "(logs) over the lifetime of the system",
        "PASS" if (chain["ok"] and recomputed == 20) else "FAIL",
        {"steps": 20, "chain_ok": chain["ok"], "hash_independently_recomputed": recomputed,
         "manual_hash_calls_by_caller": 0},
        "20 步全部由 append 自动生成 prev/hash，调用方未做任何哈希或链接动作，"
        "第三方按同规则可独立重算 20/20 一致。")


def p_lifetime(keys: dict, tmp: str) -> dict:
    """Art.12(1) 'over the lifetime'：能否跨进程续写同一条轨迹。"""
    api = [n for n in dir(tl.TraceLedger) if not n.startswith("_")]
    has_load = any(k in api for k in ("from_body", "load", "resume", "restore"))
    # 实测：手工把既有 entries 塞回去后链是否仍可延续（证明"格式允许"，但"接口缺失"）
    body = build(10, "S9-LIFE")
    seeded = tl.TraceLedger(trace_id="S9-LIFE", actor="agent:s9-probe")
    seeded._entries = copy.deepcopy(body["entries"])  # noqa: SLF001  仅探针内部验证格式
    seeded.append("step_after_restart", {"i": 10}, {"ok": True})
    b2 = seeded.body()
    manual_ok = tl.verify_chain(b2)["ok"] and b2["step_count"] == 11
    return probe_pid(
        "P02", "EU AI Act Art.12(1) / Recital 71",
        "recording of events ... over the lifetime of the system",
        "PARTIAL" if manual_ok and not has_load else ("PASS" if has_load else "FAIL"),
        {"public_methods": api, "has_public_resume_api": has_load,
         "manual_seeded_continue_ok": manual_ok, "steps_after_manual_continue": b2["step_count"]},
        "链格式支持续写（手工注入 10 步后再 append，链自洽且 step_count=11），但**没有公开的"
        "from_body/load 接口**，跨进程续写要靠调用方自己拼 body。长生命周期记录只做到"
        "「格式可行」，未做到「接口可用」，因此记 PARTIAL。")


def p_event_taxonomy(keys: dict, tmp: str) -> dict:
    """Art.12(2)(a)(b)(c)：记录要能支撑风险情形识别 / 上市后监测 / 运行监控。"""
    body = build(3, "S9-EVENT")
    keyset = sorted(body["entries"][0].keys())
    builtin = [k for k in keyset if k in ("severity", "risk_flag", "event_type", "monitor_tag")]
    return probe_pid(
        "P03", "EU AI Act Art.12(2)(a)(b)(c)",
        "logging capabilities shall enable the recording of events relevant for (a) identifying "
        "situations presenting a risk or substantial modification; (b) post-market monitoring; "
        "(c) monitoring the operation",
        "PARTIAL" if not builtin else "PASS",
        {"entry_keys": keyset, "builtin_risk_fields": builtin,
         "free_form_payload": ["args", "observation"]},
        "记录结构里没有风险分类/严重度/监测标签之类内建字段，只能靠 args/observation 自由承载。"
        "「能记录」成立，「能按 Art.12(2) 三类用途直接筛选」不成立，记 PARTIAL。")


def p_annexiii_fields(keys: dict, tmp: str) -> dict:
    """Art.12(3)：Annex III 1(a) 类系统至少记录起止时间、参考数据库、匹配输入、身份核验。"""
    body = build(3, "S9-A3")
    keyset = sorted(body["entries"][0].keys())
    required = {
        "period_start_and_end": ["start_ts", "end_ts", "period", "duration"],
        "reference_database": ["database_ref", "db_ref", "reference_database", "corpus"],
        "input_data_matched": ["input_data", "matched_input", "query", "probe"],
        "identity_verification_14_5": ["identity_check", "id_verification", "verification_14_5"],
    }
    hit = {k: [f for f in fields if f in keyset] for k, fields in required.items()}
    covered = sum(1 for v in hit.values() if v)
    return probe_pid(
        "P04", "EU AI Act Art.12(3)",
        "for high-risk AI systems referred to in Annex III point 1(a), logging shall include at "
        "least the period of each use, the reference database, the input data that led to a match, "
        "and the verification of the natural person per Article 14(5)",
        "PASS" if covered == 4 else ("PARTIAL" if covered else "FAIL"),
        {"entry_keys": keyset, "required_field_hits": hit, "covered_of_4": covered},
        "4 项必备字段内建命中 %d/4。ts 只有单点时间，不构成「本次使用的起止时间」；"
        "参考数据库、匹配输入、身份核验均无内建字段。按 Annex III 1(a) 场景须由上层自建 schema，"
        "本库不自证覆盖。" % covered)


def p_retention(keys: dict, tmp: str) -> dict:
    """Art.19 / Art.26(6)：日志留存至少六个月——本库是否有留存/归档机制。"""
    pat = re.compile(r"retention|retain|ttl|expire|archive|rotate|purge|six_month|6\s*month",
                     re.I)
    with open(LEDGER, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    hits = [(i + 1, l.strip()) for i, l in enumerate(lines) if pat.search(l)]
    return probe_pid(
        "P05", "EU AI Act Art.19 / Art.26(6)",
        "logs shall be kept for a period appropriate to the intended purpose, of at least six months",
        "FAIL" if not hits else "PARTIAL",
        {"scanned_file": "swordholder/trace_ledger.py", "scanned_lines": len(lines),
         "retention_keyword_hits": len(hits), "hits": hits[:5],
         "record_is_static_json": True},
        "库内没有任何留存期、TTL、归档或轮转逻辑（%d 行代码 0 命中）。记录本身是静态 JSON，"
        "存多久由部署方决定——这属于「不留障碍」而不是「提供机制」，按条文记 FAIL（缺口）。"
        % len(lines))


def p_forensic_integrity(keys: dict, tmp: str) -> dict:
    """Art.73(6)：事故调查前不得改动系统——需要能证明记录未被改动、且能指出改在哪。"""
    cases = {}
    sealed = tl.seal_trace(build(20, "S9-FOR"), keys["private_key_path"], issuer="s9-probe",
                           out_path=os.path.join(tmp, "s9_for.seal.json"))
    base = build(20, "S9-FOR")

    # 1) 尾部删除 3 步（删记录＝最直接的取证破坏）
    cut = copy.deepcopy(base)
    cut["entries"] = cut["entries"][:-3]
    cut = rechain(cut)
    r = tl.verify_sealed_trace(cut, sealed["seal_path"], keys_path=keys["trust_path"])
    cases["tail_truncation_3"] = {"verdict": r["verdict"], "reason": r["reason"],
                                  "segment": r["localization"].get("segment"),
                                  "exact": r["localization"].get("exact")}

    # 2) 中间步改写（改 observation）
    mid = copy.deepcopy(base)
    mid["entries"][9]["observation"] = {"ok": False, "behind": "hidden"}
    mid = rechain(mid)
    r = tl.verify_sealed_trace(mid, sealed["seal_path"], keys_path=keys["trust_path"])
    cases["middle_step_rewrite_9"] = {"verdict": r["verdict"], "reason": r["reason"],
                                      "segment": r["localization"].get("segment"),
                                      "first_break": r["chain"].get("first_break")}

    # 3) 整条轨迹置换（拿别人的自洽轨迹顶替）
    other = build(20, "S9-OTHER")
    r = tl.verify_sealed_trace(other, sealed["seal_path"], keys_path=keys["trust_path"])
    cases["whole_trace_substitution"] = {"verdict": r["verdict"], "reason": r["reason"],
                                         "segment": r["localization"].get("segment")}

    # 4) 未改动基线（不能靠"一律报错"混过检出率）
    r = tl.verify_sealed_trace(base, sealed["seal_path"], keys_path=keys["trust_path"])
    cases["untampered_baseline"] = {"verdict": r["verdict"], "reason": r["reason"]}

    detected = sum(1 for k, v in cases.items()
                   if k != "untampered_baseline" and v["verdict"] == "INVALID")
    # 步级定位只在"同一轨迹被改"时有意义：整条置换是另一条轨迹，原锚点与新轨迹无步对应关系，
    # 强行给步号反而是误导，因此单独统计而不并入定位分母。
    step_cases = [k for k in cases if k in ("tail_truncation_3", "middle_step_rewrite_9")]
    located = sum(1 for k in step_cases if cases[k].get("segment"))
    substituted = cases["whole_trace_substitution"]["reason"]
    ok = (detected == 3 and located == len(step_cases)
          and cases["untampered_baseline"]["verdict"] == "VALID")
    return probe_pid(
        "P06", "EU AI Act Art.73(6)",
        "provider shall not perform any investigation which involves altering the AI system in a "
        "way which may affect any subsequent evaluation of the causes of the incident",
        "PASS" if ok else "PARTIAL",
        {"cases": cases, "detected": detected, "of": 3,
         "step_located": located, "step_located_of": len(step_cases),
         "substitution_identified_by": substituted,
         "baseline_verdict": cases["untampered_baseline"]["verdict"]},
        "三类取证破坏全部检出：尾部删 3 步、中间步改写都给到具体步（%d/%d），"
        "整条置换由 %s 判定——此时步级定位没有意义，不并入定位率。"
        "未改动基线仍判 VALID，说明不是靠一律报错凑检出。" % (located, len(step_cases), substituted))


def p_tamper_proof(keys: dict, tmp: str) -> dict:
    """NIST AI 600-1 MS-2.8-003 要求 tamper-proof history：持私钥者改写后自己重签，能否拦住。"""
    base = build(20, "S9-PROOF")
    sealed = tl.seal_trace(base, keys["private_key_path"], issuer="s9-probe",
                           out_path=os.path.join(tmp, "s9_proof.seal.json"))
    forged = copy.deepcopy(base)
    forged["entries"][7]["observation"] = {"ok": False, "behind": "hidden"}
    forged = rechain(forged)
    forged_seal = tl.seal_trace(forged, keys["private_key_path"], issuer="s9-probe",
                               out_path=os.path.join(tmp, "s9_proof_forged.seal.json"))
    r_forged = tl.verify_sealed_trace(forged, forged_seal["seal_path"],
                                      keys_path=keys["trust_path"])
    r_old = tl.verify_sealed_trace(forged, sealed["seal_path"], keys_path=keys["trust_path"])
    return probe_pid(
        "P07", "NIST AI 600-1 MS-2.8-003",
        "digital content transparency solutions ... to provide a tamper-proof history of the "
        "content, promote transparency, and enable traceability",
        "PASS" if r_forged["verdict"] == "INVALID" else "FAIL",
        {"forged_selfsigned_verdict": r_forged["verdict"],
         "forged_vs_original_seal_verdict": r_old["verdict"],
         "forged_vs_original_reason": r_old["reason"],
         "tamper_evident": True, "tamper_proof": False},
        "攻击者用同一把私钥改写第 7 步后重新自签，验证结果是 %s——**拦不住**。"
        "本库的准确定位是 tamper-evident（可发现改动）而非 tamper-proof（不可产生改动副本）。"
        "MS-2.8-003 的 tamper-proof 字面要求未覆盖，必须列为缺口，不得写成满足。"
        % r_forged["verdict"])


def p_error_rates(keys: dict, tmp: str) -> dict:
    """NIST AI 600-1 MS-2.7-005：要求可度量误报/漏报——引用 S8 已入库的实测。"""
    path = os.path.join(REPO, "evidence", "stage8", "s8_locate.json")
    data = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    summ = (data.get("summary") or {}).get("default_anchor", {})
    fp = (data.get("false_positive_sweep") or {}).get("default_anchor", {})
    ok = (fp.get("false_positives") == 0 and summ.get("detect_rate") == 1.0)
    return probe_pid(
        "P08", "NIST AI 600-1 MS-2.7-005",
        "Evaluate the rate of false positives and false negatives in content provenance ... for "
        "verification",
        "PASS" if ok else "PARTIAL",
        {"source": "evidence/stage8/s8_locate.json",
         "false_positive_scan_checked": fp.get("checked"),
         "false_positives": fp.get("false_positives"),
         "detect_rate": summ.get("detect_rate"), "detected": summ.get("detected"),
         "locate_rate": summ.get("locate_rate"), "exact_rate": summ.get("exact_rate"),
         "exact_span_rate": summ.get("exact_span_rate")},
        "误报有专门扫描（1..80 步未篡改 × 三配置，各 80 次，误报 %s），漏报以 detection 分母"
        "（%s/%s）给出，定位还有 exact / exact_span 两档，不是只报一个 100%%。"
        % (fp.get("false_positives"), summ.get("detected"), summ.get("cases")))


def p_continuous_tracking(keys: dict, tmp: str) -> dict:
    """NIST AI RMF MEASURE 3.1：持续识别与跟踪风险——研发期度量是否延伸为部署期跟踪。"""
    ev = sorted(os.listdir(os.path.join(REPO, "evidence"))) if os.path.isdir(
        os.path.join(REPO, "evidence")) else []
    scripts = []
    for root, _dirs, files in os.walk(os.path.join(REPO, "scripts")):
        for f in files:
            if f.endswith("_bench.py"):
                scripts.append(os.path.relpath(os.path.join(root, f), REPO))
    return probe_pid(
        "P09", "NIST AI RMF 1.0 MEASURE 3.1",
        "Approaches, personnel, and documentation are in place to regularly identify and track "
        "existing, unanticipated, and emergent AI risks based on factors such as intended and "
        "actual performance in deployed contexts",
        "PARTIAL",
        {"evidence_dirs": ev, "bench_scripts": scripts,
         "has_deployed_runtime_monitoring": False},
        "研发期度量是可复跑的（bench 脚本 + 证据 JSON 入库），但没有任何部署期持续监控/告警组件，"
        "MEASURE 3.1 的 'in deployed contexts' 只覆盖了一半。")


def p_sr_documentation(keys: dict, tmp: str) -> dict:
    """SR 11-7 Documentation：不熟悉模型的人能否据此复现理解。"""
    docs = sorted(os.listdir(os.path.join(REPO, "docs"))) if os.path.isdir(
        os.path.join(REPO, "docs")) else []
    stage_docs = [d for d in docs if d.startswith("stage")]
    return probe_pid(
        "P10", "SR 11-7 (Documentation, p.21)",
        "Documentation of model development and validation should be sufficiently detailed so that "
        "parties unfamiliar with a model can understand how the model operates, its limitations, "
        "and its key assumptions",
        "PARTIAL" if stage_docs else "FAIL",
        {"docs": docs, "stage_docs": stage_docs,
         "has_model_doc_for_examiner": False},
        "有分阶段技术文档（%d 份 stage*.md）与可复跑脚本，够工程师复现；"
        "但没有面向 examiner 的完整模型文档（假设、局限、验证报告成册），"
        "SR 11-7 要求的是后者，因此记 PARTIAL。" % len(stage_docs))


def p_external_anchor(keys: dict, tmp: str) -> dict:
    """取证保全的最后一环：锚点是否离开了被记录方自己的介质（外部时间戳/WORM）。"""
    base = build(5, "S9-ANCH")
    sealed = tl.seal_trace(base, keys["private_key_path"], issuer="s9-probe",
                          out_path=os.path.join(tmp, "s9_anch.seal.json"))
    payload = tl._seal_payload(sealed["seal_path"])  # noqa: SLF001
    keys_in_payload = sorted(payload.keys())
    return probe_pid(
        "P11", "EU AI Act Art.73(6) + Art.19",
        "forensic evidence must survive the provider's own control (external anchoring / WORM)",
        "FAIL",
        {"seal_payload_keys": keys_in_payload, "has_anchors": "anchors" in keys_in_payload,
         "external_timestamp": False, "worm_storage": False,
         "anchor_location": "inside the signed credential, on the holder's own disk"},
        "锚点确实封进了签名凭证，但凭证本身也躺在被记录方自己的磁盘上："
        "能整体删掉、能整体替换、能重签。没有外部时间戳或不可写存储，"
        "就挡不住「连证据一起处理掉」。记 FAIL（缺口）。")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "evidence/stage9/s9_probes.json"))
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        keys = keygen(tmp)
        probes = [
            p_auto_record(keys, tmp),
            p_lifetime(keys, tmp),
            p_event_taxonomy(keys, tmp),
            p_annexiii_fields(keys, tmp),
            p_retention(keys, tmp),
            p_forensic_integrity(keys, tmp),
            p_tamper_proof(keys, tmp),
            p_error_rates(keys, tmp),
            p_continuous_tracking(keys, tmp),
            p_sr_documentation(keys, tmp),
            p_external_anchor(keys, tmp),
        ]

    counts = {r: sum(1 for p in probes if p["result"] == r) for r in ("PASS", "PARTIAL", "FAIL")}
    doc = {"generated_by": "scripts/stage9/compliance_probe.py",
           "version": getattr(__import__("swordholder"), "__version__", "unknown"),
           "python": sys.version.split()[0], "counts": counts, "probes": probes}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    for p in probes:
        print("%-4s %-34s %s" % (p["id"], p["clause"][:34], p["result"]))
    print("counts:", counts)
    print("written:", args.out)


if __name__ == "__main__":
    main()
