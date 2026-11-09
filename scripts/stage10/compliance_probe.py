# -*- coding: utf-8 -*-
"""S10：把"条文要求"逐条变成可执行探针，避免用形容词回答合规。（v2，见文末 CLAUSE 变更记录）

设计原则
--------
1. 一条条文对应一个探针，探针只回答"能不能做到"，不回答"做得好不好"。
2. 结果只有三档：PASS（有实测支撑的满足）/ PARTIAL（有能力但缺机制或需上层约定）/
   FAIL（不具备）。**不存在"基本满足"这种档位**——那是把缺口写成成绩的常见手法。
3. 每条探针都要带一个可复算的数字或可复核的代码事实（键集合、grep 命中数、检出计数）。

输出 ``evidence/stage10/s10_probes.json``。

用法::

    python scripts/stage10/compliance_probe.py --out evidence/stage10/s10_probes.json
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

try:  # 0.8.0 新增；在 0.7.x 上跑同一探针时必须降级为"模块不存在"，而不是 ImportError 崩掉
    from swordholder import retention as rt  # noqa: E402
except Exception:  # pragma: no cover - 仅用于跨版本对照
    rt = None

LEDGER = os.path.join(REPO, "swordholder", "trace_ledger.py")
RETENTION = os.path.join(REPO, "swordholder", "retention.py")


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


def build_dated(n: int, trace_id: str, start: str) -> dict:
    """带起点时间的轨迹体（留存期要有起点才算得出来，start_ts 与首步 ts 都给）。"""
    led = tl.TraceLedger(trace_id=trace_id, actor="agent:s10-probe", start_ts=start)
    for i in range(n):
        led.append("tool_call_%02d" % i, {"i": i}, {"ok": True}, ts=start)
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
    """Art.12(3)：Annex III 1(a) 四个必备字段——键集合命中 + 写入即强制 + 字段入链 + 封章可验。

    0.8.0 起判定口径比 S9 严格（S9 只看默认档位键集合是否命中）：

    - A 段仍如实记录**默认档位**的命中率（0/4）——不因为开了档位就把老结构说成合规；
    - B 段在 ``profile="annex3-1a"`` 下要求 4/4 命中；
    - C 段要求缺字段**拒写**（6 种缺项全部抛 TraceError），而不是"记下来再提醒"；
    - D 段要求字段**进哈希链**：改 period.end 后不重算链必须断在该步，且封章校验判 INVALID。
      只加字段不入链是假合规——字段能被悄悄改，链还照样验过。
    """
    required = {
        "period_start_and_end": ["start_ts", "end_ts", "period", "duration"],
        "reference_database": ["database_ref", "db_ref", "reference_database", "corpus"],
        "input_data_matched": ["input_data", "matched_input", "query", "probe"],
        "identity_verification_14_5": ["identity_check", "id_verification", "verification_14_5"],
    }

    def _hit(keyset):
        h = {k: [f for f in fields if f in keyset] for k, fields in required.items()}
        return h, sum(1 for v in h.values() if v)

    # A. 默认档位：0.7.x 结构原封不动，命中率必须照实写
    default_keys = sorted(build(3, "S10-A3-DEFAULT")["entries"][0].keys())
    default_hit, default_covered = _hit(default_keys)

    # B. annex3-1a 档位：三步都为"检索命中 + 人工核验"
    prof_body, prof_keys, prof_hit, prof_covered, profile_supported = {}, [], {}, 0, True
    try:
        led = tl.TraceLedger(trace_id="S10-A3", actor="agent:s10-probe", profile="annex3-1a",
                             start_ts="2026-03-01T08:00:00Z")
        for i in range(3):
            led.append(
                "biometric_search_%02d" % i, {"probe_id": "P-%03d" % i}, {"match": True},
                ts="2026-03-01T08:00:%02dZ" % (i * 5),
                period={"start": "2026-03-01T08:00:%02dZ" % (i * 5),
                        "end": "2026-03-01T08:00:%02dZ" % (i * 5 + 3)},
                db_ref="mugshot-db@2026.02.28", matched=True,
                matched_input={"sha256": "%064x" % (i + 1)},
                verified_by="op:7721", verify_method="two_person_review")
        prof_body = led.body()
        prof_keys = sorted(prof_body["entries"][0].keys())
        prof_hit, prof_covered = _hit(prof_keys)
    except (tl.TraceError, TypeError) as exc:
        profile_supported = False
        prof_body = {"error": "%s: %s" % (type(exc).__name__, exc)}

    # C. 缺项必须拒写（拒写 = 日志里不会出现合规空档）
    reject_cases = {
        "no_period": {},
        "period_without_end": {"period": {"start": "2026-03-01T08:00:00Z"}},
        "period_end_before_start": {"period": {"start": "2026-03-01T08:00:05Z",
                                               "end": "2026-03-01T08:00:00Z"}},
        "no_db_ref": {"period": {"start": "2026-03-01T08:00:00Z",
                                 "end": "2026-03-01T08:00:03Z"}},
        "matched_without_input": {"period": {"start": "2026-03-01T08:00:00Z",
                                             "end": "2026-03-01T08:00:03Z"},
                                  "db_ref": "mugshot-db@2026.02.28", "matched": True},
        "no_identity_check": {"period": {"start": "2026-03-01T08:00:00Z",
                                         "end": "2026-03-01T08:00:03Z"},
                              "db_ref": "mugshot-db@2026.02.28"},
    }
    rejects = {}
    for name, kw in reject_cases.items():
        try:
            tl.TraceLedger(trace_id="S10-A3-NEG", profile="annex3-1a").append(
                "biometric_search", {"probe_id": "P-000"}, {"match": True}, **kw)
            rejects[name] = "WRITTEN_WITHOUT_FIELD"
        except tl.TraceError as exc:
            rejects[name] = str(exc).split(":", 1)[0]
        except TypeError:
            rejects[name] = "PROFILE_UNSUPPORTED"
    rejected = sum(1 for v in rejects.values() if v.startswith("E_"))

    # D. 字段进链：只改 period.end、不重算哈希 → 必须断在该步，且封章判 INVALID
    field_binding = {"chain_first_break": None, "seal_verdict": None,
                     "seal_segment": None, "detected": False}
    if profile_supported:
        tampered = copy.deepcopy(prof_body)
        tampered["entries"][1]["period"]["end"] = "2030-01-01T00:00:00Z"
        chain_res = tl.verify_chain(tampered)
        sealed = tl.seal_trace(prof_body, keys["private_key_path"], issuer="s10-probe",
                               out_path=os.path.join(tmp, "s10_annex3.seal.json"))
        seal_res = tl.verify_sealed_trace(tampered, sealed["seal_path"],
                                         keys_path=keys["trust_path"])
        field_binding = {
            "chain_ok_after_field_edit": chain_res["ok"],
            "chain_first_break": chain_res.get("first_break"),
            "seal_verdict": seal_res["verdict"],
            "seal_reason": seal_res.get("reason"),
            "seal_segment": seal_res["localization"].get("segment"),
            "detected": (not chain_res["ok"]) and chain_res.get("first_break") == 1,
        }
        # E. 档位声明本身也进摘要：把 profile 删掉冒充普通轨迹，凭证必须对不上
        downgraded = copy.deepcopy(prof_body)
        downgraded.pop("profile", None)
        down_res = tl.verify_sealed_trace(downgraded, sealed["seal_path"],
                                          keys_path=keys["trust_path"])
        field_binding["profile_downgrade_verdict"] = down_res["verdict"]
        field_binding["profile_downgrade_reason"] = down_res.get("reason")
        field_binding["profile_downgrade_detected"] = (
            down_res["verdict"] == "INVALID"
            and str(down_res.get("reason", "")).startswith("E_TRACE_DIGEST_MISMATCH"))

    ok = (prof_covered == 4 and rejected == len(reject_cases)
          and field_binding["detected"] and field_binding["seal_verdict"] == "INVALID"
          and field_binding.get("profile_downgrade_detected") is True)
    if not profile_supported:
        note = ("本仓库版本的 TraceLedger 不接受 profile 档位（0.7.x 无此参数）：四项必备字段命中 "
                "%d/4，缺项无法在写入时拦截（%s），字段改值后链是否断无法判定。"
                "Art.12(3) 要求的起止时段、参考数据库、命中输入、身份核验四项均无落点，判 FAIL。"
                % (default_covered, ",".join(sorted(set(rejects.values())))))
        return probe_pid(
            "P04", "EU AI Act Art.12(3) (Annex III 1(a))",
            "logging shall include at least the period of each use, the reference database, the "
            "input data that led to a match, and the verification of the natural person per "
            "Article 14(5)",
            "FAIL",
            {"profile_supported": False, "default_profile": {"entry_keys": default_keys,
                                                             "covered_of_4": default_covered},
             "write_time_enforcement": {"cases": rejects}, "field_hash_binding": field_binding},
            note)

    note = (
        "annex3-1a 档位下 4 项必备字段命中 %d/4，缺项拒写 %d/%d（错误码：%s），"
        "字段入链后只改 period.end 即在第 %s 步断链、封章校验判 %s（segment=%s），"
        "把 profile 档位删掉冒充普通轨迹则凭证判 %s（%s）。"
        "**默认档位仍是 %d/4**——本库不默认采集生物特征检索字段，"
        "Art.12(3) 的覆盖是「显式启用档位 + 写入强制 + 入链可验」，不是「所有记录自动合规」。"
        % (prof_covered, rejected, len(reject_cases), ",".join(sorted(set(rejects.values()))),
           field_binding["chain_first_break"], field_binding["seal_verdict"],
           field_binding["seal_segment"],
           field_binding.get("profile_downgrade_verdict"),
           field_binding.get("profile_downgrade_reason"), default_covered))
    return probe_pid(
        "P04", "EU AI Act Art.12(3) (Annex III 1(a))",
        "logging shall include at least the period of each use, the reference database, the input "
        "data that led to a match, and the verification of the natural person per Article 14(5)",
        "PASS" if ok else ("PARTIAL" if prof_covered else "FAIL"),
        {"profile_supported": profile_supported,
         "default_profile": {"entry_keys": default_keys,
                             "required_field_hits": default_hit,
                             "covered_of_4": default_covered},
         "annex3_1a_profile": {"entry_keys": prof_keys,
                               "required_field_hits": prof_hit,
                               "covered_of_4": prof_covered},
         "write_time_enforcement": {"cases": rejects, "rejected": rejected,
                                    "of": len(reject_cases)},
         "field_hash_binding": field_binding},
        note)


def p_retention(keys: dict, tmp: str) -> dict:
    """Art.19(1)/Art.26(6)：至少六个月留存——判定从"关键词扫描"升级为"行为可复跑"。

    S9 只扫 ``trace_ledger.py`` 里有没有 retention/ttl/archive 字样，0 命中即 FAIL。
    0.8.0 把机制落到 :mod:`swordholder.retention`，探针同时要求：

    - 关键词在实现文件里**真的存在**（不是空壳注释）；
    - 声明期限低于六个月**拒绝**（法定下限是硬约束，不是默认值）；
    - 到期判定按天算得出两种状态（``retained`` / ``archive_due``）；
    - 归档副本写得出来、验得回、被改过能被发现。
    """
    pat = re.compile(r"retention|retain|ttl|expire|archive|rotate|purge|six_month|6\s*month",
                     re.I)
    scanned = {}
    hits = []
    for rel in ("swordholder/trace_ledger.py", "swordholder/retention.py"):
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            scanned[rel] = {"exists": False, "lines": 0, "hits": 0}
            continue
        lines = open(path, "r", encoding="utf-8").readlines()
        local = [(i + 1, l.strip()) for i, l in enumerate(lines) if pat.search(l)]
        scanned[rel] = {"exists": True, "lines": len(lines), "hits": len(local),
                        "sample": [l for _i, l in local[:3]]}
        hits.extend(local)

    behav = {"module_available": rt is not None, "floor_rejected": False,
             "ttl_seconds": None, "classify": {}, "archive": {}}
    ok = False
    if rt is not None:
        try:
            rt.RetentionPolicy(days=180)
            behav["floor_rejected"] = False
        except rt.RetentionError as exc:
            behav["floor_rejected"] = str(exc).startswith("E_RETENTION_BELOW_FLOOR")

        pol = rt.RetentionPolicy(days=190)
        now = "2026-09-30T00:00:00Z"
        fresh = rt.classify("2026-09-01T00:00:00Z", pol, now=now)
        mature = rt.classify("2026-01-01T00:00:00Z", pol, now=now)
        behav["policy"] = pol.to_dict()
        behav["ttl_seconds"] = pol.ttl_seconds
        behav["classify"] = {"fresh": {"state": fresh["state"], "age_days": fresh["age_days"]},
                             "mature": {"state": mature["state"], "age_days": mature["age_days"],
                                        "meets_legal_floor": mature["meets_legal_floor"]}}

        # 归档副本：写得出来 → 验得回 → 改过能发现
        body = build_dated(5, "S10-RET", "2026-01-01T00:00:00Z")
        root = os.path.join(tmp, "s10_archive")
        arc = rt.archive_record(body, root, pol, now=now)
        tamper_path = arc["path"]
        doc = json.load(open(tamper_path, encoding="utf-8"))
        doc["body"]["entries"][2]["observation"] = {"ok": False, "behind": "hidden"}
        tampered_path = os.path.join(root, "tampered_archive.json")
        json.dump(doc, open(tampered_path, "w", encoding="utf-8"), ensure_ascii=False)
        early = None
        try:
            rt.archive_record(build_dated(3, "S10-RET-EARLY", "2026-09-20T00:00:00Z"),
                              root, pol, now=now)
            early = "ARCHIVED_BEFORE_DEADLINE"
        except rt.RetentionError as exc:
            early = str(exc).split(":", 1)[0]
        behav["archive"] = {
            "written_path_rel": os.path.relpath(arc["path"], root),
            "verify_ok": arc["verified"]["ok"],
            "verify_chain_ok": arc["verified"]["chain_ok"],
            "digest_match": arc["verified"]["digest_match"],
            "sha256": arc["sha256"][:16] + "...",
            "tampered_archive_verdict": rt.verify_archive(tampered_path)["ok"],
            "tampered_archive_reason": rt.verify_archive(tampered_path)["reason"],
            "early_archive": early,
        }
        ok = (len(hits) > 0 and behav["floor_rejected"]
              and fresh["state"] == "retained" and mature["state"] == "archive_due"
              and arc["verified"]["ok"] is True
              and rt.verify_archive(tampered_path)["ok"] is False
              and early == "E_RETENTION_TOO_EARLY")

    if rt is None:
        return probe_pid(
            "P05", "EU AI Act Art.19(1) / Art.26(6)",
            "logs shall be kept for a period appropriate to the intended purpose, of at least "
            "six months",
            "FAIL",
            {"scanned_files": scanned, "retention_keyword_hits": len(hits),
             "behavior": {"module_available": False}},
            "本仓库版本没有留存期模块：trace_ledger.py 内 retention/ttl/archive/rotate 关键词命中 "
            "0 处，记录存多久、何时归档、归档后还能不能验，全凭部署方自觉。"
            "Art.19(1)/Art.26(6) 的六个月留存无一字落地，判 FAIL。")

    note = (
        "留存期机制落在 swordholder/retention.py：法定下限 %d 天，声明 180 天被拒（%s），"
        "声明 190 天时 29 天记录仍 retained、272 天记录 archive_due；归档副本写入后校验 "
        "chain/digest/body_sha256 全过，事后改副本内一步即被判 %s；未到期限强行归档被拒（%s）。"
        "两文件关键词命中 %d 处。**到期「可归档」不等于「可销毁」**，本库不提供删除接口。"
        % (rt.MIN_RETENTION_DAYS if rt else -1, behav["floor_rejected"],
           behav["archive"].get("tampered_archive_reason", "n/a"),
           behav["archive"].get("early_archive"), len(hits)))
    return probe_pid(
        "P05", "EU AI Act Art.19(1) / Art.26(6)",
        "logs shall be kept for a period appropriate to the intended purpose, of at least six months",
        "PASS" if ok else ("PARTIAL" if hits else "FAIL"),
        {"scanned_files": scanned, "retention_keyword_hits": len(hits),
         "behavior": behav},
        note)


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
    ap.add_argument("--out", default=os.path.join(REPO, "evidence/stage10/s10_probes.json"))
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
    doc = {"generated_by": "scripts/stage10/compliance_probe.py",
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
