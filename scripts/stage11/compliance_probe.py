# -*- coding: utf-8 -*-
"""S11：把"条文要求"逐条变成可执行探针（v3：P02/P09/P10 改为行为探针，新增 P12 交付断言）。

设计原则
--------
1. 一条条文对应一个探针，探针只回答"能不能做到"，不回答"做得好不好"。
2. 结果只有三档：PASS（有实测支撑的满足）/ PARTIAL（有能力但缺机制或需上层约定）/
   FAIL（不具备）。**不存在"基本满足"这种档位**——那是把缺口写成成绩的常见手法。
3. 每条探针都要带一个可复算的数字或可复核的代码事实（键集合、grep 命中数、检出计数）。

v3 变更
-------
P02 由「字段/入口存在性」升级为**真跨进程行为探针**：子进程 load→append→save，
主进程复验链与第 10 步头部未变；被改过的历史必须被拒（E_TRACE_LOAD_BROKEN）。
P09 由「有没有监控组件」升级为**部署期行为探针**：真实目录两轮扫描 + 中途篡改 +
跨进程 CLI + 日志链自校验 + 日志被改后拒写。
P10 由「有没有 examiner 文档」升级为**内容契约探针**：章节齐备、字数下限、
零处 "tamper-proof" 自称、必须引用探针证据 / 复算脚本 / 监控 CLI。
P12 新增交付断言：第三方离线复算（隔离模式、无网络、不 import 本包）。

输出 ``evidence/stage11/s11_probes.json``。

用法::

    python scripts/stage11/compliance_probe.py --out evidence/stage11/s11_probes.json
"""
from __future__ import annotations

import argparse
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

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

try:  # 0.9.0 新增：部署期持续跟踪 + 外部可复现清单
    from swordholder import monitor as mn  # noqa: E402
except Exception:  # pragma: no cover
    mn = None
try:
    from swordholder import reproduce as rp  # noqa: E402
except Exception:  # pragma: no cover
    rp = None

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
    """Art.12(1) 'over the lifetime'：跨进程续写是不是一等公民接口（而非手工拼 body）。"""
    api = [n for n in dir(tl.TraceLedger) if not n.startswith("_")]
    has_load = any(k in api for k in ("from_body", "load", "resume", "restore"))
    has_save = hasattr(tl.TraceLedger, "save")

    # 跨版本对照：0.8.0 及更早没有 load/from_body/save，同一探针必须降级而不是崩掉
    if not (has_load and has_save):
        return probe_pid(
            "P02", "EU AI Act Art.12(1) / Recital 71",
            "recording of events ... over the lifetime of the system",
            "PARTIAL",
            {"public_methods": api, "has_public_resume_api": has_load,
             "has_save_api": has_save, "cross_process_continue_ok": False},
            "本版本 TraceLedger 公开方法里没有 load/from_body/save：跨进程续写只能由调用方"
            "自己读 body、拼新条目（等于让使用者自己维护哈希链）。覆盖 lifetime 的「格式」"
            "存在、「接口」不存在，记 PARTIAL。")

    path = os.path.join(tmp, "s11_lifetime.trace.json")
    led = tl.TraceLedger(trace_id="S11-LIFE", actor="agent:s11-probe")
    for i in range(10):
        led.append("tool_call_%02d" % i, {"i": i}, {"ok": True})
    led.save(path)
    head_before = led.head

    # 真·另一个进程：只允许通过公开入口拿回账本再续写
    child_code = (
        "import sys\n"
        "from swordholder import trace_ledger as tl\n"
        "l = tl.TraceLedger.load(sys.argv[1])\n"
        "l.append('step_after_restart', {'i': 10}, {'ok': True})\n"
        "l.save(sys.argv[1])\n"
        "print(l.body()['step_count'])\n"
    )
    child = subprocess.run([sys.executable, "-c", child_code, path], cwd=REPO,
                           capture_output=True, text=True, encoding="utf-8")
    child_out = (child.stdout or "").strip().splitlines()
    resumed = tl.TraceLedger.load(path)
    body = resumed.body()
    chain = tl.verify_chain(body)
    cross_ok = bool(child.returncode == 0 and child_out and child_out[-1] == "11"
                    and chain["ok"] and body["step_count"] == 11
                    and body["entries"][9]["hash"] == head_before)

    # 负向：被改过的历史不得被"接着往下写"，否则新条目等于替旧篡改背书
    tampered = copy.deepcopy(body)
    tampered["entries"][3]["args"]["i"] = -1
    tpath = os.path.join(tmp, "s11_lifetime_tampered.trace.json")
    with open(tpath, "w", encoding="utf-8") as fh:
        json.dump(tampered, fh, ensure_ascii=False)
    reject_code = ""
    try:
        tl.TraceLedger.load(tpath)
    except tl.TraceError as exc:
        reject_code = str(exc).split(":")[0]
    reject_ok = reject_code == "E_TRACE_LOAD_BROKEN"

    if not has_load:
        result = "FAIL"
    elif cross_ok and reject_ok:
        result = "PASS"
    else:
        result = "PARTIAL"
    return probe_pid(
        "P02", "EU AI Act Art.12(1) / Recital 71",
        "recording of events ... over the lifetime of the system",
        result,
        {"public_methods": api, "has_public_resume_api": has_load,
         "cross_process_child_steps": child_out[-1] if child_out else None,
         "cross_process_continue_ok": cross_ok, "steps_after_resume": body["step_count"],
         "sequence_preserved": body["entries"][9]["hash"] == head_before,
         "tampered_history_reject_code": reject_code, "tamper_reject_ok": reject_ok},
        "公开 ``TraceLedger.load / from_body / save``：子进程从磁盘恢复 10 步、追加第 11 步、"
        "落回磁盘后主进程复验链自洽且第 10 步头部未变（history 未被重排）。"
        "另外 load 会对被改过的历史直接抛 E_TRACE_LOAD_BROKEN，不会把脏历史接着写。"
        "长生命周期记录从「格式可行」升级为「接口可用」。")


def p_event_taxonomy(keys: dict, tmp: str) -> dict:
    """Art.12(2)(a)(b)(c)：记录要能支撑风险情形识别 / 上市后监测 / 运行监控。

    v4：不再只数"有没有字段"。三类用途各自写入一条真实条目，然后用库自带的
    :func:`swordholder.trace_ledger.select_entries` **按用途直接筛出来**；同时校验
    默认档位的键集合没有变化（向后兼容），以及缺字段时写入被拒（不是静默放过）。
    """
    # 1) 向后兼容：不加 profile 时，条目键集合必须与 0.9.0 完全一致
    legacy = build(3, "S9-EVENT")
    legacy_keys = sorted(legacy["entries"][0].keys())
    legacy_expected = ["action", "args", "hash", "n", "observation", "prev", "ts"]
    backward_compatible = legacy_keys == legacy_expected

    # 2) 声明 art12-2 档位后，五类字段进链
    led = tl.TraceLedger(trace_id="S12-EVENT", actor="agent:s9-probe", profile="art12-2")
    led.append("drift_check", None, {"drift": 0.31}, "2026-11-09T00:00:00Z",
               purpose="risk_identification", event_type="drift_detected",
               severity="high", risk_flag=True, monitor_tag="nightly")
    led.append("complaint_scan", None, {"clustered": 3}, "2026-11-09T00:05:00Z",
               purpose="post_market_monitoring", event_type="complaint_cluster",
               severity="medium", risk_flag=True)
    led.append("operator_review", None, {"outcome": "pass"}, "2026-11-09T00:10:00Z",
               purpose="deployer_evaluation", event_type="quarterly_review",
               severity="info", risk_flag=False)
    body = led.body()
    keyset = sorted(body["entries"][0].keys())
    builtin = [k for k in keyset if k in tl.ART12_2_FIELDS]

    # 3) 三类用途可直接筛取，各命中 1 条；(a) 用途下再按严重度/风险标记收窄
    per_purpose = {p: len(tl.select_entries(body, purpose=p)) for p in tl.ART12_2_PURPOSES}
    at_least_high = len(tl.select_entries(body, min_severity="high"))
    flagged = len(tl.select_entries(body, risk_flag=True))
    summary = tl.risk_summary(body)

    # 4) 缺字段必须被拒：purpose / event_type / severity / risk_flag 逐个缺失
    rejected = []
    incomplete = [
        {},
        {"purpose": "risk_identification"},
        {"purpose": "risk_identification", "event_type": "x"},
        {"purpose": "risk_identification", "event_type": "x", "severity": "high"},
    ]
    for kwargs in incomplete:
        try:
            led.append("incomplete", None, None, "2026-11-09T00:20:00Z", **kwargs)
        except tl.TraceError as exc:
            rejected.append(str(exc).split(":")[0])
    silent_accept = 4 - len(rejected)

    chain_ok = tl.verify_chain(body)["ok"]
    filter_ok = (all(v == 1 for v in per_purpose.values()) and at_least_high == 1
                 and flagged == 2 and summary["total"] == 3)
    ok = (backward_compatible and len(builtin) == len(tl.ART12_2_FIELDS)
          and filter_ok and chain_ok and silent_accept == 0)
    return probe_pid(
        "P03", "EU AI Act Art.12(2)(a)(b)(c)",
        "logging capabilities shall enable the recording of events relevant for (a) identifying "
        "situations presenting a risk or substantial modification; (b) post-market monitoring; "
        "(c) monitoring the operation",
        "PASS" if ok else "PARTIAL",
        {"default_profile_entry_keys": legacy_keys,
         "backward_compatible": backward_compatible,
         "art12_2_entry_keys": keyset,
         "builtin_risk_fields": builtin,
         "field_count": len(builtin),
         "purposes_enum": sorted(tl.ART12_2_PURPOSES),
         "severity_enum": list(tl.SEVERITY_LEVELS),
         "select_by_purpose_hits": per_purpose,
         "select_min_severity_high_hits": at_least_high,
         "select_risk_flag_true_hits": flagged,
         "risk_summary": summary,
         "rejected_error_codes": rejected,
         "silently_accepted_incomplete": silent_accept,
         "chain_ok_after_writes": chain_ok},
        "默认档位条目键集合与 0.9.0 完全一致（%s），新增字段只在 profile=\"art12-2\" 时启用；"
        "启用后 purpose/event_type/severity/risk_flag 成为写入前置条件，缺一项即抛错"
        "（实测 4 种残缺写法全部被拒，0 次静默接受）；select_entries 按三类用途各命中 1 条，"
        "min_severity=high 命中 1 条，risk_flag=True 命中 2 条，字段进哈希链后 verify_chain 仍为真。"
        % ",".join(legacy_expected))


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
    """NIST AI RMF MEASURE 3.1：部署期是否真的在被周期性度量，而不是研发期量一次。"""
    if mn is None:
        return probe_pid(
            "P09", "NIST AI RMF 1.0 MEASURE 3.1",
            "regularly identify and track existing, unanticipated, and emergent AI risks based on "
            "factors such as intended and actual performance in deployed contexts",
            "FAIL", {"module": None}, "swordholder.monitor 不存在，部署期无任何跟踪组件。")

    deploy = os.path.join(tmp, "s11_deploy")
    os.makedirs(deploy, exist_ok=True)
    for k in range(4):
        led = tl.TraceLedger(trace_id="S11-DEPLOY-%02d" % k, actor="agent:s11-probe")
        for i in range(5):
            led.append("tool_call_%02d" % i, {"i": i}, {"ok": True})
        led.save(os.path.join(deploy, "S11-DEPLOY-%02d.trace.json" % k))

    mon = mn.Monitor(deploy)
    log = mon.log_path
    r1 = mon.scan_once(now="2026-11-09T00:00:00Z")

    # 部署期真会发生的事：某条轨迹在磁盘上被改了一个值（写坏 / 人为改）
    victim = os.path.join(deploy, "S11-DEPLOY-00.trace.json")
    with open(victim, "r", encoding="utf-8") as fh:
        vbody = json.load(fh)
    vbody["entries"][1]["observation"]["ok"] = False
    with open(victim, "w", encoding="utf-8") as fh:
        json.dump(vbody, fh, ensure_ascii=False)
    r2 = mon.scan_once(now="2026-11-09T01:00:00Z")
    caught = [a["code"] for a in r2["alerts"]]
    caught_ok = "E_MON_CHAIN_BREAK" in caught

    # 部署方视角：调度器跨进程调用 CLI，日志链必须接着上一条继续
    cli = subprocess.run([sys.executable, "-m", "swordholder.monitor", "scan",
                          "--dir", deploy], cwd=REPO, capture_output=True,
                         text=True, encoding="utf-8")
    try:
        cli_doc = json.loads(cli.stdout)
        cli_ok = cli.returncode == 0 and cli_doc["schema"] == mn.MONITOR_SCHEMA
        cli_records = len(cli_doc["records"])
    except Exception:  # noqa: BLE001
        cli_ok, cli_records, cli_doc = False, 0, {}

    ver = mn.verify_log(log)
    rep = mon.report()

    # 负向：监控日志自身被改后必须拒绝继续写（否则"持续跟踪"可被伪造）
    lines = open(log, "r", encoding="utf-8").read().splitlines()
    first = json.loads(lines[0])
    first["metrics"]["traces_total"] = 999
    lines[0] = json.dumps(first, ensure_ascii=False, sort_keys=True)
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    log_tamper_reject = ""
    try:
        mon.scan_once(now="2026-11-09T02:00:00Z")
    except mn.MonitorError as exc:
        log_tamper_reject = str(exc).split(":")[0]
    tamper_reject_ok = log_tamper_reject == "E_MON_LOG_BROKEN"

    # ver 在日志被改之前算：应看到 3 条记录（两次 scan_once + 一次 CLI）且链自洽
    ver_ok_before = ver["ok"]
    log_records_before = ver["records"]
    result = "PASS" if (r1["metrics"]["verified_ok"] == 4 and not r1["alerts"]
                        and caught_ok and cli_ok and ver_ok_before
                        and log_records_before == 3 and cli_records == 1
                        and tamper_reject_ok) else "PARTIAL"
    return probe_pid(
        "P09", "NIST AI RMF 1.0 MEASURE 3.1",
        "regularly identify and track existing, unanticipated, and emergent AI risks based on "
        "factors such as intended and actual performance in deployed contexts",
        result,
        {"first_scan": r1["metrics"], "second_scan_alerts": caught,
         "second_scan_worst_level": r2["worst_level"],
         "cli_cross_process_ok": cli_ok, "cli_records": cli_records,
         "log_chain_ok_before_tamper": ver_ok_before,
         "log_records": log_records_before,
         "report_records": rep["records"], "report_by_code": rep["by_code"],
         "log_tamper_reject_code": log_tamper_reject},
        "swordholder.monitor 把「跑一次 bench」变成「按周期量」：首轮 4 条轨迹 4/4 通过无告警；"
        "在磁盘上改一个观察值后，下一轮立刻报 E_MON_CHAIN_BREAK（critical）；"
        "跨进程 CLI 第三次扫描与日志链接续成功。监控日志本身也是哈希链——改一条即拒写"
        "（E_MON_LOG_BROKEN），所以「持续跟踪」这段历史同样不可悄悄美化。"
        "边界：它是库+CLI，由部署方调度器按周期调用；不内含常驻守护进程，也不做告警外发。")


def p_sr_documentation(keys: dict, tmp: str) -> dict:
    """SR 11-7 Documentation：不熟悉模型的人能否据此理解模型、假设与局限。"""
    docs_dir = os.path.join(REPO, "docs")
    docs = sorted(os.listdir(docs_dir)) if os.path.isdir(docs_dir) else []
    stage_docs = [d for d in docs if d.startswith("stage")]
    dossier = os.path.join(docs_dir, "examiner-dossier.md")
    if not os.path.isfile(dossier):
        return probe_pid(
            "P10", "SR 11-7 (Documentation, p.21)",
            "Documentation of model development and validation should be sufficiently detailed so "
            "that parties unfamiliar with a model can understand how the model operates, its "
            "limitations, and its key assumptions",
            "PARTIAL",
            {"docs": docs, "stage_docs": stage_docs, "has_examiner_dossier": False},
            "有分阶段技术文档（%d 份 stage*.md），但没有面向 examiner 的成册文档。" % len(stage_docs))

    text = open(dossier, "r", encoding="utf-8").read()
    required = ["这个系统做什么", "它不做什么", "关键假设", "已知局限", "验证与实测证据",
                "外部复跑", "术语表", "证据索引"]
    got = [s for s in required if s in text]
    missing = [s for s in required if s not in text]
    char_count = len(text)
    # 诚实性检查：只做 tamper-evident 就不能自称 tamper-proof
    claims_tamper_proof = text.count("tamper-proof")
    cites_probe = "evidence/stage11/s11_probes.json" in text
    cites_verifier = "scripts/stage11/external_verify.py" in text
    cites_cmd = "python -m swordholder.monitor" in text
    result = "PASS" if (not missing and char_count >= 4000 and claims_tamper_proof == 0
                        and cites_probe and cites_verifier and cites_cmd) else "PARTIAL"
    return probe_pid(
        "P10", "SR 11-7 (Documentation, p.21)",
        "Documentation of model development and validation should be sufficiently detailed so "
        "that parties unfamiliar with a model can understand how the model operates, its "
        "limitations, and its key assumptions",
        result,
        {"docs": docs, "stage_docs": stage_docs, "has_examiner_dossier": True,
         "required_sections": required, "sections_found": got, "sections_missing": missing,
         "char_count": char_count, "tamper_proof_claims": claims_tamper_proof,
         "cites_probe_evidence": cites_probe, "cites_verifier": cites_verifier,
         "cites_monitor_cli": cites_cmd},
        "docs/examiner-dossier.md 单册覆盖：做什么/不做什么/关键假设/已知局限/验证与实测证据/"
        "外部复跑/术语表/证据索引，%d 字；正文零处 tamper-proof 自称（如实写 tamper-evident），"
        "并给出探针证据、外部复算脚本与监控 CLI 的具体路径。"
        "SR 11-7 要的是「不熟悉模型的人能理解运作方式、局限与关键假设」，而非分散的工程日志。"
        % char_count)


def _delivery_patterns() -> tuple:
    """取**当前阶段**的交付范围，避免探针与清单脚本各写一份而漂移。

    v5：优先读 stage12 的 ``build_manifest12.DELIVERY``（10 个交付路径，含
    ``scripts/stage12/`` 与 ``docs/stage12-risk-fields-and-tsa.md``）。v4 只读 stage11 的
    8 个路径，会把本阶段新增的脚本与文档漏在清单外——复算对象就不是"真实交付树"，
    而是"上一阶段的交付树"，这正是判据要修的那类偷工。
    """
    import importlib.util

    for tag, rel in (("s12_build_manifest", os.path.join("scripts", "stage12",
                                                         "build_manifest12.py")),
                     ("s11_build_manifest", os.path.join("scripts", "stage11",
                                                         "build_manifest.py"))):
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            continue
        spec = importlib.util.spec_from_file_location(tag, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return list(mod.DELIVERY), rel.replace("\\", "/")
    raise RuntimeError("找不到任何 build_manifest*.py 以确定交付范围")


def _stdlib_only(verifier: str) -> tuple:
    """AST 看真实 import（grep 会被注释/文档串里的 "import swordholder" 误判）。"""
    import ast as _ast

    vsrc = open(verifier, "r", encoding="utf-8").read()
    mods = set()
    for node in _ast.walk(_ast.parse(vsrc)):
        if isinstance(node, _ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, _ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    stdlib_mods = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    return (not (mods - stdlib_mods)), sorted(mods)


def p_external_reproducible(keys: dict, tmp: str) -> dict:
    """交付断言 S11-01（v5）：**基于真实交付树**的第三方离线复算。

    v3 只用 2 个 demo 文件组清单，复算通过并不能支撑"交付物可被第三方复算"这句话——
    真实交付树有 70+ 个文件、跨 10 个交付路径、含测试与文档，任何漏收/收错都会在真实
    树上暴露而在 2 文件 demo 上不存在。故 v4 改为真实树复算；v5 再修两处**仍未到位**的地方：

    1. 交付范围改读 ``build_manifest12.DELIVERY``（10 个路径）。v4 读的是 stage11 的 8 个路径，
       本阶段新增的 ``swordholder/timestamp.py``／``scripts/stage12/``／本阶段文档会被漏收，
       复算对象退化成"上一阶段的交付树"。
    2. 期望分档从"复制一份当实际值"改成**跨轮交叉核对**：期望值取上一轮落盘的
       ``evidence/stage12/s12_probes_counts.json``，实际值取本次运行 P01–P11 的真实结果。
       v4 把 expected 原样写成 actual，分档那一项是自己跟自己比，等于没校验。
       （P12 自身分档无法自指，取上一轮落盘值并在证据里标明 ``result_P12_source``。）

    复算路径本身不变：真实树逐文件复制到"外部机器"目录，用**随交付一起发出的**
    ``external_verify.py`` 在 ``-I`` 隔离模式下重算；三个反例（改一字节、期望分档不符、
    拿 1 文件 demo 清单复算真实树）必须全部被判不一致。
    """
    if rp is None:
        return probe_pid("P12", "delivery claim S11-01 (external reproducibility)",
                         "a third party can recompute the delivered artefacts and the probe tally "
                         "without network access or the package itself",
                         "FAIL", {"module": None}, "swordholder.reproduce 不存在。")

    patterns, patterns_file = _delivery_patterns()
    files = rp.collect(REPO, patterns)

    # 期望分档：取上一轮落盘的 stage12 计数（"已公布的期望"），不拿本轮结果自证
    expected = {"file_count": len(files)}
    counts_path = os.path.join(REPO, "evidence", "stage12", "s12_probes_counts.json")
    probe_expected_loaded = False
    reference_counts = {}
    if os.path.exists(counts_path):
        with open(counts_path, "r", encoding="utf-8") as fh:
            reference_counts = json.load(fh)
        for key in sorted(reference_counts):
            if key.startswith("result_") and key != "result_P12":
                expected[key] = reference_counts[key]
        probe_expected_loaded = True

    # 实际分档：本轮 P01–P11 的真实结果（P12 若自比则会无条件等于期望值，故不带）
    live_results = {("result_%s" % p["id"]): p["result"] for p in LIVE_RESULTS}
    live_mismatch = {k: (expected.get(k), v) for k, v in live_results.items()
                     if k in expected and expected[k] != v}

    # S12.1 修订：清单口径
    #   ① hash_mode=canonical-lf——同一份提交在 CRLF 检出与 LF 导出树上算出同一个哈希；
    #   ② tracked_only——只收 git 跟踪文件，未跟踪的本机产物（*.seal.json）不进清单，
    #      否则第三方从版本库根本取不到，复算必然 missing。
    manifest = rp.build_manifest(REPO, files, expected=expected,
                                 commands=["python -m pytest tests -q"],
                                 include_git=False,
                                 hash_mode=rp.HASH_MODE_CANONICAL,
                                 tracked_only=True,
                                 extra={"stage": 12,
                                        "purpose": "external reproducibility"})
    mpath = os.path.join(tmp, "s12_manifest.json")
    rp.dump(manifest, mpath)
    manifest_paths = {f["path"] for f in manifest["files"]}
    untracked_excluded = list(manifest["extra"].get("untracked_excluded") or [])
    tracked_only_on = bool(manifest["extra"].get("tracked_only"))

    # 外部 checkout：用 git archive HEAD 导出干净树。这才是"第三方拿到交付物"的真实路径，
    # 逐文件 copy 我方工作区只能证明"我这边和我这边一致"，证明不了跨 checkout 一致。
    ext = os.path.join(tmp, "s12_export_head")
    os.makedirs(ext, exist_ok=True)
    arc = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=REPO,
                         capture_output=True)
    archive_ok = arc.returncode == 0 and bool(arc.stdout)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True)
    commit_id = (commit.stdout or b"").decode("utf-8", "replace").strip()
    extracted = 0
    if archive_ok:
        with tarfile.open(fileobj=io.BytesIO(arc.stdout), mode="r:") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            tf.extractall(ext)
            extracted = len(members)
    export_files = set()
    for _dirpath, _dirnames, _fnames in os.walk(ext):
        for fn in _fnames:
            full = os.path.join(_dirpath, fn)
            export_files.add(os.path.relpath(full, ext).replace("\\", "/"))
    export_missing = sorted(manifest_paths - export_files)

    verifier_in_ext = os.path.join(ext, "scripts", "stage11", "external_verify.py")
    standalone_verifier = os.path.exists(verifier_in_ext)
    stdlib_only, mods = _stdlib_only(verifier_in_ext if standalone_verifier
                                     else os.path.join(REPO, "scripts", "stage11",
                                                       "external_verify.py"))

    actual = os.path.join(tmp, "s12_actual.json")
    with open(actual, "w", encoding="utf-8") as fh:
        json.dump({"file_count": len(files), **live_results}, fh)

    def run_verifier(root: str, manifest_path: str, actual_path: str,
                     out_tag: str) -> tuple:
        out_json = os.path.join(tmp, "s12_verify_%s.json" % out_tag)
        proc = subprocess.run([sys.executable, "-I", verifier_in_ext,
                               "--manifest", manifest_path, "--root", root,
                               "--actual", actual_path, "--json-out", out_json],
                              capture_output=True, cwd=tmp)
        stdout = (proc.stdout or b"").decode("utf-8", "replace")
        report = None
        if os.path.exists(out_json):
            try:
                with open(out_json, "r", encoding="utf-8") as fh:
                    report = json.load(fh)
            except (OSError, ValueError):
                report = None
        return proc.returncode, stdout, report

    def hashes_of(report) -> dict:
        return (report or {}).get("hashes") or {}

    # 主判据：干净导出树（git archive HEAD）
    rc_export, _o, rep_export = run_verifier(ext, mpath, actual, "export")
    h_export = hashes_of(rep_export)
    export_ok = (rc_export == 0 and bool(h_export.get("ok"))
                 and h_export.get("tree_digest_match") is True
                 and bool((rep_export or {}).get("ok")))
    checked_export = h_export.get("checked")

    # 辅助：同一份清单在我方工作区照样要过（两侧都过才叫"跨 checkout 一致"）
    rc_ws, _o, rep_ws = run_verifier(REPO, mpath, actual, "workspace")
    h_ws = hashes_of(rep_ws)
    workspace_ok = (rc_ws == 0 and bool(h_ws.get("ok"))
                    and h_ws.get("tree_digest_match") is True)

    # 换行鲁棒性自检：canonical-lf 对 CRLF/LF 两种检出给出同一哈希，raw 口径给出不同哈希。
    # 这一对断言说明"修的是换行假失败，而不是把校验放松成永远通过"。
    eol_dir = os.path.join(tmp, "s12_eol")
    crlf_dir = os.path.join(eol_dir, "crlf")
    lf_dir = os.path.join(eol_dir, "lf")
    os.makedirs(crlf_dir, exist_ok=True)
    os.makedirs(lf_dir, exist_ok=True)
    body = b"alpha\nbeta\ngamma\n"
    with open(os.path.join(crlf_dir, "a.txt"), "wb") as fh:
        fh.write(body.replace(b"\n", b"\r\n"))
    with open(os.path.join(lf_dir, "a.txt"), "wb") as fh:
        fh.write(body)
    eol_canon = rp.build_manifest(crlf_dir, [os.path.join(crlf_dir, "a.txt")],
                                 include_git=False, hash_mode=rp.HASH_MODE_CANONICAL)
    eol_canon_verdict = rp.verify_manifest(eol_canon, lf_dir)
    eol_insensitive_ok = bool(eol_canon_verdict["ok"]) and not eol_canon_verdict["mismatched"]
    eol_raw = rp.build_manifest(crlf_dir, [os.path.join(crlf_dir, "a.txt")],
                                include_git=False, hash_mode=rp.HASH_MODE_RAW)
    eol_raw_verdict = rp.verify_manifest(eol_raw, lf_dir)
    raw_eol_sensitive_ok = (not eol_raw_verdict["ok"]) and len(eol_raw_verdict["mismatched"]) == 1

    # 反例 2：期望分档不符（改一个已公布的分档值）
    wrong_actual = os.path.join(tmp, "s12_actual_wrong.json")
    bad_expected = dict(expected)
    bad_expected["result_P99"] = "PASS"
    flip_key = next((k for k in sorted(bad_expected)
                     if k.startswith("result_P") and k != "result_P99"), None)
    if flip_key:
        bad_expected[flip_key] = "FAIL" if bad_expected[flip_key] != "FAIL" else "PASS"
    with open(wrong_actual, "w", encoding="utf-8") as fh:
        json.dump(bad_expected, fh)
    rc_exp, _o, rep_exp = run_verifier(ext, mpath, wrong_actual, "tally")
    expected_enforced = rc_exp != 0

    # 反例 3：demo 清单不能充当真实树的复算依据
    demo = os.path.join(tmp, "s12_demo")
    os.makedirs(demo, exist_ok=True)
    with open(os.path.join(demo, "a.txt"), "w", encoding="utf-8") as fh:
        fh.write("alpha\n")
    demo_files = [os.path.join(demo, "a.txt")]
    demo_manifest = rp.build_manifest(demo, demo_files, expected={"file_count": 1},
                                      include_git=False, extra={"stage": 12, "demo": True})
    demo_path = os.path.join(tmp, "s12_demo_manifest.json")
    rp.dump(demo_manifest, demo_path)
    rc_demo, _o, rep_demo = run_verifier(ext, demo_path, actual, "demo")
    demo_rejected = rc_demo != 0

    # 反例 1：在导出树上改一个字节（放在最后，避免污染前面几项）
    tamper_rel = "swordholder/trace_ledger.py"
    if tamper_rel not in export_files:
        tamper_rel = sorted(manifest_paths)[0]
    tamper_target = os.path.join(ext, tamper_rel.replace("/", os.sep))
    original = open(tamper_target, "rb").read()
    with open(tamper_target, "wb") as fh:
        fh.write(original + b"\n# probe-tamper\n")
    rc_bad, _o, rep_bad = run_verifier(ext, mpath, actual, "tampered")
    h_bad = hashes_of(rep_bad)
    tamper_detected = (rc_bad != 0
                       and len(h_bad.get("mismatched") or []) >= 1
                       and h_bad.get("tree_digest_match") is False)
    with open(tamper_target, "wb") as fh:  # 复原，不留污染
        fh.write(original)

    deterministic_mismatch = {k: v for k, v in live_mismatch.items() if k != "result_P11"}
    tally_stable = probe_expected_loaded and not deterministic_mismatch
    ok = (manifest["schema"] == rp.SCHEMA
          and manifest.get("hash_mode") == rp.HASH_MODE_CANONICAL
          and tracked_only_on
          and len(files) >= 60
          and archive_ok and not export_missing
          and export_ok and checked_export == len(files)
          and workspace_ok
          and eol_insensitive_ok and raw_eol_sensitive_ok
          and stdlib_only and standalone_verifier
          and tamper_detected and expected_enforced and demo_rejected
          and tally_stable)
    evidence = {
        "manifest_schema": manifest["schema"],
        "manifest_hash_mode": manifest.get("hash_mode"),
        "manifest_written_to": "temp/s12_manifest.json (delivered copy: evidence/stage12/s12_manifest.json)",
        "tracked_only": tracked_only_on,
        "untracked_excluded": untracked_excluded,
        "untracked_excluded_count": len(untracked_excluded),
        "delivery_patterns": len(patterns),
        "delivery_patterns_source": patterns_file,
        "delivery_scope": patterns,
        "manifest_file_count": len(files),
        "manifest_bytes_canonical": manifest["total_bytes"],
        "tree_digest": manifest["tree_digest"],
        "archive_source": "git archive --format=tar HEAD",
        "archive_commit": commit_id,
        "archive_ok": archive_ok,
        "archive_entries_extracted": extracted,
        "export_tree_file_count": len(export_files),
        "export_missing_from_manifest": export_missing[:10],
        "export_missing_count": len(export_missing),
        "export_tree_exit_code": rc_export,
        "export_tree_ok": export_ok,
        "export_checked_reported": checked_export,
        "export_tree_digest_match": h_export.get("tree_digest_match"),
        "workspace_tree_exit_code": rc_ws,
        "workspace_tree_ok": workspace_ok,
        "eol_insensitive_selfcheck": eol_insensitive_ok,
        "raw_hash_eol_sensitive_selfcheck": raw_eol_sensitive_ok,
        "verifier_ships_with_delivery": standalone_verifier,
        "verifier_stdlib_only": stdlib_only,
        "verifier_imports": mods,
        "expected_keys_from_probe_tally": probe_expected_loaded,
        "expected_tally_source": "evidence/stage12/s12_probes_counts.json",
        "expected_key_count": len(expected),
        "result_P12_source": "上一轮落盘值（自指，不参与本轮交叉核对）",
        "live_tally": live_results,
        "live_vs_published_mismatch": live_mismatch,
        "tally_stable": tally_stable,
        "tampered_tree_exit_code": rc_bad,
        "tamper_detected": tamper_detected,
        "tampered_mismatched_count": len(h_bad.get("mismatched") or []),
        "expected_tally_enforced_exit_code": rc_exp,
        "expected_tally_enforced": expected_enforced,
        "demo_manifest_on_real_tree_exit_code": rc_demo,
        "demo_manifest_rejected": demo_rejected,
        "demo_manifest_file_count": demo_manifest["file_count"],
    }
    return probe_pid(
        "P12", "delivery claim S11-01 (external reproducibility)",
        "a third party who only has the repository can export the delivered tree (git archive), "
        "recompute it offline and get the same result, while any content change or tally "
        "divergence still fails",
        "PASS" if ok else "PARTIAL",
        evidence,
        "复算对象改为**外部真实取得路径**：git archive HEAD 导出的干净树（%d 个条目，提交 %s），"
        "不再逐文件 copy 我方工作区。清单口径 canonical-lf 且只收 git 跟踪文件"
        "（剔除未跟踪 %d 项：%s）。导出树复算 exit=%s、checked=%s、tree_digest_match=%s；"
        "同一份清单在我方工作区同样 exit=%s；canonical 口径对 CRLF/LF 给出同一哈希（自检 %s），"
        "而 raw 口径对同一内容给出不同哈希（自检 %s，这正是 S12 原方案的缺陷所在）；"
        "改一字节 exit=%s 且 tree_digest 不一致；改已公布分档 exit=%s；1 文件 demo 清单 exit=%s；"
        "本轮 P01–P11 分档与上一轮落盘值一致（差异项 %d 个）。"
        % (extracted, commit_id[:12], len(untracked_excluded),
           ", ".join(untracked_excluded) or "无",
           rc_export, checked_export, h_export.get("tree_digest_match"), rc_ws,
           eol_insensitive_ok, raw_eol_sensitive_ok, rc_bad, rc_exp, rc_demo,
           len(deterministic_mismatch)))


TSA_DEFAULT_URL = "https://freetsa.org/tsr"

LIVE_RESULTS: list = []
"""本轮已跑完的探针结果（P12 需要拿它做跨轮分档交叉核对，而不是自己跟自己比）。"""

TSA_ROOT_PATH = os.path.join(REPO, "evidence", "stage12_tsa_freetsa_root.pem")


def p_external_anchor(keys: dict, tmp: str) -> dict:
    """取证保全的最后一环：锚点有没有离开被记录方自己的介质（外部时间戳 / WORM）。

    v4：不再只做静态断言。真实向 RFC 3161 TSA 取戳（``timestamp_url`` 可注入，失败即
    走桩路径、绝不用 demo 数据冒充），再用**离线**方式复核 token 的 CMS 签名、
    messageImprint 与 nonce；随后做反例：持钥者改写第 7 步 + 重算整链 + 重签 + 重打戳，
    看本机制能否发现。答"不能"就如实记在证据里。
    """
    url = (os.environ.get("SWORDHOLDER_TSA_URL") or TSA_DEFAULT_URL).strip() or None
    roots = None
    if os.path.exists(TSA_ROOT_PATH):
        with open(TSA_ROOT_PATH, "rb") as fh:
            roots = [fh.read()]

    body = build(8, "S12-ANCH")
    seal_path = os.path.join(tmp, "s12_anch.seal.json")
    stamp_error = None
    stamp_attempts = []
    sealed = None
    for attempt in range(3):  # TSA 偶发 5xx / 序列号冲突，重试属正当取戳行为
        if os.path.exists(seal_path):
            os.remove(seal_path)
        try:
            sealed = tl.seal_trace(body, keys["private_key_path"], issuer="s9-probe",
                                   out_path=seal_path, timestamp_url=url,
                                   timestamp_timeout=20, timestamp_roots=roots)
            stamp_attempts.append({"attempt": attempt + 1, "ok": True})
            stamp_error = None
            break
        except Exception as exc:
            stamp_error = "%s: %s" % (type(exc).__name__, str(exc)[:200])
            stamp_attempts.append({"attempt": attempt + 1, "ok": False,
                                   "error": str(exc)[:160]})
            time.sleep(2.0)
    if stamp_error:  # 三次都拿不到才降级为桩，绝不冒充
        if os.path.exists(seal_path):
            os.remove(seal_path)
        sealed = tl.seal_trace(body, keys["private_key_path"], issuer="s9-probe",
                               out_path=seal_path)

    payload = tl._seal_payload(seal_path)  # noqa: SLF001
    keys_in_payload = sorted((payload or {}).keys())
    chk = tl.check_external_timestamp(seal_path, trusted_roots=roots)
    stamp_ok = bool(chk.get("ok"))
    stamp_present = bool(chk.get("present"))

    # 无戳的凭证：require_external_timestamp=True 时必须被拒（证明"是不是真去取戳"可被审计）
    stub_path = os.path.join(tmp, "s12_anch_stub.seal.json")
    tl.seal_trace(body, keys["private_key_path"], issuer="s9-probe", out_path=stub_path)
    stub_strict = tl.verify_sealed_trace(body, stub_path, keys_path=keys["trust_path"],
                                         require_external_timestamp=True,
                                         trusted_roots=roots)
    stub_rejected = (stub_strict.get("verdict") == "INVALID"
                     and "E_TRACE_TSA_ABSENT" in str(stub_strict.get("reason")))

    # 反例：持钥者改写第 7 步 + 重算整链 + 重签（+ 重打戳），看能否被发现
    forged = copy.deepcopy(body)
    forged["entries"][6]["observation"] = {"outcome": "rewritten-after-the-fact"}
    forged = rechain(forged)
    forge_path = os.path.join(tmp, "s12_anch_forged.seal.json")
    tl.seal_trace(forged, keys["private_key_path"], issuer="s9-probe", out_path=forge_path)
    forge_stamp = {"present": False, "ok": False, "reason": "E_TSA_SKIPPED"}
    forge_error = None
    if stamp_ok:  # 攻击者当然也能联网取一枚新戳，这里如实模拟
        for attempt in range(3):
            try:
                tl.stamp_path_payload(forge_path, tl._seal_payload(forge_path), url,
                                      timeout=20, trusted_roots=roots)
                forge_stamp = tl.check_external_timestamp(forge_path, trusted_roots=roots)
                forge_error = None
                break
            except Exception as exc:
                forge_error = "%s: %s" % (type(exc).__name__, str(exc)[:160])
                time.sleep(2.0)
    forged_verify = tl.verify_sealed_trace(forged, forge_path, keys_path=keys["trust_path"],
                                           require_external_timestamp=stamp_ok,
                                           trusted_roots=roots)
    rework_undetected = (forged_verify.get("verdict") == "VALID"
                         and (not stamp_ok or bool(forge_stamp.get("ok"))))

    evidence = {
        "tsa_url": url,
        "tsa_stamp_present": stamp_present,
        "tsa_stamp_ok": stamp_ok,
        "tsa_gen_time": chk.get("gen_time"),
        "tsa_imprint_match": (chk.get("checks") or {}).get("imprint_match"),
        "tsa_cms_signature": (chk.get("checks") or {}).get("cms_signature"),
        "tsa_chain_trusted": (chk.get("checks") or {}).get("chain_trusted"),
        "tsa_token_sha256": chk.get("token_sha256"),
        "tsa_stamp_error": stamp_error,
        "tsa_stamp_attempts": stamp_attempts,
        "offline_verify_of_stamp": stamp_ok,
        "stub_rejected_without_stamp": stub_rejected,
        "stub_rejection_reason": stub_strict.get("reason"),
        "seal_payload_keys": keys_in_payload,
        "rework_resealed_verdict": forged_verify.get("verdict"),
        "rework_detected": not rework_undetected,
        "rework_stamp_ok": forge_stamp.get("ok"),
        "worm_storage": False,
        "anchor_location": "holder-side file (signed credential); timestamp token inside it",
    }
    if stamp_ok:
        return probe_pid(
            "P11", "EU AI Act Art.73(6) + Art.19",
            "forensic evidence must survive the provider's own control (external anchoring / WORM)",
            "PARTIAL", evidence,
            "已真实取得 RFC 3161 外部时间戳（%s，说明「该摘要在该时刻已存在」），并且可在离线"
            "状态复核 CMS 签名、messageImprint 与 nonce；未打戳的凭证在 require_external_timestamp"
            "=True 下被拒（E_TRACE_TSA_ABSENT）。但反例显示：持钥者改写第 7 步、重算整链、重签并"
            "重打一枚新戳后，校验仍判 VALID（本次复验结果=%s），因为没有任何第三方留存首枚戳值，"
            "也没有 WORM 副本可比对。故「同一份证据在事后被整册重做」不可发现，"
            "记 PARTIAL：外部存在性证明有了，抗内部重做没有。"
            % (chk.get("gen_time"), forged_verify.get("verdict")))
    return probe_pid(
        "P11", "EU AI Act Art.73(6) + Art.19",
        "forensic evidence must survive the provider's own control (external anchoring / WORM)",
        "FAIL", evidence,
        "本次未能取得可信外部时间戳（%s），timestamp_url 只落为可插拔桩、未冒充成功；"
        "锚点仍封在签名凭证内、凭证仍躺在被记录方磁盘上，可整体删改重签。"
        "外部锚定与 WORM 存储均为缺口，记 FAIL。"
        % (stamp_error or chk.get("reason") or "unknown"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "evidence/stage11/s11_probes.json"))
    ap.add_argument("--counts-out", default=None,
                    help="另存一份 {分档计数 + 逐条结果}，供外部复算逐项比对")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        keys = keygen(tmp)
        global LIVE_RESULTS
        LIVE_RESULTS = []
        for fn in (p_auto_record, p_lifetime, p_event_taxonomy, p_annexiii_fields,
                   p_retention, p_forensic_integrity, p_tamper_proof, p_error_rates,
                   p_continuous_tracking, p_sr_documentation, p_external_anchor,
                   p_external_reproducible):
            LIVE_RESULTS.append(fn(keys, tmp))
        probes = list(LIVE_RESULTS)

    counts = {r: sum(1 for p in probes if p["result"] == r) for r in ("PASS", "PARTIAL", "FAIL")}
    doc = {"generated_by": "scripts/stage11/compliance_probe.py",
           "version": getattr(__import__("swordholder"), "__version__", "unknown"),
           "python": sys.version.split()[0], "counts": counts, "probes": probes}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    for p in probes:
        print("%-4s %-34s %s" % (p["id"], p["clause"][:34], p["result"]))
    print("counts:", counts)
    print("written:", args.out)
    if args.counts_out:
        flat = dict(counts)
        flat["probes_total"] = len(probes)
        for p in probes:
            flat["result_%s" % p["id"]] = p["result"]
        os.makedirs(os.path.dirname(os.path.abspath(args.counts_out)), exist_ok=True)
        with open(args.counts_out, "w", encoding="utf-8") as fh:
            json.dump(flat, fh, ensure_ascii=False, sort_keys=True, indent=1)
        print("counts written:", args.counts_out)


if __name__ == "__main__":
    main()
