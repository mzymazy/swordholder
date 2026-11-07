"""命令行入口：swordholder <command>

示例：
    swordholder keygen --out keys
    swordholder seal triage.json -k keys/swordholder_ed25519_private.pem --issuer soc@example
    swordholder verify triage.seal.json --keys trusted_keys.json
    swordholder triage alert.json --format splunk --seal -k keys/... --db index.db
    echo '<splunk event>' | swordholder triage - --format splunk
    swordholder serve --port 8099 -k keys/...pem --db index.db
    swordholder query --db index.db --verdict true_positive --limit 20
    swordholder demo
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import __version__, core, exit_guard, policy_loader, rules
from .alert import AlertError

DEFAULT_TRUST_HINT = "trusted_keys.json"


def _dump(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(text))[:64] or "alert"


def _open_store(db: str):
    from .store import Store
    return Store(db)


def cmd_keygen(args) -> int:
    res = core.keygen(args.out)
    exit_guard.judge("cli:keygen", {"public_key_hex": res.get("public_key_hex"),
                                    "public_key_path": res.get("public_key_path")},
                     basis="attested")
    _dump({"private_key_path": res.get("private_key_path"),
           "public_key_path": res.get("public_key_path"),
           "public_key_hex": res.get("public_key_hex"),
           "note": "私钥不要入库；把 public_key_hex 登记到 trusted_keys.json 才算建立信任锚"})
    return 0


def cmd_seal(args) -> int:
    out = args.out or (os.path.splitext(args.record)[0] + ".seal.json")
    try:
        with open(args.record, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (FileNotFoundError, NotADirectoryError, OSError) as e:
        _dump({"ok": False, "code": "E_NOT_FOUND", "message": f"无法读取待签记录：{args.record}：{e}"})
        return 2
    except json.JSONDecodeError as e:
        _dump({"ok": False, "code": "E_BAD_JSON", "message": str(e)})
        return 2
    try:
        exit_guard.judge("cli:seal", payload, basis="attested")
        res = exit_guard.issue_credential(payload, args.key, args.issuer, exit_name="cli:seal",
                                          subject=args.subject, out_path=out,
                                          challenge=getattr(args, "challenge", None))
    except (exit_guard.JudgmentError, exit_guard.ExitIntegrityError) as e:
        _dump({"ok": False, "code": "E_JUDGMENT_DENIED", "message": f"判定未通过，拒绝签发：{e}"})
        return 3
    except core.SealError as e:
        _dump({"ok": False, "code": "E_SEAL_FAILED", "message": str(e)})
        return 3
    if args.db:
        store = _open_store(args.db)
        store.add_seal(res["seal_path"])
        store.close()
    _dump({"seal_path": res["seal_path"], "payload_sha256": res["payload_sha256"],
           "seal_id": res.get("seal_id"), "subject": res.get("subject"),
           "challenge_bound": bool(getattr(args, "challenge", None)),
           "indexed": bool(args.db)})
    return 0


def cmd_verify(args) -> int:
    res = core.verify(args.seal, keys_path=args.keys,
                      expected_challenge=getattr(args, "expect_challenge", None))
    _dump(res)
    return 0 if res.get("verdict") in ("VALID", "VALID_UNTRUSTED_KEY") else 1


def cmd_agent(args) -> int:
    exit_guard.touch("cli:agent")
    """LLM 自主分诊：模型自己取证、自己判定，结论自动盖章。"""
    from . import agent_loop
    from . import alert as alert_mod

    try:
        if args.alert == "-":
            body = sys.stdin.read()
            if not body.strip():
                _dump({"ok": False, "code": "E_EMPTY_BODY", "message": "需要一条 JSON 告警"})
                return 2
            alert = alert_mod.normalize(json.loads(body), fmt=args.format)
        else:
            alert = alert_mod.normalize_file(args.alert, fmt=args.format)
    except AlertError as e:
        _dump(e.to_dict())
        return 2
    except (json.JSONDecodeError, FileNotFoundError, NotADirectoryError, OSError) as e:
        _dump({"ok": False, "code": "E_BAD_ALERT", "message": str(e)})
        return 2

    # 会话状态：--session 给了就接着上一轮判，--session-out 把更新后的状态写回。
    from . import session as session_mod
    conversation = None
    if getattr(args, "conversation", None):
        try:
            with open(args.conversation, encoding="utf-8") as f:
                conversation = json.load(f)
            if not isinstance(conversation, list):
                raise ValueError("必须是 JSON 数组")
        except Exception as e:  # noqa: BLE001
            _dump({"ok": False, "code": "E_BAD_CONVERSATION", "message": f"{type(e).__name__}: {e}"})
            return 2
    sess = None
    if getattr(args, "session", None):
        try:
            sess = session_mod.SessionState.load(args.session)
        except session_mod.SessionError as e:
            _dump({"ok": False, "code": "E_BAD_SESSION", "message": str(e)})
            return 2

    try:
        trace = agent_loop.run_agent(alert, max_steps=args.steps,
                                     key_path=args.key, seal_out_dir=args.out_dir,
                                     verbose=args.verbose, policy_path=args.policy,
                                     conversation=conversation, session=sess,
                                     session_out=getattr(args, "session_out", None),
                                     ledger_out=getattr(args, "ledger_out", None),
                                     ledger_seal_out=getattr(args, "ledger_seal_out", None))
    except Exception as e:  # 模型不可用等：明确报错，不静默降级
        _dump({"ok": False, "code": "E_AGENT_FAILED", "message": f"{type(e).__name__}: {e}"})
        return 3

    outcome = trace.get("guardrail") or {}
    ledger = trace.get("ledger") or {}
    payload = {
        "ok": True,
        "alert_id": alert.get("alert_id"),
        "verdict": trace.get("verdict"),
        "severity": outcome.get("severity"),
        "confidence": outcome.get("confidence"),
        "engine": trace.get("engine"),
        "hypothesis": outcome.get("hypothesis"),
        "actions": outcome.get("actions"),
        "evidence_refs": outcome.get("evidence_refs"),
        "steps": [{"step": s["step"], "action": s["action"], "thought": s.get("thought")}
                  for s in trace.get("steps", [])],
        "injection_suspected": trace.get("injection_suspected"),
        "fallback_reason": trace.get("fallback_reason"),
        "seal": (trace.get("seal") or {}).get("seal_path"),
        # 账本结论随 CLI 一起给出：调用方不必再读 trace 文件就能看到
        # "这次运行的每一步是否都进了链、链自不自洽、头哈希是多少"。
        "ledger": {k: ledger.get(k) for k in ("trace_id", "step_count", "head", "path")
                   if ledger.get(k) is not None}
                  | {"chain_ok": (ledger.get("check") or {}).get("ok"),
                     "first_break": (ledger.get("check") or {}).get("first_break")},
    }
    if args.trace_out:
        os.makedirs(os.path.dirname(args.trace_out) or ".", exist_ok=True)
        with open(args.trace_out, "w", encoding="utf-8") as f:
            json.dump(trace, f, ensure_ascii=False, indent=2)
        payload["trace_path"] = args.trace_out
    _dump(payload)
    return 0 if trace.get("verdict") else 4


def cmd_triage(args) -> int:
    from_stdin = args.alert == "-"
    source = sys.stdin.read() if from_stdin else args.alert
    if from_stdin:
        if not source.strip():
            print(json.dumps({"ok": False, "code": "E_EMPTY_BODY",
                              "message": "stdin 为空，需要一条 JSON 告警"}, ensure_ascii=False))
            return 2
        try:
            source = json.loads(source)
        except json.JSONDecodeError as e:
            _dump({"ok": False, "code": "E_BAD_JSON", "message": str(e)})
            return 2
    try:
        result = core.triage_event(source, fmt=args.format, use_llm=args.llm)
    except AlertError as e:
        _dump(e.to_dict())
        return 2
    except (FileNotFoundError, NotADirectoryError, OSError):
        _dump({"ok": False, "code": "E_NOT_FOUND", "message": f"无法读取告警文件：{source}"})
        return 2
    except json.JSONDecodeError as e:
        _dump({"ok": False, "code": "E_BAD_JSON", "message": str(e)})
        return 2

    try:
        exit_guard.judge("cli:triage", result, basis="policy")
    except (exit_guard.JudgmentError, exit_guard.ExitIntegrityError) as e:
        _dump({"ok": False, "code": "E_JUDGMENT_DENIED",
               "message": f"判定未通过，拒绝产出结论：{e}"})
        return 3

    if args.seal:
        if not args.key:
            print("--seal 需要 -k 指定私钥", file=sys.stderr)
            return 2
        if from_stdin:
            record_path = os.path.join(args.out_dir, _safe(result.get("alert_id")) + ".triage.json")
        else:
            record_path = os.path.splitext(args.alert)[0] + ".triage.json"
        os.makedirs(os.path.dirname(record_path) or ".", exist_ok=True)
        with open(record_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        try:
            sealed = exit_guard.issue_credential(
                result, args.key, "swordholder-triage/" + __version__, exit_name="cli:triage",
                out_path=record_path.replace(".triage.json", ".seal.json"))
        except core.SealError as e:
            _dump({"ok": False, "code": "E_SEAL_FAILED", "message": str(e),
                   "triage": result, "record_path": record_path})
            return 3
        result = dict(result, seal=sealed["seal_path"], payload_sha256=sealed["payload_sha256"])
        if args.db:
            store = _open_store(args.db)
            store.add_seal(sealed["seal_path"])
            store.close()
            result["indexed"] = True
    _dump(result)
    return 0


def cmd_query(args) -> int:
    store = _open_store(args.db)
    try:
        rows = store.query(verdict=args.verdict, subject=args.subject, alert_id=args.alert_id,
                           since=args.since, limit=args.limit)
        stats = store.stats()
    finally:
        store.close()
    if args.json:
        _dump({"ok": True, "count": len(rows), "stats": stats, "items": rows})
        return 0
    if not rows:
        print(f"无匹配凭证（索引共 {stats['total']} 条）")
        return 0
    header = f"{'created_at':22} {'verdict':14} {'sev':8} {'alert_id':24} seal_id"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{str(r['created_at']):22} {str(r['triage_verdict']):14} "
              f"{str(r['severity']):8} {str(r['alert_id'])[:24]:24} {r['seal_id']}")
    print(f"\n共 {len(rows)} 条；索引总计 {stats['total']} 条 {stats['by_verdict']}")
    return 0


# ---------------------------------------------------------------- trust 治理

def _trust_mod():
    from . import trust
    return trust


def _read_pubkey_file(path: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("公钥不是 ed25519")
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw).hex()


def _seal_id_from(target: str) -> str:
    if os.path.exists(target):
        with open(target, "r", encoding="utf-8") as f:
            doc = json.load(f)
        seal_id = (doc.get("seal_header") or {}).get("seal_id")
        if not seal_id:
            raise ValueError(f"文件里没有 seal_header.seal_id：{target}")
        return str(seal_id)
    return target


def cmd_trust_show(args) -> int:
    trust = _trust_mod()
    info = trust.summary(args.keys_file)
    if args.json:
        _dump(info)
        return 0 if info["loaded"] else 1
    print(f"信任根：{info.get('trust_root') or '（未设置）'}")
    print(f"锚文件：{info.get('keys_path')}")
    print(f"锚数量：{info['counts']['total']}  {info['counts']['by_status']}")
    if info["keys"]:
        print(f"\n{'key_id':<24} {'status':<10} {'state':<10} {'not_after':<22} replaced_by")
        for k in info["keys"]:
            print(f"{k['key_id']:<24} {k['status']:<10} {k['state']:<10} "
                  f"{str(k.get('not_after') or '-'):<22} {k.get('replaced_by') or '-'}")
    print(f"\n已吊销凭证：{info['revoked_seal_count']} 份")
    for r in info["revoked_seals"][:20]:
        print(f"  - {r['seal_id']}  {r.get('revoked_at') or ''}  {r.get('reason') or ''}")
    if not info["loaded"]:
        print("警告：锚文件缺失或无法解析，验签只会得到 VALID_UNTRUSTED_KEY")
        return 1
    return 0


def cmd_trust_check(args) -> int:
    trust = _trust_mod()
    res = trust.check_rotation(args.keys_file)
    _dump(res)
    return 0 if not res["warnings"] else 2


def cmd_trust_add(args) -> int:
    trust = _trust_mod()
    pub = args.pubkey
    if not pub and args.pubkey_file:
        try:
            pub = _read_pubkey_file(args.pubkey_file)
        except Exception as e:
            print(f"读取公钥失败：{e}", file=sys.stderr)
            return 1
    if not pub:
        print("必须提供 --pubkey 或 --pubkey-file", file=sys.stderr)
        return 1
    exit_guard.judge("cli:trust_add", {"pubkey": pub, "key_id": args.key_id},
                     basis="attested")
    try:
        res = trust.add_key(args.keys_file, pub, key_id=args.key_id,
                            not_before=args.not_before, not_after=args.not_after,
                            note=args.note, trust_root=args.trust_root)
    except trust.TrustError as e:
        print(f"登记失败：{e}", file=sys.stderr)
        return 1
    _dump(res)
    return 0


def cmd_trust_retire(args) -> int:
    exit_guard.judge("cli:trust_retire", {"key_id": args.key_id, "replaced_by": args.replaced_by}, basis="attested")
    trust = _trust_mod()
    try:
        res = trust.retire_key(args.keys_file, args.key_id, at=args.at,
                               replaced_by=args.replaced_by)
    except trust.TrustError as e:
        print(f"停用失败：{e}", file=sys.stderr)
        return 1
    _dump(res)
    print("提示：窗口（not_after）之前的旧凭证仍可验通，之后由该锚签发的凭证会被判 E_KEY_EXPIRED。")
    return 0


def cmd_trust_revoke(args) -> int:
    exit_guard.judge("cli:trust_revoke", {"target": args.target, "key": bool(args.revoke_key), "seal": bool(args.revoke_seal)}, basis="attested")
    trust = _trust_mod()
    if not args.target:
        print("需要给出 key_id 或 seal_id / seal.json 路径", file=sys.stderr)
        return 1
    if args.revoke_key and args.revoke_seal:
        print("--key 与 --seal 不能同时使用，请分两次执行", file=sys.stderr)
        return 1
    if not args.revoke_key and not args.revoke_seal:
        print("必须显式指定 --key 或 --seal，避免误吊销", file=sys.stderr)
        return 1
    try:
        if args.revoke_key:
            res = trust.revoke_key(args.keys_file, args.target, reason=args.reason)
            print("注意：吊销锚会使该锚签发的所有凭证立即不可信。")
        else:
            seal_id = _seal_id_from(args.target)
            res = trust.revoke_seal(args.keys_file, seal_id, reason=args.reason)
    except (trust.TrustError, ValueError, OSError) as e:
        print(f"吊销失败：{e}", file=sys.stderr)
        return 1
    _dump(res)
    return 0


def cmd_trust_restore(args) -> int:
    exit_guard.judge("cli:trust_restore", {"seal_id": args.seal_id}, basis="attested")
    trust = _trust_mod()
    try:
        res = trust.restore_seal(args.keys_file, args.seal_id)
    except trust.TrustError as e:
        print(f"回滚失败：{e}", file=sys.stderr)
        return 1
    _dump(res)
    return 0


def cmd_exits(args) -> int:
    """出口登记表与 always-invoked 覆盖率：把"所有出口必经判定"摊开给人看。"""
    if args.selftest:
        rep = exit_guard.selftest_all()
        _dump(rep)
        return 0 if rep["ok"] else 3
    rows = [{"exit": n, "kind": s.kind, "port": s.port, "entry": s.entry, "note": s.note}
            for n, s in sorted(exit_guard.EXITS.items())]
    if args.json:
        _dump({"exits": rows, "coverage": exit_guard.coverage_report()})
        return 0
    print("%-28s%-12s%-9s%s" % ("EXIT", "KIND", "PORT", "ENTRY"))
    for r in rows:
        print("%-28s%-12s%-9s%s" % (r["exit"], r["kind"], r["port"], r["entry"]))
    mandatory = [r for r in rows if r["kind"] in exit_guard.MANDATORY_KINDS]
    print("")
    print("出口合计 %d，其中必须过判定的 %d；只读 %d"
          % (len(rows), len(mandatory), len(rows) - len(mandatory)))
    return 0


def cmd_serve(args) -> int:
    from .serve import ServerConfig, serve
    cfg = ServerConfig(host=args.host, port=args.port, out_dir=args.out,
                       key_path=args.key, issuer=args.issuer, keys_file=args.keys_file,
                       db=args.db, token=args.token, use_llm=args.llm, seal=not args.no_seal)
    serve(cfg)
    return 0


def cmd_schema(args) -> int:
    which = getattr(args, "which", "alert") or "alert"
    if which == "seal":
        from . import seal_schema
        content = seal_schema.dumps(getattr(args, "seal_version", None) or seal_schema.LATEST_VERSION)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(content)
            _dump({"ok": True, "written": os.path.abspath(args.out), "which": "seal"})
            return 0
        print(content)
        return 0
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert.schema.json")
    if args.out:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(content)
        _dump({"ok": True, "written": os.path.abspath(args.out)})
        return 0
    with open(path, "r", encoding="utf-8") as f:
        print(f.read())
    return 0


def cmd_demo(args) -> int:
    os.makedirs(args.out, exist_ok=True)
    key_path = os.path.join(args.keys, "swordholder_ed25519_private.pem")
    if not os.path.exists(key_path):
        core.keygen(args.keys)
    samples = rules.sample_alerts()
    if not samples:
        print("未找到样例告警", file=sys.stderr)
        return 2

    rows, tamper = [], None
    for path in samples:
        try:
            result = core.triage_event(path, use_llm=args.llm)
        except Exception as e:  # 单个样例畸形不应中断整场演示
            rows.append({"alert_id": os.path.basename(path), "verdict": "error",
                         "error": f"{type(e).__name__}: {e}"})
            continue
        rec = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".triage.json")
        with open(rec, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        try:
            exit_guard.judge("cli:demo", result, basis="policy")
            sealed = exit_guard.issue_credential(
                result, key_path, "swordholder-triage/" + __version__, exit_name="cli:demo",
                out_path=rec.replace(".triage.json", ".seal.json"))
        except (exit_guard.JudgmentError, exit_guard.ExitIntegrityError, core.SealError) as e:
            rows.append({"alert_id": result.get("alert_id"), "verdict": result.get("verdict"),
                         "error": f"exit_guard: {e}"})
            continue
        verdict = core.verify(sealed["seal_path"], keys_path=args.keys_file)
        rows.append({"alert_id": result.get("alert_id"), "verdict": result.get("verdict"),
                     "severity": result.get("severity"), "confidence": result.get("confidence"),
                     "source_format": (result.get("input") or {}).get("source", {}).get("format"),
                     "sealed": verdict.get("verdict"), "seal_path": sealed["seal_path"]})

    # 篡改演示
    first = rows[0]["seal_path"] if rows and rows[0].get("seal_path") else None
    if not first:
        tamper = {"verdict": "SKIPPED", "reason": "E_NO_SEALED_SAMPLE"}
    else:
        with open(first, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["payload"]["verdict"] = "false_positive"
        data["payload"]["actions"] = []
        tampered = os.path.join(args.out, "tampered.seal.json")
        with open(tampered, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tamper = core.verify(tampered, keys_path=args.keys_file)

    _dump({"rows": rows,
           "tamper": {"verdict": tamper.get("verdict"), "reason": tamper.get("reason")},
           "out_dir": args.out})
    ok = all(r["sealed"] in ("VALID", "VALID_UNTRUSTED_KEY") for r in rows) \
        and tamper.get("reason") == "E_PAYLOAD_TAMPERED"
    return 0 if ok else 1


def cmd_policy_list(args) -> int:
    rows = policy_loader.list_builtin()
    if getattr(args, "json", False):
        _dump([{"file": n, "id": i, "title": t} for n, i, t in rows])
        return 0
    print(f"内置策略包目录：{policy_loader.POLICY_DIR}\n")
    print(f"{'file':<34}{'id':<28}title")
    print("-" * 90)
    for n, i, t in rows:
        print(f"{n:<34}{i:<28}{t}")
    print(f"\n当前生效：{policy_loader.resolve_path(getattr(args, 'path', None))}")
    return 0


def cmd_policy_show(args) -> int:
    try:
        p = policy_loader.load(getattr(args, "path", None))
    except policy_loader.PolicyError as e:
        print(f"策略不可用（按失败即拒收处理）：{e}")
        return 2
    if getattr(args, "json", False):
        _dump(p)
        return 0
    print(f"策略包 {p['id']} v{p.get('version')} —— {p.get('title', '')}")
    print(f"路径：{policy_loader.resolve_path(getattr(args, 'path', None))}")
    print(f"\n判定枚举：{', '.join(p['verdicts'])}")
    print(f"严重度：  {', '.join(p['severities'])}")
    lim = p["limits"]
    print(f"\n阈值：最少取证步数 {lim['min_ok_steps']}；actions {lim['actions_min']}-{lim['actions_max']} 条；"
          f"hypothesis ≤ {lim['max_hypothesis_len']} 字")
    print(f"\n不变量（{len(p['invariants'])} 条，命中即拒收）：")
    for inv in p["invariants"]:
        print(f"  [{inv['id']}] 当 verdict = {inv['when']['verdict']} → 要求 {inv['require']}（字段 {inv['field']}）")
        print(f"        {inv.get('title', '')}")
    return 0


def cmd_policy_check(args) -> int:
    try:
        p = policy_loader.load(args.path)
    except policy_loader.PolicyError as e:
        print(f"不合法：{e}")
        return 2
    print(f"合法：{p['id']} v{p.get('version')}，{len(p['invariants'])} 条不变量")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swordholder", description="给结论盖章，让任何人能验签")
    p.add_argument("--version", action="version", version=f"swordholder {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="生成 ed25519 密钥对")
    k.add_argument("--out", default="keys")
    k.set_defaults(func=cmd_keygen)

    s = sub.add_parser("seal", help="给一份 JSON 结论盖章")
    s.add_argument("record")
    s.add_argument("-k", "--key", required=True, help="私钥 pem 路径")
    s.add_argument("--issuer", required=True)
    s.add_argument("--subject", default=None)
    s.add_argument("-o", "--out", default=None)
    s.add_argument("--db", default=None, help="写入凭证索引（sqlite）")
    s.add_argument("--challenge", default=None,
                   help="验证方挑战值（8–128 位 [A-Za-z0-9_-]）：绑定本次会话，凭证不可重放")
    s.set_defaults(func=cmd_seal)

    v = sub.add_parser("verify", help="独立验签")
    v.add_argument("seal")
    v.add_argument("--keys", default=None, help="信任锚 json；不给则只验签名，不建立信任")
    v.add_argument("--expect-challenge", dest="expect_challenge", default=None,
                   help="要求凭证绑定的挑战值；不符判 E_CHALLENGE_MISMATCH，未绑定判 E_CHALLENGE_MISSING")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("triage", help="分诊一条告警（任意已支持来源）")
    t.add_argument("alert", help="告警 JSON 路径；用 - 从 stdin 读")
    t.add_argument("--format", default="auto",
                   choices=["auto", "generic", "splunk", "sentinel", "wazuh"],
                   help="来源格式；auto 按结构特征识别，识别不出会报 E_UNKNOWN_FORMAT")
    t.add_argument("--llm", action="store_true", help="叠加本机 Ollama（可选）")
    t.add_argument("--seal", action="store_true", help="同时盖章")
    t.add_argument("-k", "--key", default=None)
    t.add_argument("--out-dir", default=".", help="stdin 输入的产物目录")
    t.add_argument("--db", default=None, help="盖章后写入凭证索引（sqlite）")
    t.set_defaults(func=cmd_triage)

    q = sub.add_parser("query", help="按结论/主体/时间检索已签发的凭证")
    q.add_argument("--db", required=True)
    q.add_argument("--verdict", default=None, help="true_positive/suspicious/false_positive")
    q.add_argument("--subject", default=None)
    q.add_argument("--alert-id", dest="alert_id", default=None)
    q.add_argument("--since", default=None, help="ISO 时间下界，如 2026-10-01")
    q.add_argument("--limit", type=int, default=20)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_query)

    ex = sub.add_parser("exits", help="出口登记表：列出全部对外出口与 always-invoked 覆盖率")
    ex.add_argument("--json", action="store_true", help="机器可读输出")
    ex.add_argument("--selftest", action="store_true",
                    help="对每个必判出口真判一次；覆盖率不到 100% 退出码 3")
    ex.set_defaults(func=cmd_exits)

    sv = sub.add_parser("serve", help="启动 HTTP 服务（triage/seal/verify/index）")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8099)
    sv.add_argument("-o", "--out", default=".seals", help="凭证落盘目录")
    sv.add_argument("-k", "--key", default=None, help="私钥 pem；不给则不签发凭证")
    sv.add_argument("--issuer", default="swordholder-serve")
    sv.add_argument("--keys-file", default=None, help="信任锚 json，给了才会返回 VALID")
    sv.add_argument("--db", default=None, help="凭证索引 sqlite")
    sv.add_argument("--token", default=None, help="Bearer token；绑非回环地址时必填")
    sv.add_argument("--llm", action="store_true")
    sv.add_argument("--no-seal", action="store_true", help="只分诊不盖章")
    sv.set_defaults(func=cmd_serve)

    sc = sub.add_parser("schema", help="输出内部告警契约 JSON Schema")
    sc.add_argument("-o", "--out", default=None)
    sc.add_argument("--which", choices=["alert", "seal"], default="alert",
                    help="输出哪份契约：告警归一（alert）或凭证结构（seal）")
    sc.add_argument("--seal-version", dest="seal_version", default=None,
                    help="--which seal 时指定版本，默认最新")
    sc.set_defaults(func=cmd_schema)

    d = sub.add_parser("demo", help="跑通内置样例：归一→分诊→盖章→验签→篡改检出")
    d.add_argument("--out", default=".demo_out")
    d.add_argument("--keys", default="keys")
    d.add_argument("--keys-file", default=None, help="信任锚 json，默认用仓库根 trusted_keys.json（如存在）")
    d.add_argument("--llm", action="store_true")
    d.set_defaults(func=cmd_demo)

    ag = sub.add_parser("agent", help="LLM 自主分诊：模型自选工具取证、自主判定并盖章（需可用的模型服务）")
    ag.add_argument("alert", help="告警 JSON 路径；用 - 从 stdin 读")
    ag.add_argument("--format", default="auto", help="auto/generic/splunk/sentinel/wazuh")
    ag.add_argument("--steps", type=int, default=7, help="最大工具调用步数，默认 7")
    ag.add_argument("-k", "--key", default=None, help="用于盖章的 ed25519 私钥；不给则只判定不盖章")
    ag.add_argument("--out-dir", default="evidence/agent_lab/runs/seals", help="凭证输出目录")
    ag.add_argument("--trace-out", default=None, help="把完整决策轨迹写入指定 JSON")
    ag.add_argument("--policy", default=None,
                    help="策略包 YAML 路径（默认取 $SWORDHOLDER_POLICY 或内置 default-soc-triage.yaml）")
    ag.add_argument("--conversation", default=None,
                    help="多轮对话 JSON（[{\"role\":\"user\",\"content\":...}]），判定将计入会话历史")
    ag.add_argument("--session", default=None,
                    help="已有会话状态 JSON：接着上一轮判，跨轮不变量据此生效")
    ag.add_argument("--session-out", default=None, help="把更新后的会话状态写回指定路径")
    ag.add_argument("--ledger-out", default=None,
                    help="把本次运行的链式动作账本写入指定 JSON（可离线 verify_chain 复核）")
    ag.add_argument("--ledger-seal-out", default=None,
                    help="给动作账本盖章输出的凭证路径；需同时给 -k/--key，链不自洽则拒绝盖章")
    ag.add_argument("--verbose", action="store_true")
    ag.set_defaults(func=cmd_agent)

    # -- policy：判定规则外置治理 -----------------------------------------------
    po = sub.add_parser("policy", help="判定策略包：列出、查看、校验（判定规则不在代码里）")
    pos = po.add_subparsers(dest="policy_cmd", required=True)

    p_ls = pos.add_parser("list", help="列出内置策略包与当前生效项")
    p_ls.add_argument("--path", default=None, help="指定生效策略，仅用于回显")
    p_ls.add_argument("--json", action="store_true")
    p_ls.set_defaults(func=cmd_policy_list)

    p_sh = pos.add_parser("show", help="显示策略包内容（判定枚举 / 阈值 / 不变量）")
    p_sh.add_argument("--path", default=None, help="策略 YAML 路径；默认当前生效项")
    p_sh.add_argument("--json", action="store_true")
    p_sh.set_defaults(func=cmd_policy_show)

    p_ck = pos.add_parser("check", help="校验一个策略文件是否合法（改完先在本地过这一关）")
    p_ck.add_argument("path")
    p_ck.set_defaults(func=cmd_policy_check)

    # -- trust：信任锚治理（轮换 / 吊销 / 体检）--------------------------------
    tr = sub.add_parser("trust", help="信任锚治理：查看、登记、轮换、吊销")
    trs = tr.add_subparsers(dest="trust_cmd", required=True)

    t_show = trs.add_parser("show", help="查看信任链与吊销列表")
    t_show.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_show.add_argument("--json", action="store_true", help="输出原始 JSON")
    t_show.set_defaults(func=cmd_trust_show)

    t_check = trs.add_parser("check", help="轮换体检：并存的 active 锚、缺失窗口等提醒")
    t_check.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_check.set_defaults(func=cmd_trust_check)

    t_add = trs.add_parser("add", help="登记一把新的信任锚")
    t_add.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_add.add_argument("--key-id", default=None)
    t_add.add_argument("--pubkey", default=None, help="64 位十六进制公钥；或用 --pubkey-file 指向 pem")
    t_add.add_argument("--pubkey-file", default=None, help="公钥 pem 路径")
    t_add.add_argument("--not-before", default=None)
    t_add.add_argument("--not-after", default=None)
    t_add.add_argument("--note", default=None)
    t_add.add_argument("--trust-root", default=None)
    t_add.set_defaults(func=cmd_trust_add)

    t_retire = trs.add_parser("retire", help="停用旧锚（保留其窗口内历史凭证的验证能力）")
    t_retire.add_argument("key_id")
    t_retire.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_retire.add_argument("--at", default=None, help="截止时刻，ISO；缺省为当前时间")
    t_retire.add_argument("--replaced-by", default=None)
    t_retire.set_defaults(func=cmd_trust_retire)

    t_revoke = trs.add_parser("revoke", help="吊销：--key 吊销密钥，--seal 吊销单份凭证")
    t_revoke.add_argument("target", nargs="?", default=None, help="key_id 或 seal_id / seal.json 路径")
    t_revoke.add_argument("--key", dest="revoke_key", action="store_true", help="吊销信任锚")
    t_revoke.add_argument("--seal", dest="revoke_seal", action="store_true", help="吊销单份凭证")
    t_revoke.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_revoke.add_argument("--reason", default=None)
    t_revoke.set_defaults(func=cmd_trust_revoke)

    t_restore = trs.add_parser("restore", help="撤销一条凭证吊销记录（误吊销回滚）")
    t_restore.add_argument("seal_id")
    t_restore.add_argument("--keys-file", default=DEFAULT_TRUST_HINT)
    t_restore.set_defaults(func=cmd_trust_restore)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
