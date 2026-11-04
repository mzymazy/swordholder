"""出口完整性验收：把"判定级授权"的 always-invoked 前提变成可证伪的测试。

reference monitor 的成立前提是"每一个对外出口都必经判定点"。这句话以前只是
架构文档里的一句声明，本文件把它拆成四组可执行的断言：

A 枚举完整性（AST 扫描代码事实）
    代码里真实存在的每个出口 —— HTTP 路由、MCP 工具、CLI 子命令 —— 都必须在
    ``exit_guard.EXITS`` 登记。新增出口却忘了登记，CI 直接红。

B 绕过注入（反例优先）
    十类"想办法不经过判定点就产出结论/凭证"的动作必须全部 fail-closed：
    无票签发、篡改 payload、跨出口复用票据、伪造票据、未登记出口、只读出口越权、
    attested 降级、环境开关、命令行开关、策略包缺失。

C 出口清偿（正例闭环）
    HTTP / MCP / CLI / Agent 四条链路各跑一遍真实请求，票据与凭证必须一一对账；
    再对全部 mandatory 出口表驱动取票，确保 coverage_report() 能到 100%。

D 签发通道唯一（静态门禁）
    除 exit_guard 之外没有任何模块能直接盖章；任何调 issue_credential 的函数体内
    必须同时出现 judge 调用（配对门禁）。

A+B+D 同时成立，"所有出口必经判定"才不是一句口号；缺任何一组，判定级授权在
语义上都会退回"事后审计"。
"""

import ast
import io
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp_server import server as mcp_srv                      # noqa: E402
from swordholder import agent_loop as al                      # noqa: E402
from swordholder import cli, core, rules                      # noqa: E402
from swordholder import exit_guard as eg                      # noqa: E402
from swordholder import policy_loader                         # noqa: E402
from swordholder.alert import normalize                       # noqa: E402
from swordholder.serve import ServerConfig, build_server      # noqa: E402

ALERT = {
    "search_name": "CI runner outbound to unregistered ASN",
    "sid": "1728.9999",
    "urgency": "high",
    "dest": "build-runner-09",
    "signature": "outbound TLS to unknown ASN 215199",
    "description": "6 long-lived TLS sessions to 198.51.100.77:443",
    "_time": "2026-11-05T03:14:00Z",
}

GOOD_RECORD = {"alert_id": "A-1", "verdict": "true_positive", "severity": "high",
               "confidence": 0.82, "hypothesis": "构建机外联未登记 ASN，疑似凭据外泄",
               "actions": ["阻断出站", "轮换 token"]}


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_runtime(monkeypatch):
    """每个用例都从"没有票据"的干净状态开始，且清掉可能残留的绕过开关。"""
    for k in list(os.environ):
        if any(m in k.upper() for m in eg.BYPASS_ENV_MARKERS):
            monkeypatch.delenv(k, raising=False)
    eg.reset_ledger()
    yield
    eg.reset_ledger()


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


@pytest.fixture()
def live(tmp_path, keys):
    cfg = ServerConfig(port=0, out_dir=str(tmp_path / "seals"),
                       key_path=keys["private_key_path"], db=str(tmp_path / "index.db"),
                       token="t0ken")
    httpd = build_server(cfg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield {"base": base, "cfg": cfg}
    httpd.shutdown()
    httpd.server_close()
    cfg.close()


def _post(url, payload, token="t0ken"):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# A 组：枚举完整性
# --------------------------------------------------------------------------- #


def _sources():
    out = []
    for d in ("swordholder", "mcp_server"):
        out.extend(sorted((ROOT / d).glob("*.py")))
    return out


def _http_routes():
    """从 serve.py 里读出真实存在的路由字面量（代码事实，不是登记表自说自话）。"""
    src = (ROOT / "swordholder/serve.py").read_text(encoding="utf-8")
    routes = set(re.findall(r'path == "(/[^"]*)"', src))
    for rx in re.findall(r're\.fullmatch\(r"(/[^"]+)"', src):
        routes.add(re.sub(r"\([^()]*\)", "<seal_id>", rx))
    return routes


def _defined_functions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]


def test_every_http_route_is_registered():
    """serve.py 里出现过的每一条路由都必须登记，否则就是一条没经过判定的出口。"""
    registered = {n for n, s in eg.EXITS.items() if s.port == eg.PORT_HTTP}
    routes = _http_routes()
    assert routes, "没有从 serve.py 里解析出任何路由，扫描逻辑失效"
    missing = [r for r in routes if f"http:{r}" not in registered]
    assert not missing, f"HTTP 出口未登记：{missing}（新出口必须先登记再动手）"


def test_every_mcp_tool_is_registered():
    registered = {n for n, s in eg.EXITS.items() if s.port == eg.PORT_MCP}
    tools = [f"mcp:{n[5:]}" for n in _defined_functions(ROOT / "mcp_server/server.py")
             if n.startswith("tool_")]
    assert len(tools) >= 5, f"MCP 工具扫描结果异常：{tools}"
    missing = [t for t in tools if t not in registered]
    assert not missing, f"MCP 出口未登记：{missing}"


def test_every_cli_command_is_registered():
    registered = {n for n, s in eg.EXITS.items() if s.port == eg.PORT_CLI}
    cmds = [f"cli:{n[4:]}" for n in _defined_functions(ROOT / "swordholder/cli.py")
            if n.startswith("cmd_")]
    assert len(cmds) >= 10, f"CLI 子命令扫描结果异常：{cmds}"
    missing = [c for c in cmds if c not in registered]
    assert not missing, f"CLI 出口未登记：{missing}"


def test_registered_entries_point_at_real_code():
    """登记表不能靠编名字过关：entry 的模块要存在，函数名要真在源码里。"""
    for name, spec in eg.EXITS.items():
        mod, _, qual = spec.entry.partition(":")
        path = ROOT / (mod.replace(".", "/") + ".py")
        assert path.exists(), f"{name} 登记的模块不存在：{mod}"
        leaf = qual.split(".")[-1]
        assert leaf in path.read_text(encoding="utf-8"), f"{name} 登记的函数 {qual} 在 {path} 里找不到"
        assert spec.kind in (eg.DECISION, eg.CREDENTIAL, eg.READONLY), f"{name} 的 kind 非法"


def test_agent_exit_is_registered():
    """Agent 结论提交是最容易被忽略的出口：它不签发文件，但在对外断言。"""
    assert eg.EXITS["agent:submit_verdict"].kind == eg.DECISION
    assert eg.EXITS["agent:seal"].kind == eg.CREDENTIAL


# --------------------------------------------------------------------------- #
# B 组：绕过注入，全部必须 fail-closed
# --------------------------------------------------------------------------- #


def test_b1_issue_without_judgment_is_rejected(tmp_path, keys):
    """没取票就签发 —— 这是最直白的绕过，必须拒。"""
    with pytest.raises(eg.ExitIntegrityError):
        eg.issue_credential(GOOD_RECORD, keys["private_key_path"], "t",
                            exit_name="http:/v1/triage",
                            out_path=str(tmp_path / "x.seal.json"))
    assert not (tmp_path / "x.seal.json").exists()


def test_b2_payload_tampered_after_judgment_is_rejected(tmp_path, keys):
    """判定时看的是 A，签发时给的是 A' —— 摘要对不上，必须拒。"""
    rec = dict(GOOD_RECORD)
    eg.judge("cli:seal", rec)
    rec["verdict"] = "false_positive"   # 判定后偷换结论
    with pytest.raises(eg.ExitIntegrityError):
        eg.issue_credential(rec, keys["private_key_path"], "t",
                            exit_name="cli:seal", out_path=str(tmp_path / "x.seal.json"))
    assert not (tmp_path / "x.seal.json").exists()


def test_b3_ticket_cannot_be_reused_across_exits(tmp_path, keys):
    """在 HTTP 口取的票，不能拿去给 CLI 口用 —— 票据绑定出口名。"""
    eg.judge("http:/v1/triage", GOOD_RECORD)
    with pytest.raises(eg.ExitIntegrityError):
        eg.issue_credential(GOOD_RECORD, keys["private_key_path"], "t",
                            exit_name="cli:seal", out_path=str(tmp_path / "x.seal.json"))


def test_b4_forged_ticket_is_rejected(tmp_path, keys):
    """直接把票据里的 verdict 改漂亮 —— MAC 不匹配，必须拒。"""
    j = eg.judge("http:/v1/triage", {**GOOD_RECORD, "verdict": "suspicious"})
    base = dict(GOOD_RECORD)
    base["verdict"] = "suspicious"
    j.verdict = "true_positive"        # 篡改票据内容
    with pytest.raises(eg.ExitIntegrityError):
        eg.require_judgment("http:/v1/triage", base)


def test_b5_attested_cannot_cover_a_verdict():
    """声明 basis=attested 想跳过策略校验 —— 只要 payload 带 verdict，就不许降级。"""
    with pytest.raises(eg.JudgmentError):
        eg.judge("mcp:seal_record", {"alert_id": "A", "verdict": "benign"}, basis="attested")


def test_b6_unregistered_exit_is_rejected():
    with pytest.raises(eg.ExitIntegrityError):
        eg.judge("http:/v1/backdoor", GOOD_RECORD)


def test_b7_readonly_exit_cannot_take_a_ticket():
    """只读出口不该产结论；给它取票说明有人想借只读路由盖章。"""
    with pytest.raises(eg.ExitIntegrityError):
        eg.judge("http:/healthz", {"ok": True})


def test_b8_env_switch_cannot_disable_judgment(monkeypatch):
    monkeypatch.setenv("SWORDHOLDER_SKIP_JUDGE", "1")
    with pytest.raises(eg.ExitIntegrityError):
        eg.judge("cli:seal", GOOD_RECORD)


def test_b9_cli_flag_cannot_disable_judgment():
    with pytest.raises(eg.ExitIntegrityError):
        eg.assert_no_bypass_switches(env={}, argv=["seal", "rec.json", "--no-judge"])


def test_b10_missing_policy_fails_closed_for_verdict_payload(monkeypatch, tmp_path):
    """策略包没法读时，带 verdict 的结论一律不许放行。"""
    monkeypatch.setenv(policy_loader.ENV_VAR, str(tmp_path / "nope.yaml"))
    policy_loader.load.cache_clear() if hasattr(policy_loader.load, "cache_clear") else None
    with pytest.raises(eg.JudgmentError):
        eg.judge("http:/v1/triage", GOOD_RECORD)


def test_b11_artifact_without_verdict_still_gets_a_ticket():
    """反向确认不是"一律拒" —— 无 verdict 的工件按 attested 正常取票。"""
    j = eg.judge("mcp:seal_record", {"artifact": "report.pdf", "sha256": "00" * 32},
                 basis="attested")
    assert j.basis == "attested" and j.verdict is None
    assert eg.require_judgment("mcp:seal_record",
                               {"artifact": "report.pdf", "sha256": "00" * 32}).nonce == j.nonce


# --------------------------------------------------------------------------- #
# C 组：出口清偿（正例闭环）
# --------------------------------------------------------------------------- #


def test_c1_http_triage_produces_judgment_and_credential(live):
    t0 = len(eg.ledger()["issued"])
    st, body = _post(live["base"] + "/v1/triage", ALERT)
    assert st == 200, body
    assert body["judgment"]["exit_name"] == "http:/v1/triage"
    assert body["judgment"]["verdict"] == body["triage"]["verdict"]
    assert os.path.exists(body["seal"]["seal_path"])

    led = eg.ledger()
    assert any(t["exit_name"] == "http:/v1/triage" and t["mac_ok"] for t in led["tickets"])
    issued = led["issued"]
    assert len(issued) == t0 + 1
    assert issued[-1]["exit_name"] == "http:/v1/triage"
    assert issued[-1]["judgment_nonce"], "凭证必须能追溯到一次判定"


def test_c2_http_triage_fails_closed_when_judgment_denied(live, monkeypatch, tmp_path):
    """判定层拒收时，HTTP 出口不许返回"没盖章但可用"的结论。"""
    def boom(*a, **kw):
        raise eg.JudgmentError("模拟判定不成立")

    monkeypatch.setattr(eg, "judge", boom)
    st, body = _post(live["base"] + "/v1/triage", ALERT)
    assert st == 403
    assert body["code"] == "E_JUDGMENT_DENIED"
    assert not list((tmp_path / "seals").glob("*.seal.json"))


def test_c3_mcp_seal_records_judgment(tmp_path, keys):
    out = mcp_srv.tool_seal_record({"payload": GOOD_RECORD,
                                    "private_key_path": keys["private_key_path"],
                                    "out_path": str(tmp_path / "mcp.seal.json")})
    assert out["ok"] is True
    assert out["judgment"]["exit_name"] == "mcp:seal_record"
    assert out["judgment"]["basis"] == "policy"
    assert os.path.exists(out["seal_path"])


def test_c4_mcp_seal_denied_when_judgment_fails(tmp_path, keys, monkeypatch):
    def boom(*a, **kw):
        raise eg.JudgmentError("模拟判定不成立")

    monkeypatch.setattr(eg, "judge", boom)
    out = mcp_srv.tool_seal_record({"payload": {"alert_id": "A-2"},
                                    "private_key_path": keys["private_key_path"],
                                    "out_path": str(tmp_path / "deny.seal.json")})
    assert out["ok"] is False and "判定未通过" in out["error"]
    assert not (tmp_path / "deny.seal.json").exists()


def test_c5_cli_triage_and_seal_go_through_the_gate(tmp_path, keys, monkeypatch):
    alert_path = rules.sample_alerts()[0]
    monkeypatch.setattr(sys, "stdin", io.StringIO(Path(alert_path).read_text(encoding="utf-8")))
    rc = cli.main(["triage", "-", "--seal", "-k", keys["private_key_path"],
                   "--out-dir", str(tmp_path / "out")])
    assert rc == 0
    assert any(t["exit_name"] == "cli:triage" for t in eg.ledger()["tickets"])
    assert any(i["exit_name"] == "cli:triage" for i in eg.ledger()["issued"])

    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(GOOD_RECORD, ensure_ascii=False), encoding="utf-8")
    rc = cli.main(["seal", str(rec), "-k", keys["private_key_path"], "--issuer", "t",
                   "--out", str(tmp_path / "rec.seal.json")])
    assert rc == 0
    assert os.path.exists(tmp_path / "rec.seal.json")
    assert any(i["exit_name"] == "cli:seal" for i in eg.ledger()["issued"])


def test_c6_cli_seal_denied_when_judgment_fails(tmp_path, keys, monkeypatch):
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps({"alert_id": "A", "verdict": "benign"}), encoding="utf-8")

    def boom(*a, **kw):
        raise eg.JudgmentError("模拟判定不成立")

    monkeypatch.setattr(eg, "judge", boom)
    rc = cli.main(["seal", str(rec), "-k", keys["private_key_path"], "--issuer", "t",
                   "--out", str(tmp_path / "rec.seal.json")])
    assert rc == 3
    assert not (tmp_path / "rec.seal.json").exists()


def _agent_alert(**over):
    base = {"alert_id": "ALRT-EI-0001", "title": "build runner egress", "asset": "build-runner-07",
            "severity": "high", "signal": "unexpected outbound TLS to unknown ASN 215199",
            "tags": ["egress"], "description": "构建机向未登记 ASN 建立长连接。",
            "observed": {"first_seen": "2026-11-02T03:14:00Z", "connections": 6}}
    base.update(over)
    return normalize(base)


def test_c7_agent_chain_seals_through_the_gate(tmp_path, keys, monkeypatch):
    script = [
        {"thought": "看资产画像", "action": "get_asset_profile", "args": {"asset": "build-runner-07"}},
        {"thought": "看外联", "action": "get_process_tree", "args": {"host": "build-runner-07"}},
        {"thought": "证据充分，提交判定", "action": "submit_verdict",
         "args": {"verdict": "true_positive", "severity": "high", "confidence": 0.86,
                  "hypothesis": "构建机外联基线外 ASN，疑似 CI token 外泄后的回连。",
                  "actions": ["阻断目标 ASN 出站", "轮换 CI token", "回溯 7 天调用记录"],
                  "evidence_refs": ["step.1", "step.2"]}},
    ]
    seq = list(script)
    monkeypatch.setattr(al, "call_llm",
                        lambda *a, **kw: json.dumps(seq.pop(0), ensure_ascii=False) if seq else "{}")
    trace = al.run_agent(_agent_alert(), cfg={"provider": "scripted", "model": "s", "base": "",
                                              "api_key": ""},
                         key_path=keys["private_key_path"],
                         seal_out_dir=str(tmp_path / "agentseals"))
    assert trace["sealed"] is True, trace.get("seal_error")
    names = {t["exit_name"] for t in eg.ledger()["tickets"]}
    assert {"agent:submit_verdict", "agent:seal"} <= names
    assert any(i["exit_name"] == "agent:seal" for i in eg.ledger()["issued"])


# 每个 mandatory 出口的最小可判定 payload 定义在 exit_guard.MINIMAL_PAYLOADS，
# 与 CLI（swordholder exits --selftest）共用一份，避免两处各写一份然后悄悄分叉。
MIN_PAYLOADS = eg.MINIMAL_PAYLOADS


def test_c8_mandatory_cases_cover_every_registered_exit():
    mandatory = {n for n, s in eg.EXITS.items() if s.kind in eg.MANDATORY_KINDS}
    assert set(MIN_PAYLOADS) == mandatory, (
        f"出口清单与用例清单不一致：多出 {set(MIN_PAYLOADS) - mandatory}，"
        f"漏测 {mandatory - set(MIN_PAYLOADS)}")


def test_c9_every_mandatory_exit_can_take_a_ticket():
    for name, payload in MIN_PAYLOADS.items():
        j = eg.judge(name, payload)
        assert j.mac, f"{name} 取票失败"
        assert eg.require_judgment(name, payload).nonce == j.nonce
    rep = eg.coverage_report()
    assert rep["unjudged"] == [], f"仍有出口取不到判定票据：{rep['unjudged']}"
    assert rep["all_invoked"] is True
    assert rep["coverage"] == 1.0


# --------------------------------------------------------------------------- #
# D 组：签发通道唯一（静态门禁）
# --------------------------------------------------------------------------- #

# 允许出现"直接盖章"动作的文件：core.py 是 SDK 层转接，exit_guard 是唯一通道，
# mcp_server 是底层实现。其它任何模块出现这些调用都是绕过判定。
ALLOW_ISSUE_CALLS = {
    "swordholder/core.py": {"tool_seal_record"},
    "swordholder/exit_guard.py": {"_seal_record_impl"},
    "mcp_server/server.py": {"_seal_record_impl"},
}
ISSUE_HINTS = {"seal", "tool_seal_record", "_seal_record_impl"}


def _call_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                yield f.attr, node.lineno
            elif isinstance(f, ast.Name):
                yield f.id, node.lineno


def test_d1_no_module_can_issue_credentials_directly():
    offenders = []
    for path in _sources():
        rel = path.relative_to(ROOT).as_posix()
        allow = ALLOW_ISSUE_CALLS.get(rel, set())
        for name, line in _call_names(path):
            if name in ISSUE_HINTS and name not in allow:
                offenders.append(f"{rel}:{line} 直接调用 {name}()")
    assert not offenders, "存在绕过 exit_guard 的签发路径：" + "；".join(offenders)


def test_d2_issue_credential_is_always_paired_with_judge():
    """静态配对：任何一个函数里调了 issue_credential，就必须在同一函数里调 judge。"""
    bad = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            names = {n for n, _ in _call_names_from(node)}
            if "issue_credential" in names and "judge" not in names and node.name != "issue_credential":
                bad.append(f"{path.relative_to(ROOT).as_posix()}:{node.name}")
    assert not bad, "这些函数直接签发了凭证却没先取判定票：" + "；".join(bad)


def _call_names_from(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute):
                yield f.attr, sub.lineno
            elif isinstance(f, ast.Name):
                yield f.id, sub.lineno
