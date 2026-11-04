"""出口完整性守卫：把"判定级授权"从设计口号做成可被测试证伪的运行时约束。

reference monitor 的经典前提是 **always invoked** —— 只要还有一个对外出口不经过
判定点，"判定级授权"在语义上就退化成"事后审计"，整套凭证体系的成立性缺支撑。

本模块只做三件事：

1. ``EXITS`` 出口登记表：每个对外出口（HTTP 路由 / MCP 工具 / CLI 子命令 /
   Agent 结论提交）必须在此声明身份与判定义务。新增出口而不登记 = CI 红灯。
2. ``judge()`` 判定点：出口在产出**结论**或**凭证**之前必须取得票据
   （judgment ticket）。票据绑定「出口名 + payload 摘要 + 策略版本」，用进程内
   随机密钥做 HMAC —— 换进程即失效，离线伪造不可能；payload 被改动则摘要对不上。
3. ``issue_credential()`` 唯一签发通道：内部先 ``require_judgment()``，无票即拒
   （fail-closed）。仓内任何一处直接调 ``core.seal`` 都会被门禁测试点名。

刻意不做的事：

- 不提供"跳过判定"的开头开关。环境变量里出现 skip/bypass 类名字一律视为攻击面，
  ``assert_no_bypass_switches()`` 直接报错而不是默默放行。
- 不自己写领域判定。verdict 白名单、阈值、不变量全部来自策略包（policy_loader），
  内核只负责"不给判定的结论盖不出章"。
- 不假装能校验一切。门级判定只做**可证伪的最小约束**（verdict 白名单、confidence
  区间、结构化、payload 有内容）；完整判据仍由 agent_loop.guardrail 与策略包
  invariants 承担。门级判定的职责边界写在 ``evaluate()`` 的注释里。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import policy_loader

# --------------------------------------------------------------------------- #
# 出口登记表
# --------------------------------------------------------------------------- #

DECISION = "decision"      # 产出结论（判定意见）：必须判定
CREDENTIAL = "credential"  # 签发凭证 / 授予能力：必须判定
READONLY = "readonly"      # 纯读取 / 纯验签 / 健康检查：豁免判定，但必须登记

PORT_HTTP = "http"
PORT_MCP = "mcp"
PORT_CLI = "cli"
PORT_AGENT = "agent"


@dataclass(frozen=True)
class ExitSpec:
    """一个对外出口的登记项。

    ``entry`` 写代码事实位置（module:qualname），测试会拿它和 AST 扫描结果对照，
    所以登记表不能靠"拍脑袋写个名字"过关。
    """

    name: str
    kind: str
    port: str
    entry: str
    note: str = ""


def _spec(name: str, kind: str, port: str, entry: str, note: str = "") -> tuple[str, ExitSpec]:
    return name, ExitSpec(name=name, kind=kind, port=port, entry=entry, note=note)


EXITS: dict[str, ExitSpec] = dict([
    # -- HTTP：serve.py 的每一条路由都是出口 ---------------------------------- #
    _spec("http:/v1/triage", CREDENTIAL, PORT_HTTP, "swordholder.serve:Handler._triage",
          "结论 + 可能的凭证，签发前必须判定"),
    _spec("http:/v1/verify", READONLY, PORT_HTTP, "swordholder.serve:Handler._verify",
          "只验签，不产生新断言"),
    _spec("http:/healthz", READONLY, PORT_HTTP, "swordholder.serve:Handler.do_GET",
          "健康检查"),
    _spec("http:/v1/schema", READONLY, PORT_HTTP, "swordholder.serve:Handler.do_GET",
          "告警契约"),
    _spec("http:/v1/seals", READONLY, PORT_HTTP, "swordholder.serve:Handler.do_GET",
          "凭证索引检索"),
    _spec("http:/v1/seals/<seal_id>", READONLY, PORT_HTTP, "swordholder.serve:Handler.do_GET",
          "单份凭证检索"),
    _spec("http:/v1/trust", READONLY, PORT_HTTP, "swordholder.serve:Handler.do_GET",
          "信任锚与轮换提醒摘要"),
    # -- MCP：tools/call 是唯一入口，seal_record 是唯一的签发动作 ------------- #
    _spec("mcp:tools/call", READONLY, PORT_MCP, "mcp_server.server:handle",
          "MCP 工具分发口本身不产结论，判定义务由各具体工具承担"),
    _spec("mcp:seal_record", CREDENTIAL, PORT_MCP, "mcp_server.server:tool_seal_record",
          "MCP 侧签发凭证"),
    _spec("mcp:keygen", CREDENTIAL, PORT_MCP, "mcp_server.server:tool_keygen",
          "生成密钥对 = 授予签发能力，按 attested 判定登记"),
    _spec("mcp:verify_seal", READONLY, PORT_MCP, "mcp_server.server:tool_verify_seal", "只验签"),
    _spec("mcp:verify_proof", READONLY, PORT_MCP, "mcp_server.server:tool_verify_proof", "只验签"),
    _spec("mcp:list_trusted_keys", READONLY, PORT_MCP,
          "mcp_server.server:tool_list_trusted_keys", "只读信任锚"),
    # -- CLI：能改变对外状态的子命令 ----------------------------------------- #
    _spec("cli:seal", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_seal", "签发凭证"),
    _spec("cli:triage", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_triage",
          "分诊，--seal 时签发凭证"),
    _spec("cli:demo", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_demo", "演示链路内签发凭证"),
    _spec("cli:agent", READONLY, PORT_CLI, "swordholder.cli:cmd_agent",
          "分发口：真签发发生在 agent:seal，本命令自身不产凭证"),
    _spec("cli:keygen", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_keygen", "生成密钥对"),
    _spec("cli:verify", READONLY, PORT_CLI, "swordholder.cli:cmd_verify", "只验签"),
    _spec("cli:query", READONLY, PORT_CLI, "swordholder.cli:cmd_query", "只读索引"),
    _spec("cli:schema", READONLY, PORT_CLI, "swordholder.cli:cmd_schema", "只读契约"),
    _spec("cli:trust_add", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_trust_add",
          "改信任锚 = 改信任根，按 attested 判定登记"),
    _spec("cli:trust_retire", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_trust_retire",
          "停用旧锚会改变谁有资格签发"),
    _spec("cli:trust_revoke", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_trust_revoke",
          "吊销密钥/凭证是对已签发结论的否定"),
    _spec("cli:trust_restore", CREDENTIAL, PORT_CLI, "swordholder.cli:cmd_trust_restore",
          "撤销吊销记录 = 恢复一份结论的可信性"),
    _spec("cli:trust_show", READONLY, PORT_CLI, "swordholder.cli:cmd_trust_show", "只读信任链"),
    _spec("cli:trust_check", READONLY, PORT_CLI, "swordholder.cli:cmd_trust_check", "只读轮换体检"),
    _spec("cli:exits", READONLY, PORT_CLI, "swordholder.cli:cmd_exits",
          "只读出口登记表与覆盖率"),
    _spec("cli:serve", READONLY, PORT_CLI, "swordholder.cli:cmd_serve",
          "分发口：对外行为发生在 HTTP 出口，各自判定"),
    _spec("cli:policy_list", READONLY, PORT_CLI, "swordholder.cli:cmd_policy_list",
          "只读列出策略包"),
    _spec("cli:policy_show", READONLY, PORT_CLI, "swordholder.cli:cmd_policy_show", "只读策略包"),
    _spec("cli:policy_check", READONLY, PORT_CLI, "swordholder.cli:cmd_policy_check",
          "只校验策略文件，不改生效策略"),
    # -- Agent：结论提交是它唯一的对外断言 ----------------------------------- #
    _spec("agent:submit_verdict", DECISION, PORT_AGENT, "swordholder.agent_loop:run_agent",
          "模型提交判定，必须过 guardrail 才落 trace"),
    _spec("agent:seal", CREDENTIAL, PORT_AGENT, "swordholder.agent_loop:run_agent",
          "Agent 链路签发凭证"),
])

MANDATORY_KINDS = (DECISION, CREDENTIAL)

# --------------------------------------------------------------------------- #
# 错误类型
# --------------------------------------------------------------------------- #


class ExitIntegrityError(RuntimeError):
    """出口完整性被破坏：未登记出口、无票签发、票据伪造或失效。"""


class JudgmentError(RuntimeError):
    """判定无法成立（策略包不可用、payload 不满足门级约束），出口必须 fail-closed。"""


# --------------------------------------------------------------------------- #
# 判定票据
# --------------------------------------------------------------------------- #

_SECRET = secrets.token_bytes(32)   # 进程内票据密钥：跨进程不可复用
_LOCK = threading.RLock()
_TICKETS: dict[tuple[str, str], list["Judgment"]] = {}
_ISSUED: list[dict] = []
_TOUCHES: list[dict] = []

BYPASS_ENV_MARKERS = ("SKIP_JUDGE", "NO_JUDGE", "DISABLE_JUDGE", "BYPASS_JUDGE",
                      "SWORDHOLDER_BYPASS")
BYPASS_FLAG_MARKERS = ("--no-judge", "--skip-judge", "--bypass-judge")


@dataclass
class Judgment:
    """判定票据。字段顺序即 MAC 计算顺序，勿随意调整。"""

    exit_name: str
    payload_sha256: str
    policy_id: str | None
    policy_version: str | None
    verdict: str | None
    basis: str
    issued_at: float
    nonce: str
    notes: list[str] = field(default_factory=list)
    mac: str = ""

    def _mac_input(self) -> bytes:
        head = {
            "exit_name": self.exit_name,
            "payload_sha256": self.payload_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "verdict": self.verdict,
            "basis": self.basis,
            "issued_at": round(float(self.issued_at), 6),
            "nonce": self.nonce,
        }
        return json.dumps(head, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def to_dict(self) -> dict:
        d = {
            "exit_name": self.exit_name,
            "payload_sha256": self.payload_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "verdict": self.verdict,
            "basis": self.basis,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "notes": list(self.notes),
        }
        return d


def _compute_mac(j: Judgment) -> str:
    return hmac.new(_SECRET, j._mac_input(), hashlib.sha256).hexdigest()


def payload_digest(payload: Any) -> str:
    """与盖章 header 里 payload_sha256 同一算法（json-c14n-v1），避免两套摘要分叉。"""
    from mcp_server.server import c14n, sha256_hex

    obj = payload
    if isinstance(obj, (bytes, bytearray)):
        obj = obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except Exception:
            obj = {"_raw": obj}
    return sha256_hex(c14n(obj))


# --------------------------------------------------------------------------- #
# 门禁：跳过开关一律视为攻击面
# --------------------------------------------------------------------------- #


def assert_no_bypass_switches(env: dict | None = None, argv: list | None = None) -> None:
    """发现"想绕过判定点"的环境变量或命令行开关就报错，而不是默默放行。

    判定点的存在意义是不能被关掉。任何声称"临时跳过判定"的开关都只会成为
    攻击面，所以这里不做"警告"，直接 fail-closed。
    """
    e = os.environ if env is None else env
    hits = [k for k in e if any(m in str(k).upper() for m in BYPASS_ENV_MARKERS)]
    if hits:
        raise ExitIntegrityError(f"检测到试图绕过判定点的环境开关：{sorted(hits)}")

    a = list(os.sys.argv[1:] if argv is None else argv)
    flags = [x for x in a if str(x).lower() in BYPASS_FLAG_MARKERS]
    if flags:
        raise ExitIntegrityError(f"检测到试图绕过判定点的命令行开关：{flags}")


# --------------------------------------------------------------------------- #
# 判定点
# --------------------------------------------------------------------------- #


def _get_spec(exit_name: str) -> ExitSpec:
    spec = EXITS.get(exit_name)
    if spec is None:
        raise ExitIntegrityError(
            f"未登记的对外出口：{exit_name!r}。新增出口必须先在 exit_guard.EXITS 登记，"
            "否则它就是一个可绕过判定的口子。")
    return spec


def evaluate(payload: Any, policy: dict | None = None) -> tuple[bool, str, list[str]]:
    """门级判定的最小约束（可被证伪，不假装是完整判据）。

    只查四件机器能独立判定的事：
      1. payload 是可序列化的 JSON 对象/数组且非空；
      2. 若带 ``verdict``，必须在策略包白名单内（没有策略包就不许判）；
      3. 若带 ``confidence``，必须落在 [0,1]；
      4. 若带 ``hypothesis``，必须是非空字符串。

    severity 只在对不上白名单时记一条 note，不拒收 —— 各来源（splunk/wazuh）的
    severity 词表不统一，硬拒会把正常请求打回去，那是假拒不是安全。完整判据仍由
    agent_loop.guardrail 与策略包 invariants 承担。
    """
    notes: list[str] = []
    obj = payload
    if isinstance(obj, (bytes, bytearray)):
        obj = obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except Exception:
            return False, "payload 不是合法 JSON", notes
    if not isinstance(obj, (dict, list)):
        return False, f"payload 必须是 JSON 对象或数组，实际 {type(obj).__name__}", notes
    if isinstance(obj, dict) and not obj:
        return False, "payload 为空对象，没有可判定的内容", notes
    if isinstance(obj, list) and not obj:
        return False, "payload 为空数组，没有可判定的内容", notes

    if not isinstance(obj, dict) or "verdict" not in obj:
        notes.append("basis=attested：payload 无 verdict 字段，按工件登记处理")
        return True, "ok", notes

    if policy is None:
        return False, "payload 带 verdict 但没有策略包，判定不能成立（fail-closed）", notes

    verdicts = [str(v).strip().lower() for v in policy.get("verdicts", [])]
    v = str(obj.get("verdict", "")).strip().lower()
    if v not in verdicts:
        return False, f"verdict {v!r} 不在策略包白名单 {verdicts}", notes

    if "confidence" in obj:
        try:
            conf = float(obj["confidence"])
        except Exception:
            return False, f"confidence 非数值：{obj.get('confidence')!r}", notes
        if not 0.0 <= conf <= 1.0:
            return False, f"confidence 超界 [0,1]：{conf}", notes

    if "hypothesis" in obj and not str(obj.get("hypothesis") or "").strip():
        return False, "hypothesis 为空字符串", notes

    sevs = [str(s).strip().lower() for s in policy.get("severities", [])]
    sv = str(obj.get("severity", "")).strip().lower()
    if sv and sevs and sv not in sevs:
        notes.append(f"severity {sv!r} 不在策略包词表 {sevs}，门级不拒收，交由完整判据处理")
    return True, "ok", notes


def judge(exit_name: str, payload: Any, *, verdict: str | None = None,
          basis: str = "policy", policy: dict | None = None) -> Judgment:
    """在出口产出结论/凭证前登记一次判定，返回票据。

    ``basis=attested`` 只能用于**不带 verdict** 的 payload（例如工件清单、密钥对）。
    一旦 payload 里出现 verdict，无论调用方声明什么 basis，都强制加载策略包校验 ——
    否则"声明 attested"就成了一条绕过判定的暗道。
    """
    spec = _get_spec(exit_name)
    if spec.kind == READONLY:
        raise ExitIntegrityError(f"只读出口不产结论，不应调用判定点：{exit_name}")
    assert_no_bypass_switches()

    pol = policy
    obj = payload
    if isinstance(obj, (bytes, bytearray)):
        obj = obj.decode("utf-8", "replace")
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except Exception:
            obj = None
    has_verdict = isinstance(obj, dict) and "verdict" in obj

    if has_verdict or basis == "policy":
        if pol is None:
            try:
                pol = policy_loader.load()
            except policy_loader.PolicyError as e:
                if has_verdict:
                    # 带 verdict 的 payload 不许降级为 attested，否则"声明 attested"
                    # 就成了一条绕过判定的暗道。
                    raise JudgmentError(
                        f"策略包不可用，判定不能成立（fail-closed）：{e}") from e
                basis = "attested"
        # 带 verdict 一律进策略校验；无 verdict 时即使调用方声明 policy 也降级成
        # attested —— 没有可校验的判定字段，硬套策略只会制造假拒。
        basis = "policy" if has_verdict else basis
        if not has_verdict and basis == "policy":
            basis = "attested"

    ok, reason, notes = evaluate(payload, pol if basis == "policy" else None)
    if not ok:
        raise JudgmentError(reason)

    if has_verdict:
        v = str(obj.get("verdict")).strip().lower()
    else:
        v = (str(verdict).strip().lower() if verdict else None)

    j = Judgment(
        exit_name=exit_name,
        payload_sha256=payload_digest(payload),
        policy_id=(pol or {}).get("id"),
        policy_version=str((pol or {}).get("version")) if pol else None,
        verdict=v,
        basis=basis,
        issued_at=time.time(),
        nonce=secrets.token_hex(8),
        notes=notes,
    )
    j.mac = _compute_mac(j)
    with _LOCK:
        _TICKETS.setdefault((j.exit_name, j.payload_sha256), []).append(j)
    return j


def require_judgment(exit_name: str, payload: Any) -> Judgment:
    """校验票据：出口名一致、payload 摘要一致、MAC 未被伪造。任一不成立即拒。"""
    assert_no_bypass_switches()
    digest = payload_digest(payload)
    with _LOCK:
        cands = _TICKETS.get((exit_name, digest)) or []
        if not cands:
            raise ExitIntegrityError(
                f"出口 {exit_name} 试图在无判定票据的情况下产出结果"
                f"（payload 摘要 {digest[:16]}…）。判定点未被调用，拒绝放行。")
        j = cands[-1]
        expected = _compute_mac(j)
    if not hmac.compare_digest(j.mac, expected):
        raise ExitIntegrityError(f"出口 {exit_name} 的判定票据签名不匹配（伪造或跨进程复用）")
    return j


# --------------------------------------------------------------------------- #
# 唯一签发通道
# --------------------------------------------------------------------------- #


def issue_credential(record: Any, private_key_path: str, issuer: str, *,
                     exit_name: str, subject: str | None = None,
                     out_path: str | None = None) -> dict:
    """仓内唯一的凭证签发通道：先要票，再盖章。

    直接调 ``core.seal`` 的代码会被 ``tests/test_exit_integrity.py`` 的 AST 门禁点名，
    所以"绕过判定点签发"不是靠自觉，而是靠测试与 CI 卡住。
    """
    j = require_judgment(exit_name, record)
    from mcp_server import server as _srv

    args = {"payload": record, "private_key_path": private_key_path, "issuer": issuer}
    if subject is not None:
        args["subject"] = subject
    if out_path is not None:
        args["out_path"] = out_path
    res = _srv._seal_record_impl(args)
    if not res.get("ok"):
        from . import core
        raise core.SealError(res.get("error") or "签发失败")
    with _LOCK:
        _ISSUED.append({
            "exit_name": exit_name,
            "seal_path": res.get("seal_path"),
            "seal_id": res.get("seal_id"),
            "payload_sha256": res.get("payload_sha256"),
            "judgment_nonce": j.nonce,
            "policy_id": j.policy_id,
            "policy_version": j.policy_version,
            "issued_at": res.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
    return res


# --------------------------------------------------------------------------- #
# 只读出口打点与覆盖率
# --------------------------------------------------------------------------- #


def touch(exit_name: str, note: str = "") -> None:
    """只读出口调用打点。只读出口豁免判定，但必须留下"我经过了"的事实。"""
    spec = _get_spec(exit_name)
    with _LOCK:
        _TOUCHES.append({"exit_name": exit_name, "kind": spec.kind, "note": note,
                         "at": time.time()})


def reset_ledger() -> None:
    """清空进程内票据与打点（仅测试与长驻服务巡检用）。"""
    with _LOCK:
        _TICKETS.clear()
        _ISSUED.clear()
        _TOUCHES.clear()


def ledger() -> dict:
    with _LOCK:
        judged = sorted({k[0] for k in _TICKETS})
        return {
            "tickets": [j.to_dict() | {"mac_ok": hmac.compare_digest(j.mac, _compute_mac(j))}
                        for ks in _TICKETS.values() for j in ks],
            "issued": list(_ISSUED),
            "touches": list(_TOUCHES),
            "judged_exits": judged,
        }


# --------------------------------------------------------------------------- #
# 出口自检：每个 mandatory 出口给一份最小可判定 payload
# --------------------------------------------------------------------------- #
# 这份表是"出口清单可被真正判定"的证据，也是新增出口时必须补的一行。
# CLI（swordholder exits --selftest）与 tests/test_exit_integrity.py 共用同一份定义，
# 避免两处各写一份然后悄悄分叉。

MINIMAL_PAYLOADS: dict[str, dict] = {
    "http:/v1/triage": {"alert_id": "SELFTEST-1", "verdict": "true_positive",
                        "severity": "high", "confidence": 0.9,
                        "hypothesis": "出口自检用最小结论"},
    "mcp:seal_record": {"alert_id": "SELFTEST-1"},
    "mcp:keygen": {"public_key_hex": "00" * 32},
    "cli:seal": {"alert_id": "SELFTEST-1"},
    "cli:triage": {"alert_id": "SELFTEST-1", "verdict": "suspicious", "severity": "medium",
                   "confidence": 0.7, "hypothesis": "出口自检用最小结论"},
    "cli:demo": {"alert_id": "SELFTEST-1", "verdict": "true_positive", "severity": "high",
                 "confidence": 0.9, "hypothesis": "出口自检用最小结论"},
    "cli:keygen": {"public_key_hex": "00" * 32},
    "cli:trust_add": {"pubkey": "11" * 32},
    "cli:trust_retire": {"key_id": "k-selftest"},
    "cli:trust_revoke": {"target": "seal-selftest", "seal": True},
    "cli:trust_restore": {"seal_id": "seal-selftest"},
    "agent:submit_verdict": {"verdict": "true_positive", "severity": "high", "confidence": 0.9,
                             "hypothesis": "出口自检用最小结论", "evidence_refs": ["step.1"]},
    "agent:seal": {"alert_id": "SELFTEST-1"},
}


def selftest_all() -> dict:
    """把每个 mandatory 出口都真判一次，返回覆盖率是否到 100%。

    这是 CI 里那条"出口完整性能被证伪"的门禁：任一出口取不到票，退出码就不是 0。
    """
    failed: list[dict] = []
    for name in sorted(n for n, s in EXITS.items() if s.kind in MANDATORY_KINDS):
        payload = MINIMAL_PAYLOADS.get(name)
        if payload is None:
            failed.append({"exit": name, "reason": "E_NO_SELFTEST_PAYLOAD",
                           "detail": "新增出口必须补 MINIMAL_PAYLOADS 才能进自检"})
            continue
        try:
            judge(name, payload)
        except (JudgmentError, ExitIntegrityError) as e:
            failed.append({"exit": name, "reason": "E_JUDGMENT_FAILED", "detail": str(e)})
    rep = coverage_report()
    rep["failed"] = failed
    rep["ok"] = not failed and rep["all_invoked"]
    return rep


def coverage_report() -> dict:
    """always-invoked 覆盖率：应判定的出口集合 vs 实际取过票的出口集合。"""
    mandatory = sorted(n for n, s in EXITS.items() if s.kind in MANDATORY_KINDS)
    with _LOCK:
        judged = sorted({k[0] for k in _TICKETS})
    covered = [n for n in mandatory if n in judged]
    unjudged = [n for n in mandatory if n not in judged]
    return {
        "exits_total": len(EXITS),
        "mandatory": mandatory,
        "covered": covered,
        "unjudged": unjudged,
        "coverage": round(len(covered) / len(mandatory), 4) if mandatory else 1.0,
        "all_invoked": not unjudged,
    }


__all__ = [
    "MINIMAL_PAYLOADS", "selftest_all",
    "DECISION", "CREDENTIAL", "READONLY", "PORT_HTTP", "PORT_MCP", "PORT_CLI", "PORT_AGENT",
    "MANDATORY_KINDS", "EXITS", "ExitSpec", "Judgment", "JudgmentError", "ExitIntegrityError",
    "judge", "require_judgment", "issue_credential", "evaluate", "payload_digest",
    "assert_no_bypass_switches", "touch", "ledger", "coverage_report", "reset_ledger",
]
