"""证据来源认证（L1 修复候选，纯增量模块）。

问题（见 docs/formal-model.md 定理 1）：`agent_loop._facts()` 只从工具返回里
抽取值语义，`tool_verified_ref` / `window_covers_alert` 两条不变量也只对值做
成员判定与区间判定，因此**一条自洽的伪造工单**可以同时满足两者——框架必然放行。
定理 1 说这是引理 1（判定只依赖值）的直接推论，不是偶发缺陷。

本模块给出最小改动修复：**只把可验签的证据放进 facts**。

    facts' = { r ∈ Val(E) : Verify(pk_Src, σ, H(c14n(r)) ‖ challenge) = 1 }

安全性质与前提见文档 §4（EUF-CMA 归约）与 §5（challenge 绑定的防重放界）。

设计约束（刻意为之，勿"优化"掉）：
1. **纯增量**：不修改 `agent_loop` 任何代码。已完成的 304 次运行的语义不受影响，
   L2 统计与前序实测仍可比。
2. **fail-closed**：验签失败 / 缺认证 / 信任锚不可用 / 挑战值不符，一律**不进 facts**，
   让 I1 以 `unverified` 拒收；绝不"验不了就放过"。
3. **不依赖墙钟**：新鲜度只靠 `challenge`（由验证方按告警派生），不用时间戳判定，
   避免把可信时间源拖成安全前提（文档 §5 的设计取舍）。
4. **值的绑定必须完整**：seal 覆盖的是整条记录的 c14n 哈希，不是"来源已表态"。
   只签来源不签值可被"保签名改窗口"绕过（文档引理 2）。
5. **本模块不做签发方**：签发属出口闸门的职责，只能经
   `core.seal → tool_seal_record → exit_guard.judge` 发生。仓库不变量 D1
   （`tests/test_exit_integrity.py::test_d1_no_module_can_issue_credentials_directly`）
   会用 AST 扫 `swordholder/*.py` 与 `mcp_server/*.py`，任何新增模块直接调
   `seal*/_seal_record_impl*` 都会被判为"绕过 exit_guard 的签发路径"并失败。
   这不是障碍而是约束：**验证方与签发方必须分离**，否则修复本身就成了新攻击面。
   证据服务的签发实现落在 `mcp_server/server.py`（已登记出口），本模块只验证。

用法（接入时）：
    facts = evidence_auth.facts_attested(executed, alert, keys_path=...)
    ok, reason, norm = agent_loop.guardrail(decision, executed, facts=facts, ...)
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from swordholder import core

# challenge 必须落在 mcp_server.CHALLENGE_RE 允许的字符集与长度内：8–128 位 [A-Za-z0-9_-]
_CTX_PREFIX = "swordholder-evidence-ctx/1|"
_CTX_LEN = 32


def _c14n(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def context_for(alert: dict) -> str:
    """按告警派生挑战值：同一告警的判定上下文一致，跨告警不可复用。

    用 sha256 截断成 32 位十六进制（16 字节 → 128 bit 截断到 32 nibble，
    实际取值空间 2^128 内的均匀采样），满足 `[A-Za-z0-9_-]{8,128}`。
    """
    anchor = str(alert.get("alert_id") or alert.get("id") or alert.get("subject") or "")
    if not anchor:
        # 没有告警标识就不能派生上下文 —— 直接抛错，由调用方 fail-closed。
        raise ValueError("告警缺少 alert_id/id/subject，无法派生证据上下文")
    digest = hashlib.sha256((_CTX_PREFIX + anchor).encode("utf-8")).hexdigest()
    return digest[:_CTX_LEN]


def verify_evidence(seal_path: str, alert: dict, keys_path: str | None = None) -> dict:
    """验签一条证据凭证，返回 {"trusted": bool, "reason": str, "verdict": str, ...}。

    只有 `verdict == "VALID"`（即签名有效 **且** 签发方在信任锚内、未吊销）才算可信。
    `VALID_UNTRUSTED_KEY` 与 `unknown` 一律判为不可信 —— 签名有效 ≠ 来源可信。
    """
    if not seal_path or not os.path.exists(seal_path):
        return {"trusted": False, "reason": "E_NO_ATTESTATION", "verdict": "MISSING"}
    try:
        ctx = context_for(alert)
    except ValueError as e:
        return {"trusted": False, "reason": f"E_NO_CONTEXT: {e}", "verdict": "INVALID"}
    try:
        res = core.verify(seal_path, keys_path, expected_challenge=ctx)
    except Exception as e:  # noqa: BLE001  任何验签异常都不可信
        return {"trusted": False, "reason": f"E_VERIFY_ERROR: {e}", "verdict": "INVALID"}
    verdict = res.get("verdict")
    trusted = verdict == "VALID" and res.get("trust") == "trusted"
    return {"trusted": trusted, "verdict": verdict,
            "reason": "OK" if trusted else (res.get("reason") or "E_UNTRUSTED"),
            "seal_id": res.get("seal_id"), "key_id": res.get("key_id")}


def _sealed_payload_matches(seal_path: str, record: dict) -> bool:
    """seal 内的 payload 必须与模型实际看到的记录逐字节一致（防"凭证与数据两张皮"）。"""
    try:
        with open(seal_path, "r", encoding="utf-8") as f:
            sealed = (json.load(f) or {}).get("payload")
    except Exception:  # noqa: BLE001
        return False
    return _c14n(sealed) == _c14n(record)


def facts_attested(executed: dict[int, dict], alert: dict, keys_path: str | None = None,
                   keys: str | None = None) -> dict:
    """与 `agent_loop._facts` 同形，但只收留**验签通过**的工单。

    返回值除 `tickets` 外附带 `audit`：每条候选的准入/拒绝理由，
    便于报告里出示"拒收了几条、为什么拒"，而不是只报一个结果。
    """
    tickets: dict[str, dict] = {}
    audit: list[dict[str, Any]] = []
    for step_no, s in executed.items():
        if s.get("action") != "lookup_ticket" or s.get("ok") is not True:
            continue
        r = s.get("result") or {}
        if not r.get("found"):
            continue
        rec = {k: v for k, v in r.items() if k != "attestation"}
        tid = str(rec.get("ticket_id", "")).upper()
        if not tid:
            audit.append({"step": step_no, "ticket_id": "", "admitted": False,
                          "reason": "E_NO_TICKET_ID"})
            continue
        v = verify_evidence(str(r.get("attestation") or ""), alert,
                            keys_path=keys_path if keys_path is not None else keys)
        if not v["trusted"]:
            audit.append({"step": step_no, "ticket_id": tid, "admitted": False,
                          "reason": v["reason"]})
            continue
        if not _sealed_payload_matches(str(r["attestation"]), rec):
            audit.append({"step": step_no, "ticket_id": tid, "admitted": False,
                          "reason": "E_ATTESTATION_PAYLOAD_MISMATCH"})
            continue
        tickets[tid] = rec
        audit.append({"step": step_no, "ticket_id": tid, "admitted": True, "reason": "OK"})
    return {"tickets": tickets, "audit": audit}
