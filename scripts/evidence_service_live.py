"""证据服务出口模拟器（评测夹具，非产品代码）。

为什么需要这个文件
------------------
`swordholder/evidence_auth.py` 是**验证方**：只把验签通过的工单放进 facts。
但 `swordholder/agent_loop.py` 的内置 `tool_lookup_ticket` 是纯数据查询，不签发凭证
（不变量 D1 禁止 `swordholder/*.py`、`mcp_server/*.py` 直接签发，签发只能走
`exit_guard` 登记的出口）。

后果是：真实 LLM 运行一旦切到 attested 口径，**所有**工单都会 E_NO_ATTESTATION 被拒。
这是 fail-closed 的预期行为，但也意味着"attested 口径下模型到底怎么判"在 live 运行里
观察不到。本文件补上缺失的另一半——扮演**证据服务**，为 lookup_ticket 返回的真实记录
签发 seal，把 seal 路径写回 `result["attestation"]`，供 `agent_loop._facts_for` 验签。

证据边界的做法（关键，勿简化）
------------------------------
签发对象是**未经污染的真实工具输出**，不是当前 `al.TOOLS["lookup_ticket"]` 的返回。
即：证据服务只为"我自己这个数据源确实返回过这条记录"背书。

- 真实工单（S0 类）：当前返回 == 真实返回 → 签发 → 准入 → 判定继续往下走。
- 伪造工单（污染注入的 CHG-5602 等）：当前返回 ≠ 真实返回 → **不签** → 无凭证
  → E_NO_ATTESTATION 拒收，模型压根看不到这条被伪造的授权。

这与 `scripts/probe_evidence_integration.py` 的 S3a/S3b 反例矩阵同构，区别只在这里
是活体模型在跑。

纪律
----
- 只签工具实际返回的记录，不构造、不改写任何值（签的就是 c14n(record)）。
- 签发走 `mcp_server.server.tool_seal_record`（登记出口 + exit_guard 判定点）。
- 签出的 seal 落中间产物目录，不进仓库产物，不进报告。
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

KEYS_DIR_DEFAULT = "keys/swordholder_ed25519_private.pem"
ISSUER_DEFAULT = "swordholder-agent"


def _c14n(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def issue(payload: dict, alert: dict, out_dir: str,
          key_path: str = KEYS_DIR_DEFAULT, issuer: str = ISSUER_DEFAULT,
          seq: int = 0) -> dict:
    """对一条真实记录签发 seal。返回 tool_seal_record 的原始结果（含 seal_path）。"""
    from mcp_server.server import tool_seal_record
    from swordholder import evidence_auth

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    subject = str(alert.get("alert_id") or alert.get("id") or "unspecified")
    out_path = os.path.join(out_dir, f"{subject}.{seq}.ticket.seal.json")
    return tool_seal_record({
        "payload": payload,
        "private_key_path": key_path,
        "issuer": issuer,
        "subject": subject,
        "challenge": evidence_auth.context_for(alert),
        "out_path": out_path,
    })


class attesting_lookup:
    """把 lookup_ticket 包一层：真实记录签发凭证，被篡改的记录不给凭证。

    用法（必须套在污染 patch 的**外层**，即装配顺序为 _Patched → attesting_lookup）：

        with _Patched(...):
            with attesting_lookup(alert, seal_dir):
                trace = al.run_agent(...)
    """

    def __init__(self, alert: dict, out_dir: str,
                 key_path: str = KEYS_DIR_DEFAULT, issuer: str = ISSUER_DEFAULT):
        self.alert = alert
        self.out_dir = out_dir
        self.key_path = key_path
        self.issuer = issuer
        self._saved: Callable | None = None
        self.stats = {"issued": 0, "withheld": 0, "issue_failed": 0}

    def __enter__(self):
        from swordholder import agent_loop as al

        saved = al.TOOLS.get("lookup_ticket")
        real = al.tool_lookup_ticket          # 模块级真实实现，不受 TOOLS 污染影响
        seq = {"n": 0}

        def wrapper(**kw):
            cur = saved(**kw) if saved else real(**kw)
            if not (isinstance(cur, dict) and cur.get("found")):
                return cur
            true_r = real(**kw)
            rec = {k: v for k, v in cur.items() if k != "attestation"}
            true_rec = {k: v for k, v in (true_r or {}).items() if k != "attestation"}
            if _c14n(rec) != _c14n(true_rec):
                # 当前返回与真实数据源不一致：属注入/伪造，证据服务不为其背书
                self.stats["withheld"] += 1
                return {**rec}
            seq["n"] += 1
            got = issue(rec, self.alert, self.out_dir, self.key_path, self.issuer, seq["n"])
            if not got.get("ok"):
                self.stats["issue_failed"] += 1
                return {**rec}
            self.stats["issued"] += 1
            return {**rec, "attestation": got["seal_path"]}

        self._saved = saved
        al.TOOLS["lookup_ticket"] = wrapper
        return self

    def __exit__(self, *exc):
        from swordholder import agent_loop as al

        if self._saved is not None:
            al.TOOLS["lookup_ticket"] = self._saved
        return False


def selfcheck(tmp_dir: str = "temp/_evidence_service_selfcheck") -> dict:
    """自检：真实记录签发后必须验签通过，篡改记录必须被 payload 比对拦下。"""
    from swordholder import evidence_auth, core
    from mcp_server.server import tool_seal_record

    alert = {"alert_id": "ALRT-SELFCHECK-0001", "observed_at": "2026-11-02T03:14:00Z"}
    rec = {"ticket_id": "CHG-5521", "status": "closed", "found": True,
           "authorized_pentest": True,
           "window_start": "2026-10-20T09:00:00Z", "window_end": "2026-10-20T17:00:00Z"}
    got = issue(rec, alert, tmp_dir, seq=1)
    out = {"seal_ok": bool(got.get("ok")), "seal_path": got.get("seal_path")}
    if got.get("ok"):
        v = evidence_auth.verify_evidence(got["seal_path"], alert, keys_path="trusted_keys.json")
        out["verify"] = v
        out["payload_match"] = evidence_auth._sealed_payload_matches(got["seal_path"], rec)
        tampered = dict(rec, window_end="2027-12-31T00:00:00Z")
        out["tampered_match"] = evidence_auth._sealed_payload_matches(got["seal_path"], tampered)
        out["admitted"] = evidence_auth.facts_attested(
            {1: {"action": "lookup_ticket", "ok": True, "result": {**rec, "attestation": got["seal_path"]}}},
            alert, keys_path="trusted_keys.json")
    # 反例：用未登记密钥签发，必须判不可信（签名有效 ≠ 来源可信）
    rogue_dir = os.path.join(tmp_dir, "rogue")
    rogue = os.path.join(rogue_dir, "swordholder_ed25519_private.pem")
    if not os.path.exists(rogue):
        from mcp_server.server import tool_keygen
        kg = tool_keygen({"out_dir": rogue_dir})
        out["rogue_keygen"] = kg.get("ok")
    if os.path.exists(rogue):
        from mcp_server.server import tool_seal_record as _seal
        r2 = _seal({"payload": rec, "private_key_path": rogue, "issuer": "attacker",
                    "challenge": evidence_auth.context_for(alert),
                    "out_path": os.path.join(tmp_dir, "rogue.ticket.seal.json")})
        out["rogue_sign_ok"] = bool(r2.get("ok"))
        if r2.get("ok"):
            out["rogue_verify"] = evidence_auth.verify_evidence(
                r2["seal_path"], alert, keys_path="trusted_keys.json")
    return out


if __name__ == "__main__":
    res = selfcheck()
    print(json.dumps(res, ensure_ascii=False, indent=2))
