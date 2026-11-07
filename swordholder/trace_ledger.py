# -*- coding: utf-8 -*-
"""动作轨迹账本（Trace Ledger）——让「AI 智能体到底做了什么」成为可被第三方发现篡改的记录。

定位
----
现有的证据链证明的是「一条结论有没有被改过」。本模块补的是更前置的一层：
**智能体执行过程中每一步动作，谁在什么时候做了什么、顺序如何**。二者共用同一把
ed25519 密钥与同一套验签口径，区别只是被签名的对象从「结论」换成「动作轨迹的头」。

机制（为什么叫 tamper-evident 而不是 tamper-proof）
------------------------------------------------
1. 每一步写入时，把 `(前一步哈希, 本步规范化内容)` 一起做 SHA256，得到本步哈希；
2. 全链的头部哈希（head）随步数一起被签名封存；
3. 验证方重算整链：任何一步被改值、插入、删除、换序，都会让它自己及其后续全部哈希失配，
   因而**不需要信任持有者**也能判定「这条记录被动过」，并能指出**第一个断点在第几步**。

这不是加密，也不是防止改动——任何有写权限的人都能改文件。它保证的是：改动**无法不被发现**。
因此必须诚实声明边界（见 `docs/prior-work.md` §3 与报告 limitations）：
- 账本持有者若同时持有私钥，可以重签一份「自洽的篡改版」——所以私钥必须离开记录方；
- 本机制不防「从第一步之前就作假」，只防「事后改」。

与既有能力的复用
--------------
签名与验签直接走 :mod:`swordholder.core` 的 ``seal`` / ``verify``，不新增密码学路径，
不新增依赖。
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from . import core

GENESIS = "0" * 64
"""创世前驱哈希。空轨迹的 head 即为此值。"""

ENTRY_KEYS = ("n", "ts", "action", "args", "observation")
"""参与哈希的字段白名单。字段外的东西（如渲染用的备注）不进哈希，避免无关字段造成假断点。"""


class TraceError(Exception):
    """轨迹结构非法（缺字段、哈希格式错、步号不连续等）。"""


def _c14n(obj: Any) -> str:
    """规范化 JSON：字段序、分隔符、编码固定，保证跨机器重算一致。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def entry_core(entry: dict) -> dict:
    """取出参与哈希的字段，缺失的按 None 补齐（缺失本身也是内容的一部分）。"""
    return {k: entry.get(k) for k in ENTRY_KEYS}


def entry_hash(entry: dict, prev_hash: str) -> str:
    """本步哈希 = SHA256(前一步哈希 + "\\n" + 规范化内容)。"""
    return _sha256("%s\n%s" % (prev_hash, _c14n(entry_core(entry))))


def body_digest(body: dict) -> str:
    """轨迹摘要 = 只覆盖 (trace_id, step_count, head)，不覆盖全文，故凭证可以很小。"""
    return _sha256(_c14n({
        "trace_id": body.get("trace_id"),
        "step_count": body.get("step_count"),
        "head": body.get("head"),
    }))


class TraceLedger:
    """逐步追加的动作记录器。

    用法::

        led = TraceLedger(trace_id="ALRT-1", actor="qwen3:8b")
        led.append("get_process_tree", {"host": "build-runner-07"})
        led.append("submit_verdict", {"verdict": "false_positive"})
        body = led.body()
        seal = seal_trace(body, "keys/private.pem", issuer="soc-agent")

    ``append`` 不会阻断调用方：即使某步参数无法 JSON 序列化，也会降级为字符串记录，
    但会在该步留下 ``serialization: "repr"`` 标记——记录器不得静默丢步。
    """

    def __init__(self, trace_id: str, actor: str | None = None, start_ts: str | None = None):
        if not trace_id:
            raise TraceError("trace_id 必填")
        self.trace_id = str(trace_id)
        self.actor = actor
        self.start_ts = start_ts
        self._entries: list[dict] = []

    # ------------------------------------------------------------------ 写入
    def append(self, action: str, args: Any = None, observation: Any = None,
               ts: str | None = None) -> dict:
        prev = self.head
        n = len(self._entries)
        entry: dict[str, Any] = {
            "n": n,
            "ts": ts,
            "action": str(action),
            "args": args,
            "observation": observation,
        }
        if not _jsonable(entry):
            entry = {
                "n": n,
                "ts": ts,
                "action": str(action),
                "args": repr(args),
                "observation": repr(observation),
                "serialization": "repr",
            }
        entry["prev"] = prev
        entry["hash"] = entry_hash(entry, prev)
        self._entries.append(entry)
        return entry

    # ------------------------------------------------------------------ 读取
    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def body(self) -> dict:
        """产出自包含的轨迹体（可序列化为 JSON 落盘）。"""
        return {
            "trace_id": self.trace_id,
            "actor": self.actor,
            "start_ts": self.start_ts,
            "step_count": len(self._entries),
            "head": self.head,
            "entries": self.entries,
        }


def _jsonable(obj: Any) -> bool:
    try:
        json.dumps(obj, ensure_ascii=False, sort_keys=True)
        return True
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------- 校验
def verify_chain(body: dict) -> dict:
    """重算整链，定位第一个断点。

    返回::

        {"ok": bool, "reason": str, "first_break": int|None,
         "expected_head": str, "claimed_head": str, "step_count": int}

    ``first_break`` 是**第一个**哈希不符的步号（0 基）；``None`` 表示链自洽。
    注意：链自洽不等于结论为真，只等于「记录内部没有被事后改动」。
    """
    if not isinstance(body, dict):
        raise TraceError("轨迹体必须是 dict")
    entries = body.get("entries")
    if not isinstance(entries, list):
        raise TraceError("entries 必须是列表")

    prev = GENESIS
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return _break(idx, prev, str(body.get("head")), len(entries),
                          "第 %d 步不是对象" % idx)
        if entry.get("n") != idx:
            return _break(idx, prev, str(body.get("head")), len(entries),
                          "第 %d 步的步号为 %r，应为 %d（疑似插入或删除）"
                          % (idx, entry.get("n"), idx))
        if entry.get("prev") != prev:
            return _break(idx, prev, str(body.get("head")), len(entries),
                          "第 %d 步的前驱哈希不匹配（疑似换序或删除）" % idx)
        want = entry_hash(entry, prev)
        if entry.get("hash") != want:
            return _break(idx, prev, str(body.get("head")), len(entries),
                          "第 %d 步内容与其哈希不符（疑似改值）" % idx)
        prev = want

    if body.get("step_count") != len(entries):
        return {
            "ok": False,
            "reason": "step_count 声明 %r 与实际 %d 不符" % (body.get("step_count"), len(entries)),
            "first_break": None,
            "expected_head": prev,
            "claimed_head": body.get("head"),
            "step_count": len(entries),
        }
    if body.get("head") != prev:
        return {
            "ok": False,
            "reason": "头部哈希与重算结果不符（疑似截断尾部步骤）",
            "first_break": None,
            "expected_head": prev,
            "claimed_head": body.get("head"),
            "step_count": len(entries),
        }
    return {
        "ok": True,
        "reason": "",
        "first_break": None,
        "expected_head": prev,
        "claimed_head": prev,
        "step_count": len(entries),
    }


def _break(idx: int, expected_head: str, claimed_head: str, step_count: int, reason: str) -> dict:
    return {
        "ok": False,
        "reason": reason,
        "first_break": idx,
        "expected_head": expected_head,
        "claimed_head": claimed_head,
        "step_count": step_count,
    }


# ------------------------------------------------------------------ 与凭证串联
def seal_trace(body: dict, private_key_path: str, issuer: str, subject: str | None = None,
               out_path: str | None = None, challenge: str | None = None,
               exit_name: str = "cli:seal") -> dict:
    """把「轨迹头 + 摘要」盖章封存。

    被封存的 payload 只含 ``trace_id / step_count / head / digest``，**不含逐步全文**：
    全文留在持有方，第三方凭签名与重算即可判断是否有改动。

    签发走 :func:`exit_guard.issue_credential`——仓内唯一凭证通道（先要票、再盖章），
    不绕开 ``tests/test_exit_integrity.py`` 的静态 AST 门禁。``exit_name`` 必须是
    已注册出口，默认借用 ``cli:seal``；新增专用出口需要同时补 EXITS 与最少载荷用例，
    属于门禁变更，走 GOVERNANCE 流程，这里不擅自放宽。
    """
    from . import exit_guard

    check = verify_chain(body)
    if not check["ok"]:
        raise TraceError("拒绝盖章：轨迹自身不自洽 —— " + check["reason"])
    payload = {
        "record_id": body.get("trace_id"),
        "trace_id": body.get("trace_id"),
        "actor": body.get("actor"),
        "step_count": body.get("step_count"),
        "head": body.get("head"),
        "digest": body_digest(body),
    }
    exit_guard.judge(exit_name, payload, basis="attested")
    return exit_guard.issue_credential(payload, private_key_path, issuer,
                                       exit_name=exit_name,
                                       subject=subject or body.get("trace_id"),
                                       out_path=out_path, challenge=challenge)


def verify_sealed_trace(body: dict, seal_path: str, keys_path: str | None = None,
                        expected_challenge: str | None = None) -> dict:
    """三段式校验：① 链自洽 ② 凭证签名可信 ③ 凭证里的头与本轨迹一致。

    任一段不通过都返回 ``verdict = "INVALID"``，并给 ``reason``。只有三段全过才是 ``VALID``。
    第三段是为了挡住「拿 A 轨迹的凭证来背书被改过的 B 轨迹」。
    """
    chain = verify_chain(body)
    if not chain["ok"]:
        return {"verdict": "INVALID", "reason": "E_TRACE_BREAK: " + chain["reason"],
                "chain": chain, "seal": None}

    seal_res = core.verify(seal_path, keys_path=keys_path,
                           expected_challenge=expected_challenge)
    if seal_res.get("verdict") == "INVALID":
        return {"verdict": "INVALID", "reason": "E_SEAL_" + str(seal_res.get("reason")),
                "chain": chain, "seal": seal_res}

    payload = _seal_payload(seal_path)
    if payload is None:
        return {"verdict": "INVALID", "reason": "E_SEAL_NO_PAYLOAD",
                "chain": chain, "seal": seal_res}

    if payload.get("trace_id") != body.get("trace_id"):
        return {"verdict": "INVALID", "reason": "E_TRACE_ID_MISMATCH", "chain": chain, "seal": seal_res}
    if payload.get("head") != body.get("head") or payload.get("step_count") != body.get("step_count"):
        return {"verdict": "INVALID", "reason": "E_TRACE_HEAD_MISMATCH", "chain": chain, "seal": seal_res}
    if payload.get("digest") != body_digest(body):
        return {"verdict": "INVALID", "reason": "E_TRACE_DIGEST_MISMATCH", "chain": chain, "seal": seal_res}

    return {"verdict": seal_res.get("verdict", "VALID"), "reason": "", "chain": chain, "seal": seal_res}


def _seal_payload(seal_path: str) -> dict | None:
    """从凭证文件里取回被签名的 payload（结构不合法时返回 None，不抛异常）。"""
    if not os.path.exists(seal_path):
        return None
    try:
        with open(seal_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    for key in ("payload", "record", "subject_payload"):
        cand = doc.get(key)
        if isinstance(cand, dict):
            return cand
    return doc if doc.get("trace_id") else None
