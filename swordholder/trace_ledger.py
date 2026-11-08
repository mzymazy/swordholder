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

ANCHOR_MAX = 64
"""凭证里默认携带的步级锚点上限。步数不超过它时锚点密度为 1，即**逐步可定位**。"""

ANCHOR_TRUNC = 16
"""锚点哈希保留的十六进制字符数（16 字符 = 64 bit）。截断只为压体积，不改变可定位性。"""

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


# ------------------------------------------------------- 步级锚点（定位用）
def anchor_stride(step_count: int, max_anchors: int = ANCHOR_MAX) -> int:
    """给定步数，算出能装进 ``max_anchors`` 个锚点的最小步距（步距 1 = 逐步可定位）。"""
    n = int(step_count or 0)
    if n <= 0:
        return 1
    if max_anchors is None or int(max_anchors) <= 0:
        return n
    return max(1, -(-n // int(max_anchors)))


def anchor_points(step_count: int, stride: int) -> list[int]:
    """锚点落位：均匀取样，且**强制包含最后一步**（否则尾部篡改落进盲区）。"""
    n = int(step_count or 0)
    if n <= 0:
        return []
    s = max(1, int(stride))
    pts = list(range(s - 1, n, s))
    if not pts or pts[-1] != n - 1:
        pts.append(n - 1)
    return pts


def _chain_hashes(entries: list) -> list[str]:
    """独立重算整链哈希（不看条目里存的 ``hash`` 字段，避免被伪造值带偏）。"""
    prev, out = GENESIS, []
    for entry in entries:
        h = entry_hash(entry, prev)
        out.append(h)
        prev = h
    return out


def build_anchors(body: dict, stride: int | None = None, trunc: int = ANCHOR_TRUNC,
                  max_anchors: int = ANCHOR_MAX) -> dict:
    """从轨迹体算出步级锚点向量：``{"stride","trunc","count","points":[{"i","h"}]}``。

    锚点是「第 i 步之后的累计哈希」的前缀截断。它随凭证一起被签名，因而**由签发方**
    固定下来；验证方重算后逐点比对，即可把「整链自洽但头部对不上」的篡改**夹逼到
    一个步区间**，而不是只能报一句「头不符」。

    为什么要它：链式哈希的定位能力只对「没重算后续哈希」的篡改有效。攻击者若把改过的
    那一步及之后全部重算、连 head 一起改，链会自洽，凭证只能靠 head 判 INVALID——这时
    若凭证里没有独立的步级承诺，篡改位置在信息论上就**无从恢复**。锚点就是补这个承诺。
    """
    entries = body.get("entries") if isinstance(body, dict) else None
    if not isinstance(entries, list):
        raise TraceError("entries 必须是列表，无法生成锚点")
    n = len(entries)
    s = anchor_stride(n, max_anchors) if stride is None else int(stride)
    s = max(1, s)
    t = max(8, min(64, int(trunc)))
    hashes = _chain_hashes(entries)
    return {
        "v": 1,
        "stride": s,
        "trunc": t,
        "count": n,
        "points": [{"i": i, "h": hashes[i][:t]} for i in anchor_points(n, s)],
    }


def locate_step(body: dict, sealed_anchors: dict) -> dict:
    """用凭证里的锚点夹逼篡改步区间。

    返回::

        {"mode": "anchor", "stride": int, "matched": bool,
         "segment": [lo, hi] | None, "exact": bool, ...}

    ``segment`` 是**可能被改动的步号闭区间**：链式哈希的缘故，改动第 t 步会让 t 及其
    之后全部累计哈希变样，故第一个失配锚点 ``i_k`` 之前的锚点都还对，于是
    ``t ∈ (i_{k-1}, i_k]``。步距为 1 时区间退化为单点，即精确到步。
    """
    if not isinstance(sealed_anchors, dict):
        raise TraceError("锚点必须是 dict")
    stride = int(sealed_anchors.get("stride") or 1)
    trunc = int(sealed_anchors.get("trunc") or ANCHOR_TRUNC)
    sealed_pts = sealed_anchors.get("points") or []
    if not isinstance(sealed_pts, list):
        raise TraceError("锚点 points 必须是列表")

    fresh = build_anchors(body, stride=stride, trunc=trunc, max_anchors=0)
    fresh_pts = fresh["points"]
    n = len(body.get("entries") or [])

    idx = None
    for k in range(min(len(sealed_pts), len(fresh_pts))):
        a, b = sealed_pts[k], fresh_pts[k]
        if not isinstance(a, dict) or a.get("i") != b["i"] or a.get("h") != b["h"]:
            idx = k
            break

    if idx is None and len(sealed_pts) == len(fresh_pts):
        return {"mode": "anchor", "stride": stride, "matched": True,
                "segment": None, "exact": True, "count": n}

    if idx is None:
        # 点数不同：多步/少步（截断或追加），指纹落在缺失的那一段
        idx = min(len(sealed_pts), len(fresh_pts))
        lo = fresh_pts[idx - 1]["i"] + 1 if idx > 0 and idx - 1 < len(fresh_pts) else 0
        hi = max(n - 1, lo)
        return {"mode": "anchor", "stride": stride, "matched": False,
                "segment": [lo, hi], "exact": (lo == hi),
                "note": "anchor_count_changed",
                "sealed_points": len(sealed_pts), "observed_points": len(fresh_pts)}

    lo = fresh_pts[idx - 1]["i"] + 1 if idx > 0 else 0
    hi = fresh_pts[idx]["i"] if idx < len(fresh_pts) else max(n - 1, lo)
    out = {"mode": "anchor", "stride": stride, "matched": False,
           "segment": [lo, hi], "exact": (lo == hi),
           "first_mismatch_anchor": fresh_pts[idx]["i"],
           "sealed_hash": sealed_pts[idx].get("h") if idx < len(sealed_pts) else None,
           "observed_hash": fresh_pts[idx]["h"]}
    if idx == 0:
        # 第一个锚点（第 0 步累计哈希）就已不符：只能确定「从第 0 步起就和凭证不同」，
        # 无法区分「只改了第 0 步并重算整链」与「整条本来就是另一条轨迹」——两者在
        # 信息上等价。故 segment 只表示**分叉点**，改动跨度不可收窄，必须标出来，
        # 免得把 [0,0] 误读成「改动范围就是一步」。
        out["span_unbounded"] = True
        out["note"] = "divergence_from_step0"
    return out


# ------------------------------------------------------------------ 与凭证串联
def seal_trace(body: dict, private_key_path: str, issuer: str, subject: str | None = None,
               out_path: str | None = None, challenge: str | None = None,
               exit_name: str = "cli:seal", anchor_stride: int | None = None,
               anchor_max: int = ANCHOR_MAX, anchor_trunc: int = ANCHOR_TRUNC) -> dict:
    """把「轨迹头 + 摘要 + 步级锚点」盖章封存。

    被封存的 payload 含 ``trace_id / step_count / head / digest / anchors``，**不含逐步全文**：
    全文留在持有方，第三方凭签名与重算即可判断是否有改动，并能把改动**夹逼到具体步**。

    ``anchors`` 是 0.7.5 新增的步级承诺向量（见 :func:`build_anchors`）。传
    ``anchor_stride=0`` 可退回 0.7.4 的纯头部凭证（此时凭证更小，但只能判 INVALID、
    无法定位）；默认 ``None`` 表示按 ``anchor_max`` 自动取步距，步数不超过 64 时步距为 1。

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
    if anchor_stride is None or int(anchor_stride) > 0:
        payload["anchors"] = build_anchors(body, stride=anchor_stride,
                                          trunc=anchor_trunc, max_anchors=anchor_max)
    exit_guard.judge(exit_name, payload, basis="attested")
    return exit_guard.issue_credential(payload, private_key_path, issuer,
                                       exit_name=exit_name,
                                       subject=subject or body.get("trace_id"),
                                       out_path=out_path, challenge=challenge)


def verify_sealed_trace(body: dict, seal_path: str, keys_path: str | None = None,
                        expected_challenge: str | None = None,
                        require_anchors: bool = False) -> dict:
    """三段式校验：① 链自洽 ② 凭证签名可信 ③ 凭证里的头/摘要与本轨迹一致。

    任一段不通过都返回 ``verdict = "INVALID"``，并给 ``reason``。只有三段全过才是 ``VALID``。
    第三段是为了挡住「拿 A 轨迹的凭证来背书被改过的 B 轨迹」。

    0.7.5 起，返回体固定带 ``localization``：

    - ``mode="chain"``：链自己就断了，``first_break`` 即精确步号；
    - ``mode="anchor"``：链自洽但凭证不符，用凭证里的锚点夹逼出 ``segment=[lo,hi]``，
      ``exact=True`` 表示该区间只有一个步（步距 1 时成立）；
    - ``mode="none"``：凭证是 0.7.4 风格的纯头部凭证，无步级锚点，只能判 INVALID。

    ``require_anchors=True`` 时拒绝无锚点凭证（``E_TRACE_ANCHORS_ABSENT``），用于
    阻断「拿旧版弱凭证降级验证」。
    """
    chain = verify_chain(body)
    if not chain["ok"]:
        first = chain["first_break"]
        return {"verdict": "INVALID", "reason": "E_TRACE_BREAK: " + chain["reason"],
                "chain": chain, "seal": None,
                "localization": {"mode": "chain", "first_break": first,
                                 "segment": None if first is None else [first, first],
                                 "exact": first is not None}}


    seal_res = core.verify(seal_path, keys_path=keys_path,
                           expected_challenge=expected_challenge)
    if seal_res.get("verdict") == "INVALID":
        return {"verdict": "INVALID", "reason": "E_SEAL_" + str(seal_res.get("reason")),
                "chain": chain, "seal": seal_res,
                "localization": {"mode": "none", "reason": "seal_untrusted",
                                 "segment": None, "exact": False}}

    payload = _seal_payload(seal_path)
    if payload is None:
        return {"verdict": "INVALID", "reason": "E_SEAL_NO_PAYLOAD",
                "chain": chain, "seal": seal_res,
                "localization": {"mode": "none", "reason": "no_payload",
                                 "segment": None, "exact": False}}

    sealed_anchors = payload.get("anchors") if isinstance(payload, dict) else None
    if require_anchors and not isinstance(sealed_anchors, dict):
        return {"verdict": "INVALID", "reason": "E_TRACE_ANCHORS_ABSENT",
                "chain": chain, "seal": seal_res,
                "localization": {"mode": "none", "reason": "seal_without_anchors",
                                 "segment": None, "exact": False}}

    if payload.get("trace_id") != body.get("trace_id"):
        loc = _locate(body, sealed_anchors)
        return {"verdict": "INVALID", "reason": "E_TRACE_ID_MISMATCH", "chain": chain,
                "seal": seal_res, "localization": loc}
    if payload.get("head") != body.get("head") or payload.get("step_count") != body.get("step_count"):
        loc = _locate(body, sealed_anchors)
        return {"verdict": "INVALID", "reason": "E_TRACE_HEAD_MISMATCH", "chain": chain,
                "seal": seal_res, "localization": loc}
    if payload.get("digest") != body_digest(body):
        loc = _locate(body, sealed_anchors)
        return {"verdict": "INVALID", "reason": "E_TRACE_DIGEST_MISMATCH", "chain": chain,
                "seal": seal_res, "localization": loc}
    # 头与摘要都对上，却有条目级锚点不符：只可能出现在截断参数被改或哈希碰撞下，
    # 属防御性拦截——宁可多报一次异常，也不让「头对得上但内容对不上」溜过。
    if isinstance(sealed_anchors, dict):
        loc = _locate(body, sealed_anchors)
        if loc.get("matched") is False:
            return {"verdict": "INVALID", "reason": "E_TRACE_ANCHOR_MISMATCH",
                    "chain": chain, "seal": seal_res, "localization": loc}

    return {"verdict": seal_res.get("verdict", "VALID"), "reason": "", "chain": chain,
            "seal": seal_res,
            "localization": {"mode": "anchor" if isinstance(sealed_anchors, dict) else "none",
                             "reason": "no_tamper", "segment": None, "exact": True}}


def _locate(body: dict, sealed_anchors: Any) -> dict:
    """锚点夹逼的容错封装：锚点缺失/不可解析时退化为「无法定位」，绝不让校验本身抛错。"""
    if not isinstance(sealed_anchors, dict) or not sealed_anchors.get("points"):
        return {"mode": "none", "reason": "seal_without_anchors",
                "segment": None, "exact": False}
    try:
        return locate_step(body, sealed_anchors)
    except (TraceError, TypeError, ValueError) as exc:
        return {"mode": "none", "reason": "anchors_unusable: %s" % exc,
                "segment": None, "exact": False}


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
