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

import base64
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

AUTH_EXTRA_KEYS = ("period", "db_ref", "matched_input", "identity_check",
                   "purpose", "event_type", "severity", "risk_flag", "monitor_tag")
"""可选认证字段。前四个是 0.8.0 的 Art.12(3) 高危用途必备记录，后五个是 0.9.1 的
Art.12(2)(a)(b)(c) 风险事件字段（见 ``ART12_2_FIELDS``）。

这九个字段**只有出现时才进哈希**（见 :func:`entry_core`）。这样 0.7.x / 0.8.0 的旧轨迹
一个字节都不用改，重算哈希仍与历史一致；而一旦启用，字段本身也受哈希链保护，
不会出现「字段在但没被链覆盖、可被悄悄改写」的半吊子实现。

字段语义（对应 Art.12(3)(a)–(d)）

- ``period``：本次使用的起止时间 ``{"start": ISO8601, "end": ISO8601}``；
- ``db_ref``：被检索的参考数据库（含版本/快照标识）标识符；
- ``matched_input``：导致命中（match）的那份输入数据或其摘要；
- ``identity_check``：Art.14(5) 自然人身份核验结果 ``{"verifier", "method", "at"}``。
"""

EXT_TS_KEY = "external_timestamp"
"""凭证文件里承载 RFC 3161 时间戳的键名（与 payload 平级，不参与签名）。"""

ANNEX_III_VARIANTS = ("annex3-1a",)
"""受支持的记录档位。目前只实现 Art.12(3) 指向的 Annex III 1(a)（生物特征识别类）。"""

ART12_2_FIELDS = ("purpose", "event_type", "severity", "risk_flag", "monitor_tag")
"""``profile="art12-2"`` 档位的内建风险字段（EU AI Act Art.12(2)(a)(b)(c)）。

为什么要有这五个字段：Art.12(2) 要求高风险系统的日志能**按用途与风险情形筛出**——
(a) 识别风险情形、(b) 上市后监测、(c) 部署方对已部署系统的评估。只有时间戳和动作名
的日志，只能证明"发生过什么"，没法回答"哪几步属于风险识别"这类合规提问，筛取只能
靠调用方自己在外层约定字段名，第三方审计时无从对齐。故把用途/事件类型/严重度/风险
标记/监测标签做成**档位前置的必填字段**，缺失即拒绝写入（不允许事后补，否则日志里
会出现无法区分「漏填」与「被删」的空档）。

向后兼容：默认档位（``profile=None``）下条目键集合仍是
``n/ts/action/args/observation/prev/hash``，一个字节不变；这五个字段只在显式传入或
档位开启时才进哈希（见 :func:`entry_core`）。
"""

ART12_2_PURPOSES = {
    "risk_identification": "Art.12(2)(a)",
    "post_market_monitoring": "Art.12(2)(b)",
    "deployer_evaluation": "Art.12(2)(c)",
}
"""用途取值 → 条文出处。(a) 风险情形识别；(b) Art.72 上市后监测；(c) Art.26(5) 部署方评估。"""

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
"""严重度序数。比较用 :data:`SEVERITY_RANK`，不靠字符串排序。"""

SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_LEVELS)}

SUPPORTED_PROFILES = ("annex3-1a", "art12-2")
"""``TraceLedger(profile=...)`` 可接受的档位。``annex3-1a`` 管 Art.12(3) 生物识别类，
``art12-2`` 管 Art.12(2) 三类用途的风险字段。"""


class TraceError(Exception):
    """轨迹结构非法（缺字段、哈希格式错、步号不连续等）。"""


def _c14n(obj: Any) -> str:
    """规范化 JSON：字段序、分隔符、编码固定，保证跨机器重算一致。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_risk_fields(purpose: Any = None, event_type: Any = None,
                           severity: Any = None, risk_flag: Any = None,
                           monitor_tag: Any = None) -> dict:
    """校验并归一化 Art.12(2) 风险字段；未传的字段不出现在返回值里。

    取值一律**闭集**校验（用途、严重度），避免"high"/"High"/"高风险"混写导致筛取漏项。
    """
    out: dict[str, Any] = {}
    if purpose is not None:
        val = str(purpose)
        if val not in ART12_2_PURPOSES:
            raise TraceError("E_ART12_2_PURPOSE_INVALID: purpose=%r 不在允许取值内（%s）"
                             % (purpose, ", ".join(ART12_2_PURPOSES)))
        out["purpose"] = val
    if event_type is not None:
        val = _normalize_ref(event_type, "event_type")
        out["event_type"] = val
    if severity is not None:
        val = str(severity).lower()
        if val not in SEVERITY_RANK:
            raise TraceError("E_ART12_2_SEVERITY_INVALID: severity=%r 不在允许取值内（%s）"
                             % (severity, ", ".join(SEVERITY_LEVELS)))
        out["severity"] = val
    if risk_flag is not None:
        if not isinstance(risk_flag, bool):
            raise TraceError("E_ART12_2_RISK_FLAG_INVALID: risk_flag 必须是布尔，收到 %r"
                             % (risk_flag,))
        out["risk_flag"] = risk_flag
    if monitor_tag is not None:
        out["monitor_tag"] = _normalize_ref(monitor_tag, "monitor_tag")
    return out


def select_entries(body: dict, *, purpose: Any = None, event_type: Any = None,
                   severity: Any = None, min_severity: Any = None,
                   risk_flag: Any = None, monitor_tag: Any = None) -> list[dict]:
    """在轨迹体里按 Art.12(2) 字段筛选条目（纯读，不改链、不改文件）。

    这就是"可直接筛取"的那一半：审计方不需要知道调用方私有的字段命名约定，
    用 ``purpose="risk_identification"`` 或 ``min_severity="high"`` 就能把
    (a)/(b)/(c) 三类用途的日志分别取出来。``min_severity`` 用 :data:`SEVERITY_RANK`
    比较，不做字符串排序。未声明档位的旧轨迹里没有这些字段，筛取结果自然为空
    （而不是报错），便于对同一批日志混跑新旧格式。
    """
    want: dict[str, Any] = {}
    if purpose is not None:
        want["purpose"] = str(purpose)
    if event_type is not None:
        want["event_type"] = str(event_type)
    if severity is not None:
        want["severity"] = str(severity).lower()
    if risk_flag is not None:
        want["risk_flag"] = bool(risk_flag)
    if monitor_tag is not None:
        want["monitor_tag"] = str(monitor_tag)
    floor = None
    if min_severity is not None:
        key = str(min_severity).lower()
        if key not in SEVERITY_RANK:
            raise TraceError("E_ART12_2_MIN_SEVERITY_INVALID: min_severity=%r 不在允许取值内"
                             % (min_severity,))
        floor = SEVERITY_RANK[key]

    hits: list[dict] = []
    for entry in (body or {}).get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if any(entry.get(k) != v for k, v in want.items()):
            continue
        if floor is not None:
            got = entry.get("severity")
            if got not in SEVERITY_RANK or SEVERITY_RANK[got] < floor:
                continue
        hits.append(entry)
    return hits


def risk_summary(body: dict) -> dict:
    """按用途/严重度给一份计数摘要，便于把"日志里有多少风险情形"变成可核对的数字。"""
    entries = [e for e in ((body or {}).get("entries") or []) if isinstance(e, dict)]
    by_purpose = {k: 0 for k in ART12_2_PURPOSES}
    by_severity = {k: 0 for k in SEVERITY_LEVELS}
    flagged = 0
    unclassified = 0
    for e in entries:
        purpose = e.get("purpose")
        severity = e.get("severity")
        if purpose in by_purpose:
            by_purpose[purpose] += 1
        if severity in by_severity:
            by_severity[severity] += 1
        if e.get("risk_flag") is True:
            flagged += 1
        if purpose is None and severity is None and "risk_flag" not in e:
            unclassified += 1
    return {"total": len(entries), "risk_flagged": flagged,
            "unclassified": unclassified, "by_purpose": by_purpose,
            "by_severity": by_severity}


def entry_core(entry: dict) -> dict:
    """取出参与哈希的字段，缺失的按 None 补齐（缺失本身也是内容的一部分）。

    ``AUTH_EXTRA_KEYS`` 里的字段是**条件入链**：只有条目里真的带了它才拼进规范化内容。
    因此不含这些字段的 0.7.x 条目哈希与历史完全一致（向后兼容），含这些字段的条目
    则把字段一起锁死在哈希链里（无法只改字段不改链）。
    """
    core = {k: entry.get(k) for k in ENTRY_KEYS}
    for k in AUTH_EXTRA_KEYS:
        if k in entry:
            core[k] = entry[k]
    return core


def entry_hash(entry: dict, prev_hash: str) -> str:
    """本步哈希 = SHA256(前一步哈希 + "\\n" + 规范化内容)。"""
    return _sha256("%s\n%s" % (prev_hash, _c14n(entry_core(entry))))


def body_digest(body: dict) -> str:
    """轨迹摘要 = 只覆盖 (trace_id, step_count, head, profile)，不覆盖全文，故凭证可以很小。

    ``profile`` 只在轨迹体显式声明档位时才并入摘要：不含该键的 0.7.x 轨迹摘要与历史
    完全一致（旧凭证仍能验），而声明了 ``annex3-1a`` 的轨迹，把声明改掉（例如把档位删了
    冒充普通轨迹）会让摘要对不上——档位声明本身也被锁进凭证，不只是条目里的字段。
    """
    core = {
        "trace_id": body.get("trace_id"),
        "step_count": body.get("step_count"),
        "head": body.get("head"),
    }
    if body.get("profile") is not None:
        core["profile"] = body.get("profile")
    return _sha256(_c14n(core))


def _parse_iso(value: Any) -> Any:
    """把 ISO8601 字符串解析成 datetime；解析不了返回 None（用于区间单调性校验）。"""
    from datetime import datetime

    if not isinstance(value, str):
        return None
    txt = value.strip()
    if not txt:
        return None
    try:
        return datetime.fromisoformat(txt.replace("Z", "+00:00"))
    except ValueError:
        return None


def _normalize_period(period: Any) -> dict:
    """校验并规范化 ``{"start","end"}``：逐字保留调用方时间串，只做缺项/倒序拦截。"""
    if not isinstance(period, dict):
        raise TraceError("E_ANNEX3_PERIOD_INVALID: period 必须是 {start,end} 对象，收到 %r"
                         % (type(period).__name__,))
    start, end = period.get("start"), period.get("end")
    for name, val in (("start", start), ("end", end)):
        if not isinstance(val, str) or not val.strip():
            raise TraceError("E_ANNEX3_PERIOD_INVALID: period.%s 必须是非空 ISO8601 字符串，"
                             "收到 %r" % (name, val))
    ds, de = _parse_iso(start), _parse_iso(end)
    if ds is None or de is None:
        raise TraceError("E_ANNEX3_PERIOD_INVALID: period 起止时间必须是可解析的 ISO8601"
                         "（收到 %r / %r）" % (start, end))
    if de < ds:
        raise TraceError("E_ANNEX3_PERIOD_INVALID: period.end（%s）早于 period.start（%s）"
                         % (end, start))
    out = {"start": start.strip(), "end": end.strip()}
    for extra in ("tz", "source"):
        if extra in period:
            out[extra] = period[extra]
    return out


def _normalize_ref(value: Any, field: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise TraceError("E_ANNEX3_FIELD_INVALID: %s 必须是非空字符串，收到 %r" % (field, value))


def _normalize_identity(identity_check: Any) -> dict:
    """Art.14(5) 身份核验：至少要有「谁核验的」，方法与时间可缺省但会被显式写 null。"""
    if isinstance(identity_check, str) and identity_check.strip():
        identity_check = {"verifier": identity_check.strip()}
    if not isinstance(identity_check, dict):
        raise TraceError("E_ANNEX3_IDENTITY_INVALID: identity_check 必须是对象或自然人标识字符串")
    verifier = identity_check.get("verifier")
    if not isinstance(verifier, str) or not verifier.strip():
        raise TraceError("E_ANNEX3_IDENTITY_INVALID: identity_check.verifier 必填（自然人标识）")
    out = {"verifier": verifier.strip(),
           "method": identity_check.get("method"),
           "at": identity_check.get("at")}
    for extra in ("result", "role"):
        if extra in identity_check:
            out[extra] = identity_check[extra]
    return out


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

    def __init__(self, trace_id: str, actor: str | None = None, start_ts: str | None = None,
                 profile: str | None = None):
        if not trace_id:
            raise TraceError("trace_id 必填")
        if profile is not None and profile not in SUPPORTED_PROFILES:
            raise TraceError("不支持的记录档位 %r（可选：%s）"
                             % (profile, ", ".join(SUPPORTED_PROFILES)))
        self.trace_id = str(trace_id)
        self.actor = actor
        self.start_ts = start_ts
        self.profile = profile
        self._entries: list[dict] = []

    # ------------------------------------------------------------------ 写入
    def append(self, action: str, args: Any = None, observation: Any = None,
               ts: str | None = None, *, period: dict | None = None,
               db_ref: Any = None, matched_input: Any = None,
               identity_check: dict | None = None, matched: bool = False,
               verified_by: str | None = None,
               verify_method: str = "human_review",
               purpose: str | None = None, event_type: str | None = None,
               severity: str | None = None, risk_flag: bool | None = None,
               monitor_tag: str | None = None) -> dict:
        """追加一步。

        普通用法与 0.7.x 完全一致（``action/args/observation/ts``）——此时条目键集合
        仍是 ``n/ts/action/args/observation/prev/hash``，哈希与历史逐字节相同。

        启用 ``profile="annex3-1a"``（对应 EU AI Act Art.12(3) 指向的 Annex III 1(a)）
        时，README 里承诺的四个必备字段变成**写入前置条件**：缺一项直接抛
        :class:`TraceError`，不允许「先写进去再补」——否则日志里就会出现无字段的
        合规空档，事后无法区分是漏填还是被删。

        - ``period``：``{"start","end"}``，ISO8601，end 不得早于 start；
        - ``db_ref``：参考数据库标识（建议含版本/快照号，便于复现命中）；
        - ``matched``：本步检索是否命中；为 True 时必须给 ``matched_input``；
        - ``verified_by``：做 Art.14(5) 人工复核的自然人标识，给了就生成
          ``identity_check = {verifier, method, at}``；档位开启时该项也必填。

        启用 ``profile="art12-2"``（对应 Art.12(2)(a)(b)(c)）时，``purpose`` /
        ``event_type`` / ``severity`` / ``risk_flag`` 变成写入前置条件（缺一项抛
        :class:`TraceError`），``monitor_tag`` 仍可选：

        - ``purpose``：``risk_identification`` / ``post_market_monitoring`` /
          ``deployer_evaluation``，分别对应 (a)/(b)/(c)；
        - ``event_type``：事件类型短标识（如 ``drift_detected``），用于同用途下细分；
        - ``severity``：``info/low/medium/high/critical`` 五档；
        - ``risk_flag``：本步是否属于已识别的风险情形（布尔，必填 —— 不填与"没有风险"
          在日志里无法区分）；
        - ``monitor_tag``：监测通道/批次标签，便于按来源筛取。

        未启用该档位时这五个字段仍可显式传入（进哈希、可筛取），只是不强制。
        """
        prof = self.profile
        extras: dict[str, Any] = {}

        if period is not None:
            extras["period"] = _normalize_period(period)
        if db_ref is not None:
            extras["db_ref"] = _normalize_ref(db_ref, "db_ref")
        if matched_input is not None:
            extras["matched_input"] = matched_input
        if verified_by is not None:
            identity_check = {"verifier": _normalize_ref(verified_by, "verifier"),
                              "method": str(verify_method),
                              "at": ts or (extras.get("period") or {}).get("end")}
        if identity_check is not None:
            extras["identity_check"] = _normalize_identity(identity_check)
        extras.update(_normalize_risk_fields(purpose=purpose, event_type=event_type,
                                            severity=severity, risk_flag=risk_flag,
                                            monitor_tag=monitor_tag))

        if prof == "annex3-1a":
            if "period" not in extras:
                raise TraceError(
                    "E_ANNEX3_PERIOD_MISSING: Art.12(3)(a) 要求记录本次使用的起止时间，"
                    "annex3-1a 档位下 period 不可缺省（单点 ts 不构成起止区间）")
            if "db_ref" not in extras:
                raise TraceError(
                    "E_ANNEX3_DB_REF_MISSING: Art.12(3)(b) 要求记录参考数据库，annex3-1a 档位下必填")
            if matched and "matched_input" not in extras:
                raise TraceError(
                    "E_ANNEX3_MATCHED_INPUT_MISSING: Art.12(3)(c) 要求记录导致命中的输入数据，"
                    "matched=True 时必须给 matched_input")
            if "identity_check" not in extras:
                raise TraceError(
                    "E_ANNEX3_IDENTITY_MISSING: Art.12(3)(d) 要求记录 Art.14(5) 自然人身份核验，"
                    "annex3-1a 档位下必填（可用 verified_by= 传入）")

        if prof == "art12-2":
            if "purpose" not in extras:
                raise TraceError(
                    "E_ART12_2_PURPOSE_MISSING: Art.12(2)(a)(b)(c) 要求日志可按用途筛取，"
                    "art12-2 档位下 purpose 必填（可选：%s）" % ", ".join(ART12_2_PURPOSES))
            if "event_type" not in extras:
                raise TraceError(
                    "E_ART12_2_EVENT_TYPE_MISSING: Art.12(2) 要求日志能定位到具体风险事件，"
                    "art12-2 档位下 event_type 必填")
            if "severity" not in extras:
                raise TraceError(
                    "E_ART12_2_SEVERITY_MISSING: Art.12(2) 要求按风险情形筛取，"
                    "art12-2 档位下 severity 必填（可选：%s）" % ", ".join(SEVERITY_LEVELS))
            if "risk_flag" not in extras:
                raise TraceError(
                    "E_ART12_2_RISK_FLAG_MISSING: Art.12(2)(a) 要区分「属风险情形」与普通步骤，"
                    "art12-2 档位下 risk_flag 必填（不确定不等于没风险，不填即拒绝）")

        prev = self.head
        n = len(self._entries)
        entry: dict[str, Any] = {
            "n": n,
            "ts": ts,
            "action": str(action),
            "args": args,
            "observation": observation,
        }
        entry.update(extras)
        if not _jsonable({k: v for k, v in entry.items()}):
            entry = {
                "n": n,
                "ts": ts,
                "action": str(action),
                "args": repr(args),
                "observation": repr(observation),
                "serialization": "repr",
            }
            entry.update(extras)
        entry["prev"] = prev
        entry["hash"] = entry_hash(entry, prev)
        self._entries.append(entry)
        return entry

    # ------------------------------------------------------------------ 续写
    @classmethod
    def from_body(cls, body: dict, *, verify: bool = True) -> "TraceLedger":
        """从已有轨迹体恢复账本，用于跨进程 / 跨会话续写。

        ``verify=True``（默认）先重算整链，链不自洽直接拒收——否则新条目会给旧篡改
        背书。恢复后 ``append`` 从原头部继续链接，``step_count`` 自然递增。
        """
        if not isinstance(body, dict):
            raise TraceError("E_TRACE_BODY_INVALID: 轨迹体必须是 dict")
        trace_id = body.get("trace_id")
        if not trace_id:
            raise TraceError("E_TRACE_BODY_INVALID: 轨迹体缺少 trace_id")
        entries = body.get("entries")
        if not isinstance(entries, list):
            raise TraceError("E_TRACE_BODY_INVALID: entries 必须是列表")
        if verify:
            check = verify_chain(body)
            if not check["ok"]:
                raise TraceError("E_TRACE_LOAD_BROKEN: 拒绝续写不自洽的轨迹 —— %s"
                                 % check["reason"])
        profile = body.get("profile")
        if profile is not None and profile not in ANNEX_III_VARIANTS:
            raise TraceError("E_TRACE_BODY_INVALID: 未知记录档位 %r" % (profile,))
        obj = cls(trace_id=trace_id, actor=body.get("actor"),
                  start_ts=body.get("start_ts"), profile=profile)
        obj._entries = [dict(e) for e in entries]  # noqa: SLF001
        return obj

    @classmethod
    def load(cls, path: str, *, verify: bool = True) -> "TraceLedger":
        """从磁盘轨迹 JSON 恢复账本（接受裸轨迹体或带 body 外壳的凭证文档）。"""
        if not os.path.exists(path):
            raise TraceError("E_TRACE_FILE_MISSING: 轨迹文件不存在：%s" % path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            raise TraceError("E_TRACE_FILE_UNREADABLE: %s" % exc)
        if isinstance(doc, dict) and isinstance(doc.get("body"), dict):
            doc = doc["body"]
        return cls.from_body(doc, verify=verify)

    def save(self, path: str) -> str:
        """把当前轨迹体原子写入磁盘（先写 .tmp 再替换，避免半截文件）。"""
        target_dir = os.path.dirname(os.path.abspath(path))
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.body(), fh, ensure_ascii=False, sort_keys=True, indent=1)
        os.replace(tmp, path)
        return path

    # ------------------------------------------------------------------ 读取
    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def body(self) -> dict:
        """产出自包含的轨迹体（可序列化为 JSON 落盘）。"""
        out = {
            "trace_id": self.trace_id,
            "actor": self.actor,
            "start_ts": self.start_ts,
            "step_count": len(self._entries),
            "head": self.head,
            "entries": self.entries,
        }
        if self.profile is not None:
            out["profile"] = self.profile
        return out


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
               anchor_max: int = ANCHOR_MAX, anchor_trunc: int = ANCHOR_TRUNC,
               timestamp_url: str | None = None, timestamp_timeout: float | None = None,
               timestamp_roots: Any = None) -> dict:
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

    ``timestamp_url`` 非空时，把 payload 的规范化摘要交给该 RFC 3161 TSA 换取外部
    时间戳，token 与 payload 一起落在同一份凭证文件里（见
    :func:`check_external_timestamp`）。**只承诺「这份摘要在该时刻已存在」**：TSA
    不保管你的文件，事后把整份凭证连同重签一起重做、再换一个新时间戳，仍然无法被
    本机制发现——那需要第三方留存或 WORM，不在此处。
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
    res = exit_guard.issue_credential(payload, private_key_path, issuer,
                                      exit_name=exit_name,
                                      subject=subject or body.get("trace_id"),
                                      out_path=out_path, challenge=challenge)
    if timestamp_url:
        seal_path = res.get("seal_path") or out_path
        stamp_res = stamp_path_payload(seal_path, payload, timestamp_url,
                                      timeout=timestamp_timeout,
                                      trusted_roots=timestamp_roots)
        out = dict(res)
        out["external_timestamp"] = stamp_res
        return out
    return res


def payload_imprint(payload: dict) -> str:
    """外部时间戳覆盖的摘要 = SHA256(规范化 payload)。跨机器可重算。"""
    return _sha256(_c14n(payload))


def stamp_path_payload(seal_path: str, payload: dict, url: str,
                       timeout: float | None = None,
                       trusted_roots: Any = None) -> dict:
    """为已签发的凭证补一枚外部时间戳（RFC 3161），写回同一份凭证文件。

    与 ``seal_trace(timestamp_url=...)`` 二选一使用：那条路径是签发时顺手打戳，这条是
    对既有凭证补打（例如先离线签、后联网打戳）。
    """
    from . import timestamp as _timestamp

    if not seal_path or not os.path.exists(seal_path):
        raise TraceError("补打时间戳失败：凭证文件不存在 —— %s" % seal_path)
    kwargs = {} if timeout is None else {"timeout": float(timeout)}
    digest = _timestamp.digest_of(_c14n(payload).encode("utf-8"))
    stamp = _timestamp.stamp_digest(digest, url, trusted_roots=trusted_roots, **kwargs)
    record = {
        "schema": _timestamp.SCHEMA,
        "url": stamp["url"],
        "gen_time": stamp["verified"]["tst"]["gen_time"],
        "digest_alg": stamp["digest_alg"],
        "imprint_sha256": stamp["digest_hex"],
        "nonce": stamp["nonce"],
        "token_b64": stamp["token_b64"],
        "token_sha256": stamp["token_sha256"],
    }
    _write_seal_ext(seal_path, record)
    return {"present": True, "ok": True, "gen_time": record["gen_time"],
            "url": record["url"], "token_sha256": record["token_sha256"],
            "imprint_sha256": record["imprint_sha256"]}


def _write_seal_ext(seal_path: str, record: dict) -> None:
    """原子地把 ``external_timestamp`` 段写进凭证文件（不改动 payload）。"""
    with open(seal_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise TraceError("补打时间戳失败：凭证文件结构非法")
    doc[EXT_TS_KEY] = record
    tmp = seal_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, sort_keys=True, indent=1)
    os.replace(tmp, seal_path)


def check_external_timestamp(seal_path: str, payload: dict | None = None,
                            trusted_roots: Any = None) -> dict:
    """离线复核凭证里的外部时间戳（不联网）。

    ``ok=True`` 需同时满足：token 能被解析、CMS 签名可信、``messageImprint`` 等于
    **当前** payload 的规范化摘要、nonce/ESS 绑定都对得上。因此 payload 被改过时，
    即便凭证签名那一段被绕过，时间戳这一层也会失配。
    """
    from . import timestamp as _timestamp

    out: dict[str, Any] = {"present": False, "ok": False, "reason": "E_TSA_ABSENT"}
    if not seal_path or not os.path.exists(seal_path):
        return out
    try:
        with open(seal_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        out["reason"] = "E_TSA_SEAL_UNREADABLE: %s" % exc
        return out
    record = doc.get(EXT_TS_KEY) if isinstance(doc, dict) else None
    if not isinstance(record, dict):
        return out
    ctx = payload if payload is not None else _seal_payload(seal_path)
    if not isinstance(ctx, dict):
        out.update({"present": True, "reason": "E_TSA_NO_PAYLOAD"})
        return out
    out.update({"present": True, "url": record.get("url"),
                "gen_time": record.get("gen_time"),
                "token_sha256": record.get("token_sha256"),
                "sealed_imprint_sha256": record.get("imprint_sha256")})
    try:
        token = base64.b64decode(record.get("token_b64") or "")
        digest = _timestamp.digest_of(_c14n(ctx).encode("utf-8"))
        res = _timestamp.verify_token(token, digest,
                                      hash_name=record.get("digest_alg", "sha256"),
                                      expected_nonce=record.get("nonce"),
                                      trusted_roots=trusted_roots)
    except (TraceError, ValueError, TypeError) as exc:  # binascii.Error 属 ValueError 子类
        out["reason"] = "E_TSA_TOKEN_UNUSABLE: %s" % exc
        return out
    out["ok"] = bool(res.get("ok"))
    out["reason"] = "" if out["ok"] else (res.get("reason") or "E_TSA_VERIFY_FAILED")
    out["checks"] = res.get("checks")
    out["recomputed_imprint_sha256"] = digest.hex()
    return out


def verify_sealed_trace(body: dict, seal_path: str, keys_path: str | None = None,
                        expected_challenge: str | None = None,
                        require_anchors: bool = False,
                        require_external_timestamp: bool = False,
                        trusted_roots: Any = None) -> dict:
    """三段式校验（链 / 签名 / 头摘要）+ 第四段：凭证里若带外部时间戳则离线复核。

    前三段的行为与返回值见 :func:`_verify_sealed_trace_stages`。返回体固定多一个
    ``external_timestamp``：``present`` 表示该凭证是否打了戳，``ok`` 表示戳本身是否
    通过（token 可解析、CMS 签名可信、imprint 等于**当前** payload 摘要、nonce/ESS 绑定成立）。

    ``require_external_timestamp=True`` 时，缺戳或戳不成立一律 ``verdict="INVALID"``
    （``E_TRACE_TSA_ABSENT`` / ``E_TRACE_TSA_INVALID``）——这是"要外部时间背书才算数"
    的口径；默认 ``False`` 时戳只是附加证据，不影响前三级判定，避免旧凭证集体失效。
    """
    res = _verify_sealed_trace_stages(body, seal_path, keys_path=keys_path,
                                      expected_challenge=expected_challenge,
                                      require_anchors=require_anchors)
    ext = check_external_timestamp(seal_path, trusted_roots=trusted_roots)
    res["external_timestamp"] = ext
    if not require_external_timestamp:
        return res
    if not ext.get("present"):
        out = dict(res)
        out.update({"verdict": "INVALID", "reason": "E_TRACE_TSA_ABSENT"})
        return out
    if not ext.get("ok"):
        out = dict(res)
        out.update({"verdict": "INVALID",
                    "reason": "E_TRACE_TSA_INVALID: %s" % ext.get("reason")})
        return out
    return res


def _verify_sealed_trace_stages(body: dict, seal_path: str, keys_path: str | None = None,
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
