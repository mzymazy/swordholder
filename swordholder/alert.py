"""告警输入适配层。

真实 SOC 里没有"标准告警"：Splunk notable event、Microsoft Sentinel incident、
Wazuh alert、以及本地自建格式各说各话。这里做的事只有一件 ——
把各路原始事件**无损归一**成内部结构，并明确报出缺什么字段，
而不是靠关键词瞎猜。

设计约束：
1. 零外部依赖（便于在隔离环境里跑）；
2. 未知格式不猜，报 E_UNKNOWN_FORMAT，让调用方显式指定；
3. 原始载荷完整保留在 ``raw``，并附 canonical sha256，便于事后审计与对账；
4. 归一化结果保证含 rules 层需要的字段：alert_id / title / severity / signal。

用法::

    from swordholder.alert import normalize
    alert = normalize(raw_event, fmt="splunk")
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

SEVERITIES = ("low", "medium", "high", "critical")

# 内部结构的契约版本，随 alert.schema.json 同步
SCHEMA_VERSION = "1.0"


class AlertError(ValueError):
    """告警无法归一（非法类型、缺关键字段、未知格式）。"""

    def __init__(self, errors: list[dict]):
        self.errors = errors
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))

    def to_dict(self) -> dict:
        return {"ok": False, "code": "E_ALERT_INVALID", "errors": self.errors}


def _err(field: str, message: str, code: str = "E_FIELD") -> dict:
    return {"field": field, "code": code, "message": message}


def _first(d: Any, *keys: str, default: Any = None) -> Any:
    """按顺序取第一个非空字段。"""
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


def _severity(value: Any, default: str = "medium") -> str:
    """把各家严重度刻度压到 low/medium/high/critical。"""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        # Wazuh 用 0-15；其它数值刻度按同一比例归并
        n = float(value)
        if n <= 3:
            return "low"
        if n <= 7:
            return "medium"
        if n <= 11:
            return "high"
        return "critical"
    s = str(value).strip().lower()
    table = {
        "critical": "critical", "crit": "critical", "severe": "critical",
        "p1": "critical", "urgent": "critical", "emergency": "critical",
        "high": "high", "p2": "high", "major": "high",
        "medium": "medium", "med": "medium", "moderate": "medium", "p3": "medium",
        "low": "low", "p4": "low", "minor": "low", "informational": "low",
        "info": "low", "warning": "medium",
    }
    if s in table:
        return table[s]
    if s.isdigit():
        return _severity(int(s), default)
    return default


def _canonical_sha256(obj: Any) -> str:
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _fmt_ref(alert_id: str, fmt: str) -> str:
    return f"{fmt}:{alert_id}"


# --------------------------------------------------------------------------
# 各来源适配器：输入原始 dict，输出内部字段的"半成品"，缺的由 finalize 补
# --------------------------------------------------------------------------

def _adapt_generic(raw: dict) -> dict:
    """内部/自定义格式，兼容常见别名。"""
    return {
        "alert_id": _first(raw, "alert_id", "id", "event_id", "record_id"),
        "title": _first(raw, "title", "name", "rule_name", "message"),
        "severity": raw.get("severity"),
        "signal": _first(raw, "signal", "signals", "rule", "category", "event_type"),
        "description": _first(raw, "description", "desc", "detail", "summary"),
        "asset": _first(raw, "asset", "host", "hostname", "src", "source_host"),
        "tags": raw.get("tags"),
        "observed_at": _first(raw, "observed_at", "timestamp", "time", "ts"),
        "ref": _fmt_ref(str(_first(raw, "alert_id", "id", "event_id", "record_id") or ""),
                         "generic"),
    }


def _adapt_splunk(raw: dict) -> dict:
    """Splunk ES notable event / 普通 saved search 结果。"""
    event_id = _first(raw, "event_id", "sid", "search_id", "alert_id", "id")
    rule = _first(raw, "search_name", "rule_name", "savedsearch_name", "title")
    signature = _first(raw, "signature", "rule_title", "description")
    urgency = _first(raw, "urgency", "priority", "severity")
    asset = _first(raw, "dest", "src", "host", "src_ip")
    tags = raw.get("tag") or raw.get("tags")
    if isinstance(tags, str):
        tags = [t for t in tags.replace(";", ",").split(",") if t.strip()]
    return {
        "alert_id": event_id,
        "title": rule or signature,
        "severity": urgency,
        "signal": " ".join(str(x) for x in [rule, signature] if x),
        "description": _first(raw, "description", "message", "_raw"),
        "asset": asset,
        "tags": tags,
        "observed_at": _first(raw, "_time", "timestamp", "time"),
        "ref": str(_first(raw, "result_link", "search_id", "sid") or _fmt_ref(str(event_id or ""), "splunk")),
    }


def _adapt_sentinel(raw: dict) -> dict:
    """Microsoft Sentinel incident（含 properties 包装）。"""
    props = raw.get("properties") if isinstance(raw.get("properties"), dict) else raw
    incident = _first(props, "incidentNumber", "providerIncidentId", "name", "incidentId")
    entities = props.get("entities") or props.get("relatedEntities") or []
    asset = None
    for ent in entities if isinstance(entities, list) else []:
        if not isinstance(ent, dict):
            continue
        asset = _first(ent, "hostName", "address", "fqdn", "name")
        if asset:
            break
    tactics = props.get("tactics") or props.get("additionalData", {}).get("tactics")
    if isinstance(tactics, str):
        tactics = [t.strip() for t in tactics.split(",") if t.strip()]
    return {
        "alert_id": incident,
        "title": _first(props, "title", "incidentName", "alertDisplayName"),
        "severity": props.get("severity"),
        "signal": _first(props, "alertDisplayName", "title", "alertProductNames"),
        "description": _first(props, "description", "alertDescription", "summary"),
        "asset": asset,
        "tags": tactics if isinstance(tactics, list) else None,
        "observed_at": _first(props, "createdTimeUtc", "startTimeUtc", "firstActivityTimeUtc"),
        "ref": _fmt_ref(str(incident or ""), "sentinel"),
    }


def _adapt_wazuh(raw: dict) -> dict:
    """Wazuh / OSSEC alert。"""
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    alert_id = _first(raw, "id", "alert_id") or _first(rule, "id")
    desc = _first(rule, "description", "comment") or _first(raw, "full_log", "description")
    groups = _first(rule, "groups", "group")
    if isinstance(groups, str):
        groups = [g for g in groups.split(",") if g.strip()]
    return {
        "alert_id": alert_id,
        "title": desc,
        "severity": _first(rule, "level", "severity"),
        "signal": " ".join(str(x) for x in [desc, _first(rule, "id") or ""] if x),
        "description": _first(raw, "full_log", "description", "detail"),
        "asset": _first(agent, "name", "id"),
        "tags": groups if isinstance(groups, list) else None,
        "observed_at": _first(raw, "timestamp", "@timestamp"),
        "ref": _fmt_ref(str(alert_id or ""), "wazuh"),
    }


ADAPTERS: dict[str, Callable[[dict], dict]] = {
    "generic": _adapt_generic,
    "splunk": _adapt_splunk,
    "sentinel": _adapt_sentinel,
    "wazuh": _adapt_wazuh,
}


def detect_format(raw: Any) -> str | None:
    """按结构特征识别来源；识别不出返回 None（不猜）。"""
    if not isinstance(raw, dict):
        return None
    if isinstance(raw.get("properties"), dict) and (
            "incidentNumber" in raw["properties"] or "providerIncidentId" in raw["properties"]
            or "alertDisplayName" in raw["properties"]):
        return "sentinel"
    if isinstance(raw.get("rule"), dict) and ("level" in raw["rule"] or "description" in raw["rule"]):
        return "wazuh"
    if any(k in raw for k in ("search_name", "savedsearch_name", "result_link")) or (
            "_time" in raw and ("sid" in raw or "urgency" in raw)):
        return "splunk"
    if any(k in raw for k in ("alert_id", "signal", "signals")):
        return "generic"
    return None


def normalize(raw: Any, fmt: str = "auto", *, strict_severity: bool = False) -> dict:
    """归一化一条告警。

    fmt: auto / generic / splunk / sentinel / wazuh
    返回内部结构；非法输入抛 :class:`AlertError`。
    """
    if not isinstance(raw, dict):
        raise AlertError([_err("$", "告警必须是 JSON 对象", "E_ALERT_NOT_OBJECT")])

    resolved = detect_format(raw) if fmt in (None, "", "auto") else str(fmt).lower()
    if resolved is None:
        raise AlertError([_err(
            "format",
            "无法识别来源格式，请用 format 显式指定：generic/splunk/sentinel/wazuh",
            "E_UNKNOWN_FORMAT")])
    if resolved not in ADAPTERS:
        raise AlertError([_err("format", f"不支持的格式：{resolved}（可选 {sorted(ADAPTERS)}）",
                              "E_UNKNOWN_FORMAT")])

    part = ADAPTERS[resolved](raw)
    errors: list[dict] = []
    alert_id = part.get("alert_id")
    if alert_id in (None, ""):
        errors.append(_err("alert_id", "缺少唯一标识（alert_id/id/event_id/incidentNumber）",
                           "E_MISSING_FIELD"))
    if not part.get("title") and not part.get("signal"):
        errors.append(_err("title", "缺少标题或规则名，无法定性", "E_MISSING_FIELD"))

    raw_sev = part.get("severity")
    if raw_sev not in (None, "") and str(raw_sev).strip().lower() not in SEVERITIES:
        mapped = _severity(raw_sev, default="")
        if not mapped and strict_severity:
            errors.append(_err("severity", f"无法识别的严重度：{raw_sev}", "E_BAD_SEVERITY"))
    if errors:
        raise AlertError(errors)

    tags = part.get("tags")
    if isinstance(tags, str):
        tags = [tags]
    tags = [str(t) for t in tags] if isinstance(tags, list) else []

    out = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": str(alert_id),
        "title": str(part.get("title") or part.get("signal") or ""),
        "severity": _severity(raw_sev),
        "signal": str(part.get("signal") or ""),
        "description": str(part.get("description") or ""),
        "asset": part.get("asset"),
        "tags": tags,
        "observed_at": part.get("observed_at"),
        "source": {
            "format": resolved,
            "ref": part.get("ref"),
            "raw_sha256": _canonical_sha256(raw),
        },
        "raw": raw,
    }
    return out


def normalize_file(path: str, fmt: str = "auto") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return normalize(json.load(f), fmt=fmt)
