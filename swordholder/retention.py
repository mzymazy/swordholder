# -*- coding: utf-8 -*-
"""日志留存、TTL 与归档（EU AI Act Art.19(1) / Art.26(6)）。

为什么单独一个模块
------------------
轨迹账本回答「记录有没有被改」；本模块回答另一个问题：**这份记录该留多久、什么时候
可以归档、归档副本还能不能被验**。第九阶段探针在 ``trace_ledger.py`` 里扫
``retention|ttl|expire|archive|rotate`` 命中 0 次，判定 FAIL——记录是静态 JSON，
存多久完全由部署方决定。这是「不留障碍」，不是「提供机制」。

条文口径
--------
- Art.19(1)：提供方应保留其高风险 AI 系统自动生成的日志，**期限与预期用途相称，
  且至少六个月**（除非其他法规另有规定）；
- Art.26(6)：部署方同样至少六个月。

因此本模块把「六个月」写成**硬下限** ``MIN_RETENTION_DAYS = 183``：策略声明低于它
直接抛 :class:`RetentionError`（``E_RETENTION_BELOW_FLOOR``），而不是给个默认值让人
在不知情的情况下违反。归档只写副本、**从不删除原件**——「到期可归档」不等于
「到期可销毁」，销毁属部署方的独立决定，本库不代劳（也避免把删除权塞进证据链工具）。

时区
----
一律按 UTC 计算。无时区后缀的时间串按 UTC 解释（不做本地时区猜测，避免同一份
日志在不同机器上算出不同留存期）。
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import trace_ledger as tl

MIN_RETENTION_DAYS = 183
"""Art.19(1)/Art.26(6) 的六个月下限（按 183 天算，比 6×30=180 天更严，宁可多留）。"""

ARCHIVE_SCHEMA = "swordholder.trace_archive/1"


class RetentionError(Exception):
    """留存策略非法（期限低于法定下限、时间戳无法解析、归档副本校验不通过等）。"""


# ------------------------------------------------------------------ 时间
def parse_ts(value) -> datetime:
    """把 ISO8601 字符串/时间戳解析成**带时区的 UTC** datetime。"""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str) and value.strip():
        txt = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError as exc:
            raise RetentionError("E_RETENTION_TS_INVALID: 无法解析时间 %r（%s）" % (value, exc))
    else:
        raise RetentionError("E_RETENTION_TS_INVALID: 缺少时间戳（收到 %r）" % (value,))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    """统一的 UTC 输出格式（秒级、Z 结尾，避免 +00:00 与 Z 两套写法混用）。"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ 策略
@dataclass
class RetentionPolicy:
    """留存策略。``days`` 是**声明期限**，不得低于法定下限。"""

    days: int = MIN_RETENTION_DAYS
    archive_subdir: str = "archive"
    label: str = "eu-ai-act-art19"
    rotation: str = "month"
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        try:
            days = int(self.days)
        except (TypeError, ValueError):
            raise RetentionError("E_RETENTION_POLICY_INVALID: days 必须是整数，收到 %r" % (self.days,))
        if days < MIN_RETENTION_DAYS:
            raise RetentionError(
                "E_RETENTION_BELOW_FLOOR: 声明留存 %d 天低于 Art.19(1)/Art.26(6) 的六个月下限"
                "（%d 天）。放宽到条文以下必须走法律评估，不由本库默认放行。" % (days, MIN_RETENTION_DAYS))
        if self.rotation not in ("month", "year", "none"):
            raise RetentionError("E_RETENTION_POLICY_INVALID: rotation 只能是 month/year/none")
        if not str(self.archive_subdir).strip():
            raise RetentionError("E_RETENTION_POLICY_INVALID: archive_subdir 不能为空")
        self.days = days

    # -------------------------------------------------------------- 计算
    @property
    def ttl_seconds(self) -> int:
        return self.days * 86400

    def deadline(self, ts) -> datetime:
        """某条记录的「最早可归档时间」＝起始时间 + 声明期限（必然 ≥ 法定下限）。"""
        return parse_ts(ts) + timedelta(days=self.days)

    def legal_floor_deadline(self, ts) -> datetime:
        return parse_ts(ts) + timedelta(days=MIN_RETENTION_DAYS)

    def rotation_key(self, ts) -> str:
        dt = parse_ts(ts)
        if self.rotation == "year":
            return dt.strftime("%Y")
        if self.rotation == "none":
            return "all"
        return dt.strftime("%Y-%m")

    def to_dict(self) -> dict:
        return {"label": self.label, "days": self.days, "ttl_seconds": self.ttl_seconds,
                "min_days_floor": MIN_RETENTION_DAYS, "rotation": self.rotation,
                "archive_subdir": self.archive_subdir, "extra": dict(self.extra)}


# ------------------------------------------------------------------ 到期判定
def classify(ts, policy: RetentionPolicy, now=None) -> dict:
    """判定一条记录当前处于什么状态。

    ``state`` 取值：

    - ``retained``：未满声明期限，必须继续保留（可能已满法定下限）；
    - ``archive_due``：已满声明期限，**可以**归档（不是必须销毁）。

    ``age_days`` 保留两位小数，便于报告里直接引用。
    """
    if not isinstance(policy, RetentionPolicy):
        raise RetentionError("E_RETENTION_POLICY_INVALID: policy 必须是 RetentionPolicy")
    start = parse_ts(ts)
    ref = parse_ts(now) if now is not None else utcnow()
    if ref < start:
        raise RetentionError("E_RETENTION_TS_INVALID: 参照时间 %s 早于记录起始时间 %s"
                             % (iso(ref), iso(start)))
    age_seconds = (ref - start).total_seconds()
    deadline = policy.deadline(start)
    return {
        "state": "archive_due" if ref >= deadline else "retained",
        "age_days": round(age_seconds / 86400.0, 2),
        "retention_days": policy.days,
        "legal_floor_days": MIN_RETENTION_DAYS,
        "meets_legal_floor": age_seconds >= MIN_RETENTION_DAYS * 86400,
        "deadline": iso(deadline),
        "days_remaining": max(0, int((deadline - ref).total_seconds() // 86400)),
        "checked_at": iso(ref),
    }


def plan(bodies, policy: RetentionPolicy, now=None) -> dict:
    """批量到期盘点。输入是轨迹体列表，输出可归档 / 仍保留两组及计数。"""
    if not isinstance(policy, RetentionPolicy):
        raise RetentionError("E_RETENTION_POLICY_INVALID: policy 必须是 RetentionPolicy")
    groups = {"retained": [], "archive_due": []}
    records = []
    for body in bodies or []:
        trace_id = body.get("trace_id")
        start = body.get("start_ts") or (body.get("entries") or [{}])[0].get("ts")
        if start is None:
            raise RetentionError(
                "E_RETENTION_TS_INVALID: 轨迹 %r 没有起点时间（start_ts 与第一步 ts 均为空），"
                "无法计算留存期——宁可不判定，也不默认它刚生成" % (trace_id,))
        item = {"trace_id": trace_id, "step_count": body.get("step_count"),
                "rotation": policy.rotation_key(start)}
        item.update(classify(start, policy, now=now))
        groups[item["state"]].append(item)
        records.append(item)
    return {
        "policy": policy.to_dict(),
        "checked_at": iso(parse_ts(now) if now is not None else utcnow()),
        "total": len(records),
        "retained": len(groups["retained"]),
        "archive_due": len(groups["archive_due"]),
        "records": records,
    }


# ------------------------------------------------------------------ 归档
def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def archive_dir(root: str, policy: RetentionPolicy, ts) -> str:
    """归档目录 = ``root/archive/<rotation key>``；按月分片，避免单目录无限膨胀。"""
    return os.path.join(root, policy.archive_subdir, policy.rotation_key(ts))


def archive_record(body: dict, root: str, policy: RetentionPolicy, now=None,
                   sealed_path: str | None = None) -> dict:
    """把一份轨迹体写成归档副本（**不删除、不改动原件**）。

    副本自带 ``digest`` 与全量 ``body_sha256``，并用 ``verify_archive`` 做自检，
    防止「归档即失控」：文件拷出去之后仍能证明它是不是当初那份。
    """
    if not isinstance(policy, RetentionPolicy):
        raise RetentionError("E_RETENTION_POLICY_INVALID: policy 必须是 RetentionPolicy")
    check = tl.verify_chain(body)
    if not check["ok"]:
        raise RetentionError("拒绝归档：轨迹自身不自洽 —— " + check["reason"])

    start = body.get("start_ts") or (body.get("entries") or [{}])[0].get("ts")
    if start is None:
        raise RetentionError("E_RETENTION_TS_INVALID: 轨迹缺少起点时间，无法归档")
    ref = parse_ts(now) if now is not None else utcnow()
    state = classify(start, policy, now=ref)
    if state["state"] != "archive_due":
        raise RetentionError(
            "E_RETENTION_TOO_EARLY: 记录仅 %s 天，未满声明期限 %d 天，尚未到可归档时间"
            % (state["age_days"], policy.days))

    target_dir = archive_dir(root, policy, start)
    os.makedirs(target_dir, exist_ok=True)
    head = str(body.get("head") or "")[:8]
    name = "%s.%s.json" % (body.get("trace_id"), head)
    path = os.path.join(target_dir, name)
    if os.path.exists(path) and verify_archive(path).get("digest_match"):
        raise RetentionError("E_RETENTION_ARCHIVE_EXISTS: 归档副本已存在且完好：%s" % path)

    payload = {
        "schema": ARCHIVE_SCHEMA,
        "archived_at": iso(ref),
        "policy": policy.to_dict(),
        "trace_id": body.get("trace_id"),
        "step_count": body.get("step_count"),
        "head": body.get("head"),
        "digest": tl.body_digest(body),
        "body_sha256": hashlib.sha256(tl._c14n(body).encode("utf-8")).hexdigest(),  # noqa: SLF001
        "sealed_copy": os.path.basename(sealed_path) if sealed_path else None,
        "body": body,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, sort_keys=True, indent=1)
    os.replace(tmp, path)

    verified = verify_archive(path)
    return {"path": path, "sha256": _file_sha256(path), "verified": verified,
            "state": state}


def verify_archive(path: str) -> dict:
    """校验归档副本：结构完整 + 链自洽 + 摘要与文件内容一致。"""
    out = {"path": path, "ok": False, "reason": "", "digest_match": False,
           "chain_ok": False, "trace_id": None, "step_count": None}
    if not os.path.exists(path):
        out["reason"] = "E_RETENTION_ARCHIVE_MISSING"
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        out["reason"] = "E_RETENTION_ARCHIVE_UNREADABLE: %s" % exc
        return out
    if not isinstance(doc, dict) or doc.get("schema") != ARCHIVE_SCHEMA:
        out["reason"] = "E_RETENTION_ARCHIVE_SCHEMA: 不是 %s 归档副本" % ARCHIVE_SCHEMA
        return out
    body = doc.get("body")
    if not isinstance(body, dict):
        out["reason"] = "E_RETENTION_ARCHIVE_SCHEMA: 缺少 body"
        return out
    out["trace_id"] = doc.get("trace_id")
    out["step_count"] = doc.get("step_count")
    chain = tl.verify_chain(body)
    out["chain_ok"] = bool(chain["ok"])
    out["digest_match"] = doc.get("digest") == tl.body_digest(body)
    body_sha = hashlib.sha256(tl._c14n(body).encode("utf-8")).hexdigest()  # noqa: SLF001
    out["body_sha256_match"] = doc.get("body_sha256") == body_sha
    out["ok"] = bool(chain["ok"] and out["digest_match"] and out["body_sha256_match"])
    if not out["ok"]:
        if not chain["ok"]:
            out["reason"] = "E_RETENTION_ARCHIVE_CHAIN: " + chain["reason"]
        elif not out["digest_match"]:
            out["reason"] = "E_RETENTION_ARCHIVE_DIGEST_MISMATCH"
        else:
            out["reason"] = "E_RETENTION_ARCHIVE_BODY_MISMATCH"
    return out
