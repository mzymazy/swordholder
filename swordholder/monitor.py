# -*- coding: utf-8 -*-
"""部署期持续跟踪（Deployment-time continuous tracking）。

对应 NIST AI RMF 1.0 MEASURE 3.1 的 "regularly identify and track existing,
unanticipated, and emergent AI risks based on ... intended and actual
performance in deployed contexts"。

为什么需要这一层
----------------
bench / 探针证明的是**研发期**某个时刻的度量：跑一次、落一份 JSON、写进报告。
但轨迹账本在客户机器上是**每天在被写**的，真正会出事的地方是运行期——
磁盘写坏、进程被杀导致半截文件、有人手工改一条日志、归档时链断了。
这些都不会出现在研发期证据里，因为研发期没有"部署后的数据流"。

本模块把「跑一次」变成「按周期量」，并且让量本身也可核：
- 每次扫描产出一条记录，记录写进 append-only 的监控日志；
- 日志自身是哈希链，删一条、改一条、插一条都能被 verify_log 指出来；
- 日志跨进程可续：昨天运维跑的扫描和今天的扫描在同一条链上。

边界（不夸大）
--------------
- 这是一个**库 + CLI**，由部署方用调度器（cron / 计划任务 / systemd timer）
  按周期调用；它不是常驻守护进程，也不做告警外发（不接 PagerDuty / 短信）。
- 阈值是"部署方自定"的：本模块只负责算准数字并按阈值判级，不替客户定风险偏好。
- 只读被监控目录，不删除、不修改轨迹文件（唯一写入对象是自己的监控日志）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any, Callable

from . import trace_ledger as tl

MONITOR_SCHEMA = "swordholder.monitor/1"
LOG_SCHEMA = "swordholder.monitor_log/1"
LOG_GENESIS = "0" * 64

DEFAULT_THRESHOLDS = {
    "chain_break": 0,
    "digest_mismatch": 0,
    "seal_invalid": 0,
    "unreadable": 0,
    "error_rate": 0.05,
}

TRACE_SUFFIXES = (".trace.json", ".body.json", ".seal.json")


class MonitorError(ValueError):
    """监控无法继续（配置非法、日志被改等）。"""


def _c14n(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _sha256(obj: Any) -> str:
    return hashlib.sha256(_c14n(obj)).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------- 单文件判定
def evaluate_trace(path: str) -> dict:
    """判定单个轨迹文件。返回结构固定，便于按周期比对。"""
    out = {
        "path": path,
        "trace_id": None,
        "step_count": None,
        "ok": False,
        "sealed": False,
        "problems": [],
    }

    def bad(code: str, detail: str) -> None:
        out["problems"].append({"code": code, "detail": detail})

    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        bad("E_MON_UNREADABLE", "文件不存在")
        return out
    except (OSError, ValueError) as exc:
        bad("E_MON_UNREADABLE", "无法解析 JSON：%s" % exc)
        return out

    sealed = False
    body = doc
    if isinstance(doc, dict) and isinstance(doc.get("body"), dict):
        body = doc["body"]
        sealed = any(k in doc for k in ("signature", "sig", "seal"))
    if not isinstance(body, dict) or not body.get("trace_id"):
        bad("E_MON_SHAPE", "缺少 trace_id，不是轨迹体")
        return out

    out["trace_id"] = body.get("trace_id")
    out["step_count"] = body.get("step_count")
    out["sealed"] = sealed

    chain = tl.verify_chain(body)
    if not chain["ok"]:
        bad("E_MON_CHAIN_BREAK", chain["reason"])

    # 摘要独立重算：防止有人把 entries 改完顺手把 step_count/head 也改齐
    try:
        recomputed = tl.body_digest(body)
        declared = body.get("body_digest") or doc.get("body_digest")
        if declared and declared != recomputed:
            bad("E_MON_DIGEST_MISMATCH", "body_digest 与重算值不一致")
    except Exception as exc:  # noqa: BLE001  旧格式可能没有摘要字段
        if sealed:
            bad("E_MON_DIGEST_MISMATCH", "摘要无法重算：%s" % exc)

    if sealed:
        try:
            verdict = tl.verify_sealed_trace(doc)
            if verdict.get("verdict") != "VALID":
                bad("E_MON_SEAL_INVALID", str(verdict.get("reason"))[:200])
        except Exception as exc:  # noqa: BLE001
            bad("E_MON_SEAL_INVALID", "验签异常：%s" % exc)

    out["ok"] = not out["problems"]
    return out


def scan_dir(root: str) -> dict:
    """扫一个目录下所有轨迹文件，返回一次扫描的度量。"""
    if not os.path.isdir(root):
        raise MonitorError("E_MON_DIR_MISSING: 目录不存在：%s" % root)
    files = sorted(
        os.path.join(root, f) for f in os.listdir(root)
        if f.endswith(TRACE_SUFFIXES) and os.path.isfile(os.path.join(root, f))
    )
    results = [evaluate_trace(p) for p in files]
    counts = {"chain_break": 0, "digest_mismatch": 0, "seal_invalid": 0, "unreadable": 0}
    for r in results:
        for p in r["problems"]:
            if p["code"] == "E_MON_CHAIN_BREAK":
                counts["chain_break"] += 1
            elif p["code"] == "E_MON_DIGEST_MISMATCH":
                counts["digest_mismatch"] += 1
            elif p["code"] == "E_MON_SEAL_INVALID":
                counts["seal_invalid"] += 1
            else:
                counts["unreadable"] += 1
    total = len(results)
    ok = sum(1 for r in results if r["ok"])
    metrics = {
        "root": os.path.abspath(root),
        "traces_total": total,
        "verified_ok": ok,
        "failed": total - ok,
        "chain_break": counts["chain_break"],
        "digest_mismatch": counts["digest_mismatch"],
        "seal_invalid": counts["seal_invalid"],
        "unreadable": counts["unreadable"],
        "error_rate": round((total - ok) / total, 6) if total else 0.0,
        "steps_total": sum(r["step_count"] or 0 for r in results),
    }
    return {"metrics": metrics, "results": results}


# ---------------------------------------------------------------------- 日志链
def log_entry_hash(entry: dict, prev: str) -> str:
    core = {k: v for k, v in entry.items() if k != "hash"}
    core["prev"] = prev
    return _sha256(core)


def verify_log(path: str) -> dict:
    """校验监控日志自身的哈希链（删/改/插均能定位）。"""
    if not os.path.exists(path):
        return {"ok": False, "records": 0, "first_break": None,
                "reason": "日志不存在：%s" % path}
    prev, n = LOG_GENESIS, 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("prev") != prev:
                    return {"ok": False, "records": n, "first_break": lineno,
                            "reason": "第 %d 条记录的 prev 与上一条不符（疑似删/插）" % lineno}
                if log_entry_hash(rec, prev) != rec.get("hash"):
                    return {"ok": False, "records": n, "first_break": lineno,
                            "reason": "第 %d 条记录内容与哈希不符（疑似改值）" % lineno}
                prev = rec["hash"]
                n += 1
    except (OSError, ValueError) as exc:
        return {"ok": False, "records": n, "first_break": n + 1,
                "reason": "读取失败：%s" % exc}
    return {"ok": True, "records": n, "first_break": None, "reason": "", "head": prev}


def read_log(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


class Monitor:
    """按周期量部署期轨迹健康度，并把每次量写进可校验的日志链。"""

    def __init__(self, root: str, log_path: str | None = None,
                 thresholds: dict | None = None, actor: str = "monitor"):
        if not root:
            raise MonitorError("E_MON_DIR_MISSING: 必须指定被监控目录")
        self.root = os.path.abspath(root)
        self.log_path = log_path or os.path.join(self.root, "monitor_log.jsonl")
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            unknown = set(thresholds) - set(DEFAULT_THRESHOLDS)
            if unknown:
                raise MonitorError("E_MON_THRESHOLD_UNKNOWN: 未知阈值项 %s"
                                   % ", ".join(sorted(unknown)))
            self.thresholds.update(thresholds)
        self.actor = actor

    # -------------------------------------------------- 告警判定
    def _alerts(self, metrics: dict) -> list[dict]:
        alerts = []
        checks = (
            ("chain_break", "E_MON_CHAIN_BREAK", "critical",
             "轨迹链断裂，存在被改动或写坏的文件"),
            ("digest_mismatch", "E_MON_DIGEST_MISMATCH", "high",
             "轨迹摘要与重算值不一致"),
            ("seal_invalid", "E_MON_SEAL_INVALID", "high",
             "已签轨迹验签不通过"),
            ("unreadable", "E_MON_UNREADABLE", "medium",
             "轨迹文件无法解析"),
            ("error_rate", "E_MON_ERROR_RATE", "medium",
             "失败率超过部署方阈值"),
        )
        for field, code, level, message in checks:
            limit = self.thresholds[field]
            if metrics[field] > limit:
                alerts.append({
                    "code": code,
                    "level": level,
                    "field": field,
                    "observed": metrics[field],
                    "threshold": limit,
                    "message": message,
                })
        return alerts

    # -------------------------------------------------- 一次扫描
    def scan_once(self, now: str | None = None) -> dict:
        result = scan_dir(self.root)
        metrics = result["metrics"]
        alerts = self._alerts(metrics)
        prev = LOG_GENESIS
        existing = read_log(self.log_path)
        if existing:
            check = verify_log(self.log_path)
            if not check["ok"]:
                raise MonitorError("E_MON_LOG_BROKEN: 监控日志已不可信，拒绝续写 —— %s"
                                   % check["reason"])
            prev = existing[-1]["hash"]
        record = {
            "schema": LOG_SCHEMA,
            "n": len(existing) + 1,
            "ts": now or _now(),
            "actor": self.actor,
            "metrics": metrics,
            "alerts": alerts,
            "worst_level": max([a["level"] for a in alerts],
                               key=["low", "medium", "high", "critical"].index,
                               default="none"),
            "prev": prev,
        }
        record["hash"] = log_entry_hash(record, prev)
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)) or ".", exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return record

    # -------------------------------------------------- 周期跟踪
    def watch(self, cycles: int = 1, interval: float = 0.0,
              sleep: Callable[[float], None] = time.sleep) -> list[dict]:
        """按周期连续扫描 cycles 次（部署方用调度器调用即为持续跟踪）。"""
        if cycles < 1:
            raise MonitorError("E_MON_CYCLES_INVALID: cycles 必须 >= 1")
        records = []
        for i in range(cycles):
            records.append(self.scan_once())
            if interval and i < cycles - 1:
                sleep(interval)
        return records

    # -------------------------------------------------- 汇总
    def report(self, last: int | None = None) -> dict:
        records = read_log(self.log_path)
        if last:
            records = records[-last:]
        if not records:
            return {"schema": MONITOR_SCHEMA, "records": 0,
                    "log_ok": verify_log(self.log_path)["ok"],
                    "alerts_total": 0, "by_code": {}, "first_ts": None,
                    "last_ts": None, "latest": None}
        by_code: dict[str, int] = {}
        for r in records:
            for a in r["alerts"]:
                by_code[a["code"]] = by_code.get(a["code"], 0) + 1
        return {
            "schema": MONITOR_SCHEMA,
            "records": len(records),
            "log_ok": verify_log(self.log_path)["ok"],
            "alerts_total": sum(len(r["alerts"]) for r in records),
            "by_code": by_code,
            "first_ts": records[0]["ts"],
            "last_ts": records[-1]["ts"],
            "latest_metrics": records[-1]["metrics"],
        }


# ---------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m swordholder.monitor",
        description="部署期持续跟踪：按周期扫描轨迹目录，输出 JSON 度量与告警")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="扫描一次并写入监控日志")
    p_scan.add_argument("--dir", required=True, help="被监控的轨迹目录")
    p_scan.add_argument("--log", default=None, help="监控日志路径（默认 <dir>/monitor_log.jsonl）")
    p_scan.add_argument("--cycles", type=int, default=1, help="连续扫描轮数")
    p_scan.add_argument("--interval", type=float, default=0.0, help="轮间隔秒数")
    p_scan.add_argument("--json-out", default=None, help="把结果写入 JSON 文件")

    p_rep = sub.add_parser("report", help="汇总监控日志")
    p_rep.add_argument("--dir", default=None, help="被监控目录（用于推导默认日志路径）")
    p_rep.add_argument("--log", default=None)
    p_rep.add_argument("--last", type=int, default=None)
    p_rep.add_argument("--json-out", default=None)

    p_ver = sub.add_parser("verify-log", help="校验监控日志自身链是否完整")
    p_ver.add_argument("--log", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        mon = Monitor(args.dir, log_path=args.log)
        records = mon.watch(cycles=args.cycles, interval=args.interval)
        payload = {"schema": MONITOR_SCHEMA, "records": records,
                   "report": mon.report()}
    elif args.cmd == "report":
        log = args.log or os.path.join(args.dir or ".", "monitor_log.jsonl")
        mon = Monitor(args.dir or os.path.dirname(os.path.abspath(log)), log_path=log)
        payload = mon.report(last=args.last)
    else:
        payload = verify_log(args.log)

    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=1)
    print(text)
    if getattr(args, "json_out", None):
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if payload.get("ok", True) is not False else 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
