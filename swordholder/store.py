"""凭证索引：SQLite 落盘，供服务端按主体/结论/时间检索。

只做索引，不做事实源 —— 事实源永远是磁盘上的 ``*.seal.json`` 文件，
索引只存"路径 + 关键字段"，删库不丢凭证，重建可回填。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS seals (
    seal_id        TEXT PRIMARY KEY,
    subject        TEXT,
    issuer         TEXT,
    payload_sha256 TEXT NOT NULL,
    alert_id       TEXT,
    triage_verdict TEXT,
    severity       TEXT,
    confidence     REAL,
    engine         TEXT,
    signature      TEXT,
    created_at     TEXT,
    path           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_seals_created  ON seals(created_at);
CREATE INDEX IF NOT EXISTS idx_seals_verdict  ON seals(triage_verdict);
CREATE INDEX IF NOT EXISTS idx_seals_subject  ON seals(subject);
"""


class Store:
    """线程安全的最小索引封装。"""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- 写入 ---------------------------------------------------------------
    def add_seal(self, seal_path: str, document: dict | None = None,
                 signature: str | None = None) -> dict:
        """登记一份已落盘的凭证。document 缺省时从磁盘读。"""
        if document is None:
            with open(seal_path, "r", encoding="utf-8") as f:
                document = json.load(f)
        header = document.get("seal_header") or {}
        payload = document.get("payload") or {}
        if signature is None:
            signature = (document.get("signature") or {}).get("value")
        row = {
            "seal_id": header.get("seal_id"),
            "subject": header.get("subject"),
            "issuer": header.get("issuer"),
            "payload_sha256": header.get("payload_sha256") or "",
            "alert_id": payload.get("alert_id"),
            "triage_verdict": payload.get("verdict"),
            "severity": payload.get("severity"),
            "confidence": payload.get("confidence"),
            "engine": payload.get("engine"),
            "signature": signature,
            "created_at": header.get("created_at"),
            "path": os.path.abspath(seal_path),
        }
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO seals (seal_id, subject, issuer, payload_sha256,"
                " alert_id, triage_verdict, severity, confidence, engine, signature,"
                " created_at, path) VALUES (:seal_id, :subject, :issuer, :payload_sha256,"
                " :alert_id, :triage_verdict, :severity, :confidence, :engine, :signature,"
                " :created_at, :path)", row)
            self._conn.commit()
        return row

    # -- 读取 ---------------------------------------------------------------
    def get(self, seal_id: str) -> dict | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM seals WHERE seal_id = ?", (seal_id,))
            row = cur.fetchone()
        return dict(row) if row else None

    def find_by_payload(self, payload_sha256: str) -> dict | None:
        """按内容哈希查已有凭证（服务端幂等用）。"""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM seals WHERE payload_sha256 = ? ORDER BY created_at ASC LIMIT 1",
                (payload_sha256,))
            row = cur.fetchone()
        return dict(row) if row else None

    def query(self, verdict: str | None = None, subject: str | None = None,
              alert_id: str | None = None, since: str | None = None,
              limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM seals WHERE 1=1"
        args: list[Any] = []
        if verdict:
            sql += " AND triage_verdict = ?"
            args.append(verdict)
        if subject:
            sql += " AND subject = ?"
            args.append(subject)
        if alert_id:
            sql += " AND alert_id = ?"
            args.append(alert_id)
        if since:
            sql += " AND created_at >= ?"
            args.append(since)
        sql += " ORDER BY created_at DESC, seal_id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self._lock:
            cur = self._conn.execute(sql, args)
            return [dict(r) for r in cur.fetchall()]

    def stats(self) -> dict:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM seals").fetchone()[0]
            rows = self._conn.execute(
                "SELECT triage_verdict, COUNT(*) AS n FROM seals GROUP BY triage_verdict").fetchall()
        return {"total": total, "by_verdict": {r["triage_verdict"]: r["n"] for r in rows}}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
