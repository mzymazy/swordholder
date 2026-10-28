"""HTTP 服务：把 triage → 盖章 → 验签 → 落索引 串成一条在线链路。

只依赖标准库。默认绑定 127.0.0.1；绑到非回环地址时必须给 ``--token``，
避免把"能签发凭证的接口"裸奔到网络上（签发权 = 话语权）。

接口：
    GET  /healthz             健康检查
    GET  /v1/schema           内部告警契约（alert.schema.json）
    POST /v1/triage           输入告警（任意已支持来源），返回分诊结论 [+ 凭证]
    GET  /v1/seals            最近凭证（需 --db）
    GET  /v1/seals/<seal_id>  单份凭证（需 --db）
    POST /v1/verify           提交一份凭证，返回验签结论（无状态）
"""

from __future__ import annotations

import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__, core, rules
from .alert import AlertError, normalize
from .store import Store

MAX_BODY = 1 << 20  # 1 MiB，告警是事件不是日志包
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert.schema.json")


class ServerConfig:
    def __init__(self, host: str = "127.0.0.1", port: int = 8099,
                 out_dir: str = ".seals", key_path: str | None = None,
                 issuer: str = "swordholder-serve", keys_file: str | None = None,
                 db: str | None = None, token: str | None = None,
                 use_llm: bool = False, seal: bool = True):
        self.host = host
        self.port = port
        self.out_dir = out_dir
        self.key_path = key_path
        self.issuer = issuer
        self.keys_file = keys_file
        self.db = db
        self.token = token
        self.use_llm = use_llm
        self.seal = seal
        self.store: Store | None = Store(db) if db else None
        self._lock = threading.Lock()

    def close(self) -> None:
        if self.store:
            self.store.close()


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(text))[:64] or "alert"


def make_handler(cfg: ServerConfig):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"swordholder/{__version__}"
        protocol_version = "HTTP/1.1"

        # -- 基础工具 -----------------------------------------------------
        def log_message(self, fmt: str, *args: Any) -> None:
            if os.environ.get("SWORDHOLDER_HTTP_LOG"):
                super().log_message(fmt, *args)

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Swordholder-Version", __version__)
            self.end_headers()
            self.wfile.write(body)

        def _fail(self, code: int, err_code: str, message: str, **extra: Any) -> None:
            self._send(code, dict({"ok": False, "code": err_code, "message": message}, **extra))

        def _authorized(self) -> bool:
            if not cfg.token:
                return True
            header = self.headers.get("Authorization") or ""
            token = header[7:].strip() if header.lower().startswith("bearer ") else \
                (self.headers.get("X-Swordholder-Token") or "").strip()
            return token == cfg.token

        def _read_json(self) -> Any:
            if getattr(self, "_body_error", None):
                raise ValueError(self._body_error)
            raw = getattr(self, "_raw_body", None)
            if raw is None:
                raw = self._drain_body()
            if not raw:
                raise ValueError("E_EMPTY_BODY")
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("E_BAD_JSON")

        def _drain_body(self) -> bytes:
            """先把请求体读完再处理，否则提前返回 401 会让客户端收到 RST。"""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                self._raw_body = b""
                return self._raw_body
            if length > MAX_BODY:
                self._raw_body = b""
                self.close_connection = True
                raise ValueError("E_BODY_TOO_LARGE")
            self._raw_body = self.rfile.read(length)
            return self._raw_body


        # -- 路由 ---------------------------------------------------------
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            if path == "/healthz":
                return self._send(200, {
                    "ok": True, "version": __version__, "sealing": bool(cfg.key_path),
                    "indexed": cfg.store is not None, "engine": "rules-v1",
                    "llm": cfg.use_llm and rules.llm_available(),
                })
            if path == "/v1/schema":
                with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                    return self._send(200, json.load(f))
            if not self._authorized():
                return self._fail(401, "E_UNAUTHORIZED", "缺少或错误的 Bearer token")

            if path == "/v1/seals":
                if not cfg.store:
                    return self._fail(400, "E_NO_INDEX", "服务未启用 --db，无法按索引检索")
                qs = parse_qs(parsed.query)
                rows = cfg.store.query(
                    verdict=(qs.get("verdict") or [None])[0],
                    subject=(qs.get("subject") or [None])[0],
                    alert_id=(qs.get("alert_id") or [None])[0],
                    since=(qs.get("since") or [None])[0],
                    limit=int((qs.get("limit") or ["20"])[0]),
                )
                return self._send(200, {"ok": True, "count": len(rows), "items": rows,
                                        "stats": cfg.store.stats()})

            m = re.fullmatch(r"/v1/seals/([0-9a-fA-F-]{8,64})", path)
            if m:
                if not cfg.store:
                    return self._fail(400, "E_NO_INDEX", "服务未启用 --db")
                row = cfg.store.get(m.group(1))
                if not row:
                    return self._fail(404, "E_NOT_FOUND", "索引中无此 seal_id")
                return self._send(200, {"ok": True, "item": row})

            return self._fail(404, "E_NOT_FOUND", f"未知路径：{path}")

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            try:
                self._drain_body()
            except ValueError as e:
                self._body_error = str(e)
                self.close_connection = True
            if not self._authorized():
                return self._fail(401, "E_UNAUTHORIZED", "缺少或错误的 Bearer token")

            if path == "/v1/triage":
                return self._triage(parsed)
            if path == "/v1/verify":
                return self._verify()
            return self._fail(404, "E_NOT_FOUND", f"未知路径：{path}")

        # -- 业务 ---------------------------------------------------------
        def _triage(self, parsed) -> None:
            qs = parse_qs(parsed.query)
            fmt = (qs.get("format") or ["auto"])[0]
            want_seal = (qs.get("seal") or [None])[0]
            try:
                body = self._read_json()
            except ValueError as e:
                code = str(e)
                msg = {"E_BODY_TOO_LARGE": f"请求体超过 {MAX_BODY} 字节",
                       "E_EMPTY_BODY": "请求体为空",
                       "E_BAD_JSON": "请求体不是合法 JSON"}.get(code, "请求体非法")
                return self._fail(413 if code == "E_BODY_TOO_LARGE" else 400, code, msg)

            alert_raw = body.get("alert") if isinstance(body, dict) and "alert" in body else body
            if isinstance(body, dict) and body.get("format") and fmt == "auto":
                fmt = str(body["format"])

            try:
                alert = normalize(alert_raw, fmt=fmt)
            except AlertError as e:
                return self._fail(400, "E_ALERT_INVALID", "告警无法归一",
                                  errors=e.errors, sources=["generic", "splunk", "sentinel", "wazuh"])

            record = core.triage(alert, use_llm=cfg.use_llm)

            sealing = cfg.seal and bool(cfg.key_path) and want_seal not in ("0", "false")
            out: dict[str, Any] = {"ok": True, "alert": {k: alert[k] for k in
                                  ("alert_id", "title", "severity", "asset", "source")},
                                  "triage": record}
            if not sealing:
                if cfg.seal and not cfg.key_path:
                    out["seal_note"] = "服务未配置私钥，仅返回结论，未签发凭证"
                return self._send(200, out)

            digest = core.payload_sha256(record)
            # 幂等：同一结论内容只签发一份凭证，重复请求复用旧凭证（不给攻击者刷凭证的机会）
            reused = cfg.store.find_by_payload(digest) if cfg.store else None
            if reused and os.path.exists(reused["path"]):
                verification = core.verify(reused["path"], keys_path=cfg.keys_file)
                out["seal"] = {"seal_path": reused["path"], "seal_id": reused["seal_id"],
                               "payload_sha256": digest, "reused": True}
                out["verification"] = {"verdict": verification.get("verdict"),
                                       "reason": verification.get("reason"),
                                       "trust": verification.get("trust"),
                                       "signature_alg": "ed25519"}
                return self._send(200, out)

            path = os.path.join(cfg.out_dir,
                                f"{_safe_name(record.get('alert_id'))}-{digest[:12]}.seal.json")
            try:
                sealed = core.seal(record, cfg.key_path, cfg.issuer, out_path=path)
            except core.SealError as e:
                return self._fail(500, "E_SEAL_FAILED", str(e))

            verification = core.verify(sealed["seal_path"], keys_path=cfg.keys_file)
            if cfg.store:
                cfg.store.add_seal(sealed["seal_path"])
            out["seal"] = {"seal_path": sealed["seal_path"], "seal_id": sealed.get("seal_id"),
                           "payload_sha256": sealed.get("payload_sha256")}
            out["verification"] = {"verdict": verification.get("verdict"),
                                   "reason": verification.get("reason"),
                                   "trust": verification.get("trust"),
                                   "signature_alg": "ed25519"}
            return self._send(200, out)

        def _verify(self) -> None:
            try:
                body = self._read_json()
            except ValueError as e:
                return self._fail(400, str(e), "请求体非法")
            if not isinstance(body, dict):
                return self._fail(400, "E_BAD_REQUEST", "需要 JSON 对象")
            try:
                if isinstance(body.get("seal"), dict):
                    import tempfile
                    fd, tmp = tempfile.mkstemp(suffix=".seal.json")
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(body["seal"], f, ensure_ascii=False)
                    try:
                        res = core.verify(tmp, keys_path=cfg.keys_file)
                    finally:
                        os.unlink(tmp)
                elif body.get("seal_path"):
                    res = core.verify(str(body["seal_path"]), keys_path=cfg.keys_file)
                else:
                    return self._fail(400, "E_BAD_REQUEST", "需要 seal 对象或 seal_path")
            except Exception as e:  # 验签失败必须给结论，不能 500 掉
                return self._fail(400, "E_VERIFY_FAILED", f"{type(e).__name__}: {e}")
            return self._send(200, {"ok": res.get("verdict") != "INVALID", "verification": res})

    return Handler


def build_server(cfg: ServerConfig) -> ThreadingHTTPServer:
    if cfg.host not in ("127.0.0.1", "localhost", "::1") and not cfg.token:
        raise SystemExit("绑到非回环地址时必须提供 --token（否则任何人都能签发凭证）")
    if cfg.key_path:
        os.makedirs(cfg.out_dir, exist_ok=True)
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(cfg))
    httpd.daemon_threads = True
    return httpd


def serve(cfg: ServerConfig) -> None:
    httpd = build_server(cfg)
    host, port = httpd.server_address[:2]
    print(json.dumps({"listening": f"http://{host}:{port}", "sealing": bool(cfg.key_path),
                      "indexed": cfg.db or None, "auth": "bearer" if cfg.token else "none"},
                     ensure_ascii=False), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        cfg.close()
