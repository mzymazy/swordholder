"""规则层与可选 LLM 增强的覆盖测试（S6）。

LLM 路径不 mock：本机起一个真的 HTTP 桩，走 urllib 的真实请求/超时/异常分支，
这样"模型服务不可用时必须降级而不是丢结论"这条不变量是被实测过的。
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from swordholder import rules


# ------------------------------------------------------------------ 本地 HTTP 桩

class _Handler(BaseHTTPRequestHandler):
    """按路径分流：/api/tags 健康探测，/api/generate 返回可配置载荷。"""

    mode = "ok"
    captured = []

    def log_message(self, *a):  # 静音
        pass

    def do_GET(self):
        if self.path != "/api/tags":
            self.send_error(404)
            return
        if _Handler.mode == "down":
            self.send_error(500)
            return
        body = json.dumps({"models": [{"name": "qwen3:8b"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        _Handler.captured.append(raw.decode("utf-8"))
        if _Handler.mode == "down":
            self.send_error(500)
            return
        if _Handler.mode == "garbage":
            inner = "not-json-at-all"
        elif _Handler.mode == "empty":
            inner = "{}"
        else:
            inner = json.dumps({
                "hypothesis": "模型补充的成因假设",
                "actions": ["模型建议动作 A", "模型建议动作 B"],
                "notes": "note",
            }, ensure_ascii=False)
        body = json.dumps({"response": inner}, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def stub_llm():
    _Handler.mode = "ok"
    _Handler.captured = []
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", _Handler
    srv.shutdown()
    srv.server_close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------ 规则层五条定性分支

ALERT_TEMPLATES = [
    ("supply-chain", {"signal": "postinstall script invoked", "title": "npm package",
                      "description": "typosquat of a popular package"},
     "true_positive"),
    ("egress-high", {"signal": "unexpected outbound TLS to unknown ASN", "severity": "critical"},
     "suspicious"),
    ("egress-low", {"signal": "dns tunnel beacon", "severity": "low"}, "suspicious"),
    ("ci-token", {"signal": "ci token used from foreign ASN", "title": "build-runner"},
     "true_positive"),
    ("pentest", {"signal": "port scan detected", "description": "authorized pentest window"},
     "false_positive"),
    ("fallback", {"signal": "weird unknown thing", "severity": "medium"}, "suspicious"),
]


@pytest.mark.parametrize("name,alert,expected", ALERT_TEMPLATES)
def test_rule_branches(name, alert, expected):
    alert = dict(alert, alert_id="ALRT-S6-R", asset="host")
    out = rules.rule_triage(alert)
    assert out["verdict"] == expected
    assert out["engine"] == "rules-v1"
    assert 0.0 < out["confidence"] <= 1.0
    assert out["actions"]


def test_rule_confidence_varies_with_severity():
    base = {"alert_id": "A", "asset": "h", "signal": "outbound TLS"}
    high = rules.rule_triage(dict(base, severity="high"))["confidence"]
    low = rules.rule_triage(dict(base, severity="low"))["confidence"]
    assert high > low


def test_rule_ignores_description_for_egress():
    """定性只看信号+标题：描述里出现 egress 关键词不得把兜底分支抢成外联分支。"""
    out = rules.rule_triage({"alert_id": "A", "asset": "h",
                             "signal": "weird", "description": "outbound c2 beacon"})
    assert out["verdict"] == "suspicious"
    assert "外联" not in out["hypothesis"]


# ------------------------------------------------------------------ LLM 可用性探测

def test_llm_available_true(stub_llm):
    base, _ = stub_llm
    assert rules.llm_available(base) is True


def test_llm_available_false_when_error(stub_llm):
    base, handler = stub_llm
    handler.mode = "down"
    assert rules.llm_available(base) is False


def test_llm_available_false_when_port_closed():
    assert rules.llm_available(f"http://127.0.0.1:{_free_port()}") is False


# ------------------------------------------------------------------ LLM 增强

def _base_triage():
    return rules.rule_triage({"alert_id": "ALRT-S6-L", "asset": "host",
                              "signal": "unexpected outbound TLS", "severity": "high"})


def test_llm_enrich_merges_without_touching_verdict(stub_llm):
    base, handler = stub_llm
    before = _base_triage()
    out = rules.llm_enrich({"alert_id": "A"}, before, model="qwen3:8b", base=base)
    assert out["verdict"] == before["verdict"]           # 硬约束：模型不得改判
    assert out["severity"] == before["severity"]
    assert out["hypothesis_llm"] == "模型补充的成因假设"
    assert out["actions_llm"] == ["模型建议动作 A", "模型建议动作 B"]
    assert out["engine"] == "rules-v1+qwen3:8b"
    # 请求体必须是 format=json 且带硬约束提示
    payload = json.loads(handler.captured[0])
    assert payload["format"] == "json" and "不得改变 verdict" in payload["prompt"]


def test_llm_enrich_degrades_when_server_errors(stub_llm):
    base, handler = stub_llm
    handler.mode = "down"
    out = rules.llm_enrich({"alert_id": "A"}, _base_triage(), base=base)
    assert out["engine"] == "rules-v1 (llm-unavailable)"
    assert out["llm_note"] == "HTTPError"


def test_llm_enrich_degrades_when_body_unparsable(stub_llm):
    base, handler = stub_llm
    handler.mode = "garbage"
    out = rules.llm_enrich({"alert_id": "A"}, _base_triage(), base=base)
    assert out["engine"] == "rules-v1 (llm-unavailable)"
    assert "llm_note" in out


def test_llm_enrich_keeps_base_when_model_returns_empty(stub_llm):
    base, handler = stub_llm
    handler.mode = "empty"
    out = rules.llm_enrich({"alert_id": "A"}, _base_triage(), base=base)
    assert "hypothesis_llm" not in out and "actions_llm" not in out
    assert out["engine"] == "rules-v1+qwen3:8b"


# ------------------------------------------------------------------ triage 分流

def test_triage_without_llm_marks_engine():
    out = rules.triage({"alert_id": "A", "asset": "h", "signal": "outbound TLS"})
    assert out["engine"] == "rules-v1"


def test_triage_llm_not_running(monkeypatch):
    monkeypatch.setattr(rules, "llm_available", lambda base=rules.DEFAULT_BASE: False)
    out = rules.triage({"alert_id": "A", "asset": "h", "signal": "outbound TLS"}, use_llm=True)
    assert out["engine"] == "rules-v1 (llm-not-running)"


def test_triage_llm_enriches(monkeypatch):
    def fake_enrich(alert, base_triage, model=rules.DEFAULT_MODEL, **kw):
        return dict(base_triage, engine="rules-v1+" + model, hypothesis_llm="x")

    monkeypatch.setattr(rules, "llm_available", lambda base=rules.DEFAULT_BASE: True)
    monkeypatch.setattr(rules, "llm_enrich", fake_enrich)
    out = rules.triage({"alert_id": "A", "asset": "h", "signal": "outbound TLS"},
                       use_llm=True, model="m1")
    assert out["engine"] == "rules-v1+m1" and out["hypothesis_llm"] == "x"


# ------------------------------------------------------------------ 其他工具函数

def test_load_alert_and_missing_file(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"alert_id": "A"}), encoding="utf-8")
    assert rules.load_alert(str(path))["alert_id"] == "A"
    with pytest.raises(FileNotFoundError):
        rules.load_alert(str(tmp_path / "missing.json"))


def test_sample_alerts_excludes_sealed_outputs():
    samples = rules.sample_alerts()
    assert samples, "仓库应带内置样例告警"
    assert all(s.endswith(".json") for s in samples)
    assert not any(s.endswith((".seal.json", ".triage.json")) for s in samples)


def test_sample_alerts_empty_when_dir_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(rules, "SAMPLE_DIR", str(tmp_path / "nope"))
    assert rules.sample_alerts() == []
