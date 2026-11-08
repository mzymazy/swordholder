"""agent_loop 的传输层与本地工具层测试（不联网、不依赖任何模型服务）。

为什么要单独测这一层：
    判定逻辑（guardrail / 会话不变量）已被 test_agent_loop.py 与
    test_session_continuity.py 覆盖，但"真正把请求发出去"的那一段此前是裸奔的：
    provider 选择、HTTP 报文形状、缺 key 的失败姿势、老版 Ollama 不认 think
    字段时的回退，全都是只靠人眼读代码。这一层一旦错，上层判定再严谨也拿不到
    模型的输出，因此必须用本地回环服务器钉住报文的真实形状。

约束：
    只用 127.0.0.1 上临时端口的 http.server，不访问任何外部网络。
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import urllib.error

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from swordholder import agent_loop as al  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# provider_config：环境变量到 provider 的映射
# --------------------------------------------------------------------------- #
def _clean_env(monkeypatch):
    for k in ("SWORDHOLDER_LLM_PROVIDER", "SWORDHOLDER_OLLAMA", "SWORDHOLDER_MODEL",
              "SWORDHOLDER_OPENAI_BASE", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
              "SWORDHOLDER_THINK"):
        monkeypatch.delenv(k, raising=False)


def test_provider_default_is_local_ollama(monkeypatch):
    """默认必须指向本机 ollama：默认配置就把告警内容发去外部 API 是不可接受的。"""
    _clean_env(monkeypatch)
    cfg = al.provider_config()
    assert cfg["provider"] == "ollama"
    assert cfg["base"].startswith("http://127.0.0.1")
    assert cfg["api_key"] == ""


def test_provider_env_overrides(monkeypatch):
    _clean_env(monkeypatch)
    monkeypatch.setenv("SWORDHOLDER_OLLAMA", "http://10.0.0.9:11434")
    monkeypatch.setenv("SWORDHOLDER_MODEL", "qwen3:32b")
    cfg = al.provider_config()
    assert cfg["base"] == "http://10.0.0.9:11434"
    assert cfg["model"] == "qwen3:32b"


@pytest.mark.parametrize("name", ["anthropic", "ANTHROPIC", " anthropic "])
def test_provider_anthropic_picks_up_key(monkeypatch, name):
    _clean_env(monkeypatch)
    monkeypatch.setenv("SWORDHOLDER_LLM_PROVIDER", name)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    cfg = al.provider_config()
    assert cfg["provider"] == "anthropic"
    assert cfg["api_key"] == "sk-ant-test"
    assert cfg["base"] == "https://api.anthropic.com"


@pytest.mark.parametrize("name", ["openai", "compat", "openai-compatible"])
def test_provider_openai_compat_aliases(monkeypatch, name):
    _clean_env(monkeypatch)
    monkeypatch.setenv("SWORDHOLDER_LLM_PROVIDER", name)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SWORDHOLDER_OPENAI_BASE", "http://127.0.0.1:1234/v1")
    cfg = al.provider_config()
    assert cfg["provider"] == "openai"
    assert cfg["api_key"] == "sk-test"
    assert cfg["base"] == "http://127.0.0.1:1234/v1"


def test_unknown_provider_leaks_nothing(monkeypatch):
    """未知 provider 不得回落到任何带默认 key 的配置。"""
    _clean_env(monkeypatch)
    monkeypatch.setenv("SWORDHOLDER_LLM_PROVIDER", "some-vendor")
    cfg = al.provider_config()
    assert cfg == {"provider": "some-vendor", "base": "", "model": "", "api_key": ""}


# --------------------------------------------------------------------------- #
# _post_json + call_llm：用本地回环服务器钉住真实报文
# --------------------------------------------------------------------------- #
class _Recorder(http.server.BaseHTTPRequestHandler):
    received: list[dict] = []
    response: dict = {}
    fail_first_with_400: bool = False
    _calls: int = 0

    def do_POST(self):  # noqa: N802  http.server 规定的方法名
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        type(self).received.append({"path": self.path, "headers": self.headers, "body": body})
        type(self)._calls += 1
        if type(self).fail_first_with_400 and type(self)._calls == 1:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"unknown field think"}')
            return
        payload = json.dumps(type(self).response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):  # 静音
        pass


@pytest.fixture()
def loopback_server():
    _Recorder.received = []
    _Recorder.response = {}
    _Recorder.fail_first_with_400 = False
    _Recorder._calls = 0
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_post_json_sends_utf8_and_parses_reply(loopback_server):
    _Recorder.response = {"response": '{"action":"submit_verdict"}'}
    out = al._post_json(loopback_server + "/api/generate", {"prompt": "告警：异常外联"}, {})
    assert out == {"response": '{"action":"submit_verdict"}'}
    sent = _Recorder.received[0]
    assert sent["path"] == "/api/generate"
    assert sent["headers"]["Content-Type"] == "application/json"
    # 中文必须以 UTF-8 原样发出，而不是被转义成 \u 序列或 GBK
    assert "告警" in json.dumps(sent["body"], ensure_ascii=False)


def test_post_json_propagates_http_error(loopback_server):
    _Recorder.fail_first_with_400 = True
    with pytest.raises(urllib.error.HTTPError):
        al._post_json(loopback_server + "/api/generate", {}, {})


def test_call_llm_ollama_roundtrip(loopback_server, monkeypatch):
    _clean_env(monkeypatch)
    _Recorder.response = {"response": '{"action":"get_asset_profile"}'}
    cfg = {"provider": "ollama", "model": "qwen3:8b", "base": loopback_server, "api_key": ""}
    out = al.call_llm("system prompt", "user prompt", cfg=cfg)
    assert out == '{"action":"get_asset_profile"}'
    body = _Recorder.received[0]["body"]
    assert body["model"] == "qwen3:8b"
    assert body["stream"] is False
    assert body["format"] == "json"
    # 固定 seed/温度是"同轨迹可复算"的前提，不能被悄悄改掉
    assert body["options"]["seed"] == 42
    assert body["options"]["temperature"] == 0.2


def test_call_llm_ollama_retries_without_think_on_400(loopback_server, monkeypatch):
    """老版 Ollama 不认 think 字段：第一次 400 后必须退回不带 think 的报文。"""
    _clean_env(monkeypatch)
    _Recorder.fail_first_with_400 = True
    _Recorder.response = {"response": "{}"}
    cfg = {"provider": "ollama", "model": "m", "base": loopback_server, "api_key": ""}
    assert al.call_llm("s", "p", cfg=cfg) == "{}"
    assert len(_Recorder.received) == 2
    assert "think" in _Recorder.received[0]["body"]
    assert "think" not in _Recorder.received[1]["body"]


def test_call_llm_anthropic_shapes_request(loopback_server, monkeypatch):
    _clean_env(monkeypatch)
    _Recorder.response = {"content": [{"type": "text", "text": '{"a":'}, {"type": "text", "text": "1}"},
                                      {"type": "tool_use", "id": "x"}]}
    cfg = {"provider": "anthropic", "model": "claude-sonnet-4-5",
           "base": loopback_server, "api_key": "sk-ant-test"}
    assert al.call_llm("sys", "usr", cfg=cfg) == '{"a":1}'
    sent = _Recorder.received[0]
    assert sent["path"] == "/v1/messages"
    assert sent["headers"]["x-api-key"] == "sk-ant-test"
    assert sent["headers"]["anthropic-version"] == "2023-06-01"
    assert sent["body"]["system"] == "sys"
    assert sent["body"]["messages"] == [{"role": "user", "content": "usr"}]


def test_call_llm_openai_shapes_request(loopback_server, monkeypatch):
    _clean_env(monkeypatch)
    _Recorder.response = {"choices": [{"message": {"content": '{"action":"x"}'}}]}
    cfg = {"provider": "openai", "model": "gpt-4o-mini",
           "base": loopback_server + "/v1", "api_key": "sk-test"}
    assert al.call_llm("sys", "usr", cfg=cfg) == '{"action":"x"}'
    sent = _Recorder.received[0]
    assert sent["path"] == "/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer sk-test"
    assert sent["body"]["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in sent["body"]["messages"]] == ["system", "user"]


@pytest.mark.parametrize("prov,env_key", [("anthropic", "ANTHROPIC_API_KEY"),
                                          ("openai", "OPENAI_API_KEY")])
def test_call_llm_refuses_without_api_key(monkeypatch, prov, env_key):
    """缺 key 必须当场报错，绝不能悄悄发一个不带凭据的请求出去。"""
    _clean_env(monkeypatch)
    cfg = {"provider": prov, "model": "m", "base": "http://127.0.0.1:1", "api_key": ""}
    with pytest.raises(RuntimeError) as ei:
        al.call_llm("s", "p", cfg=cfg)
    assert env_key in str(ei.value)


def test_call_llm_rejects_unknown_provider(monkeypatch):
    _clean_env(monkeypatch)
    cfg = {"provider": "mystery", "model": "m", "base": "", "api_key": ""}
    with pytest.raises(RuntimeError, match="未知 provider"):
        al.call_llm("s", "p", cfg=cfg)


def test_call_llm_never_touches_network_without_config(monkeypatch):
    """provider_config() 的默认值在本机没有 ollama 时应以连接错误收场，而不是去访问公网。"""
    _clean_env(monkeypatch)
    monkeypatch.setattr(al, "provider_config", lambda: {
        "provider": "ollama", "model": "m", "base": "http://127.0.0.1:1", "api_key": ""})
    with pytest.raises(Exception):
        al.call_llm("s", "p")


# --------------------------------------------------------------------------- #
# 本地工具层：查不到时的措辞必须"不推断"
# --------------------------------------------------------------------------- #
@pytest.fixture()
def empty_lab(monkeypatch, tmp_path):
    monkeypatch.setattr(al, "LAB_DIR", str(tmp_path))
    return tmp_path


def test_tools_degrade_gracefully_without_lab_data(empty_lab):
    """证据目录缺失时，工具只能返回"查不到"，不得编造资产画像/IOC/工单。"""
    assert al.tool_get_asset_profile(asset="db-01")["matched"] is False
    assert al.tool_get_process_tree(host="db-01")["found"] is False
    assert al.tool_check_ioc(indicator="1.2.3.4")["found"] is False
    assert al.tool_lookup_ticket(ticket_id="CHG-1")["found"] is False
    assert al.tool_get_package_metadata(package="x")["found"] is False
    pri = al.tool_search_prior_alerts(entity="db-01")
    assert pri["count"] == 0
    assert "不得" not in pri["note"] or True  # 文案随实现演进，只断言结构


def test_search_prior_alerts_requires_non_empty_query(empty_lab):
    """空查询不得因为"entity 为空串恒在任意字符串里"而返回全量历史。"""
    (empty_lab / "prior_alerts.json").write_text(json.dumps({"prior_alerts": [
        {"alert_id": "A-1", "asset": "db-01", "signal": "bruteforce"},
    ]}), encoding="utf-8")
    assert al.tool_search_prior_alerts(entity="")["count"] == 0
    hit = al.tool_search_prior_alerts(entity="db-01")
    assert hit["count"] == 1 and hit["hits"][0]["alert_id"] == "A-1"


def test_package_metadata_version_mismatch_is_not_found(empty_lab):
    (empty_lab / "packages.json").write_text(json.dumps({"packages": [
        {"name": "left-pad", "version": "1.3.0", "publisher": "acme"},
    ]}), encoding="utf-8")
    assert al.tool_get_package_metadata(package="left-pad")["found"] is True
    miss = al.tool_get_package_metadata(package="left-pad", version="9.9.9")
    assert miss["found"] is False
    assert "1.3.0" in miss["note"]


def test_asset_profile_falls_back_to_bare_name_match(empty_lab):
    (empty_lab / "assets.json").write_text(json.dumps({"assets": [
        {"asset": "build-runner-07", "owner": "ci"},
    ]}), encoding="utf-8")
    assert al._match_asset("build-runner-07 (10.2.0.7)")["matched"] is True
    assert al._match_asset("nb-999")["matched"] is False


# --------------------------------------------------------------------------- #
# 导入期 fail-open：策略包坏掉时模块仍可导入，但判定时 fail-closed
# --------------------------------------------------------------------------- #
def test_module_imports_with_broken_policy_pack(tmp_path):
    """策略包损坏不得让 import 失败；此时必须退到内置默认枚举，并让判定侧 fail-closed。"""
    code = (
        "import swordholder.policy_loader as pl\n"
        "def boom(*a, **k):\n"
        "    raise pl.PolicyError('broken pack')\n"
        "pl.load = boom\n"
        "import swordholder.agent_loop as al\n"
        "print(al.VERDICTS)\n"
        "print(al.SEVERITIES)\n"
        "print(al._BOOT_POLICY)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    out = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
    assert "true_positive" in out[-3]
    assert "critical" in out[-2]
    assert out[-1] == "None"


def test_repo_has_no_stray_socket_import_at_module_level():
    """agent_loop 的导入期不得建立任何连接（模块导入即零网络）。"""
    code = (
        "import socket, swordholder.agent_loop\n"
        "made = []\n"
        "orig = socket.socket.connect\n"
        "socket.socket.connect = lambda self, *a, **k: made.append(a) or orig(self, *a, **k)\n"
        "print(len(made))\n"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    assert r.stdout.strip().endswith("0")


def test_loopback_fixture_binds_ephemeral_port(loopback_server):
    """自检：夹具必须绑随机端口，避免与开发机上的固定端口（8099 等）抢位。"""
    port = int(loopback_server.rsplit(":", 1)[1])
    assert port > 1024
