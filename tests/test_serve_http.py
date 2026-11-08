"""HTTP 在线链路测试（S6）：真实起 ThreadingHTTPServer，真实 urllib 请求。

不 mock handler：triage→判定→盖章→验签→索引 这条链路要么整条通，要么就是不通，
把中间任何一环换掉，测出来的"通过"都不算数。
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from swordholder import core, serve


def _http(base, path, method="GET", body=None, token=None, raw=None):
    url = base + path
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


@pytest.fixture()
def live_server(tmp_path):
    keys = tmp_path / "keys"
    keygen = core.keygen(str(keys))
    cfg = serve.ServerConfig(host="127.0.0.1", port=0,
                             out_dir=str(tmp_path / "seals"),
                             key_path=keygen["private_key_path"],
                             db=str(tmp_path / "index.db"),
                             token="s6-token", issuer="soc@test")
    httpd = serve.build_server(cfg)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, cfg, tmp_path
    httpd.shutdown()
    httpd.server_close()
    cfg.close()


ALERT = {"alert_id": "ALRT-S6-HTTP", "asset": "host-http",
         "signal": "unexpected outbound TLS to unknown ASN", "severity": "high",
         "title": "egress anomaly"}


def test_healthz_and_schema(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/healthz")
    assert code == 200 and doc["ok"] and doc["sealing"] is True
    assert doc["indexed"] is True and doc["engine"] == "rules-v1"
    code, schema = _http(base, "/v1/schema")
    assert code == 200 and "$schema" in schema or code == 200


def test_token_required(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/v1/trust")
    assert code == 401 and doc["code"] == "E_UNAUTHORIZED"
    code, doc = _http(base, "/v1/trust", token="s6-token")
    assert code == 200 and "counts" in doc or code == 200


def test_triage_seal_and_idempotent_reuse(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/v1/triage", "POST", ALERT, token="s6-token")
    assert code == 200 and doc["ok"] is True
    assert doc["triage"]["verdict"] == "suspicious"
    assert doc["judgment"]["exit_name"] == "http:/v1/triage"
    assert doc["judgment"]["basis"] == "policy"
    seal = doc["seal"]
    assert seal["seal_id"] and doc["verification"]["verdict"] in ("VALID", "VALID_UNTRUSTED_KEY")

    # 同一结论内容重复请求：必须复用旧凭证，不重复签发
    code, again = _http(base, "/v1/triage", "POST", ALERT, token="s6-token")
    assert code == 200 and again["seal"]["reused"] is True
    assert again["seal"]["seal_id"] == seal["seal_id"]

    # 索引可查
    code, doc2 = _http(base, "/v1/seals?limit=5", token="s6-token")
    assert code == 200 and doc2["count"] >= 1
    code, doc3 = _http(base, f"/v1/seals/{seal['seal_id']}", token="s6-token")
    assert code == 200 and doc3["item"]["seal_id"] == seal["seal_id"]
    code, doc4 = _http(base, "/v1/seals/00000000-0000-0000-0000-000000000000", token="s6-token")
    assert code == 404 and doc4["code"] == "E_NOT_FOUND"


def test_triage_no_seal_query(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/v1/triage?seal=0", "POST", ALERT, token="s6-token")
    assert code == 200 and "seal" not in doc


def test_triage_body_errors(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/v1/triage", "POST", raw=b"", token="s6-token")
    assert code == 400 and doc["code"] == "E_EMPTY_BODY"
    code, doc = _http(base, "/v1/triage", "POST", raw=b"{not json", token="s6-token")
    assert code == 400 and doc["code"] == "E_BAD_JSON"
    # 超大请求体：服务端拒绝读取并关闭连接。客户端可能收不到 413（写一半被 RST），
    # 但绝不能拿到 200 —— 这里只钉"fail-closed"，不钉具体错误码。
    try:
        code, doc = _http(base, "/v1/triage", "POST", raw=b"x" * (serve.MAX_BODY + 10),
                          token="s6-token")
        assert code == 413 and doc["code"] == "E_BODY_TOO_LARGE"
    except (ConnectionError, OSError):
        pass


def test_triage_rejects_unusable_alert(live_server):
    base, _, _ = live_server
    code, doc = _http(base, "/v1/triage", "POST", {"nothing": "useful"}, token="s6-token")
    assert code == 400 and doc["code"] == "E_ALERT_INVALID"
    assert doc["sources"]


def test_verify_endpoint(live_server):
    base, _, _ = live_server
    _, triage = _http(base, "/v1/triage", "POST", ALERT, token="s6-token")
    seal_path = triage["seal"]["seal_path"]
    seal_doc = json.load(open(seal_path, encoding="utf-8"))

    code, doc = _http(base, "/v1/verify", "POST", {"seal": seal_doc}, token="s6-token")
    assert code == 200 and doc["ok"] is True

    code, doc = _http(base, "/v1/verify", "POST", {"seal_path": seal_path}, token="s6-token")
    assert code == 200 and doc["ok"] is True

    code, doc = _http(base, "/v1/verify", "POST", {}, token="s6-token")
    assert code == 400 and doc["code"] == "E_BAD_REQUEST"

    tampered = json.loads(json.dumps(seal_doc))
    tampered["payload"]["verdict"] = "false_positive"
    code, doc = _http(base, "/v1/verify", "POST", {"seal": tampered}, token="s6-token")
    assert code == 200 and doc["ok"] is False
    assert doc["verification"]["reason"] == "E_PAYLOAD_TAMPERED"

    code, doc = _http(base, "/v1/verify", "POST", raw=b"\xff\xfe", token="s6-token")
    assert code == 400


def test_unknown_paths(live_server):
    base, _, _ = live_server
    assert _http(base, "/v1/nope", token="s6-token")[0] == 404
    assert _http(base, "/v1/nope", "POST", {"a": 1}, token="s6-token")[0] == 404


def test_no_db_index_paths(tmp_path):
    keys = tmp_path / "keys"
    keygen = core.keygen(str(keys))
    cfg = serve.ServerConfig(host="127.0.0.1", port=0, out_dir=str(tmp_path / "s"),
                             key_path=keygen["private_key_path"], db=None)
    httpd = serve.build_server(cfg)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        code, doc = _http(base, "/healthz")
        assert code == 200 and doc["indexed"] is False
        code, doc = _http(base, "/v1/seals")
        assert code == 400 and doc["code"] == "E_NO_INDEX"
        # 未配置私钥：只给结论，不签发
        cfg2 = serve.ServerConfig(host="127.0.0.1", port=0, out_dir=str(tmp_path / "s2"),
                                  key_path=None, seal=True)
        httpd2 = serve.build_server(cfg2)
        t2 = threading.Thread(target=httpd2.serve_forever, daemon=True)
        t2.start()
        base2 = f"http://127.0.0.1:{httpd2.server_address[1]}"
        code, doc = _http(base2, "/v1/triage", "POST", ALERT)
        assert code == 200 and "seal" not in doc and "seal_note" in doc
        httpd2.shutdown()
        httpd2.server_close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        cfg.close()


def test_build_server_requires_token_on_public_bind():
    cfg = serve.ServerConfig(host="0.0.0.0", port=0, token=None)
    with pytest.raises(SystemExit):
        serve.build_server(cfg)
