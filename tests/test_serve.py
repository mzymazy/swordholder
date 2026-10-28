import json
import threading
import urllib.error
import urllib.request

import pytest

from swordholder import core
from swordholder.serve import ServerConfig, build_server
from swordholder.store import Store

ALERT = {
    "search_name": "CI runner outbound to unregistered ASN",
    "sid": "1728.9999",
    "urgency": "high",
    "dest": "build-runner-09",
    "signature": "outbound TLS to unknown ASN 215199",
    "description": "6 long-lived TLS sessions to 198.51.100.77:443",
    "_time": "2026-11-05T03:14:00Z",
}


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


@pytest.fixture()
def live(tmp_path, keys):
    cfg = ServerConfig(port=0, out_dir=str(tmp_path / "seals"),
                       key_path=keys["private_key_path"], db=str(tmp_path / "index.db"),
                       token="t0ken")
    httpd = build_server(cfg)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield {"base": base, "cfg": cfg}
    httpd.shutdown()
    httpd.server_close()
    cfg.close()


def _post(url, payload, token="t0ken"):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _get(url, token="t0ken"):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_healthz_needs_no_token(live):
    code, body = _get(live["base"] + "/healthz", token=None)
    assert code == 200
    assert body["ok"] and body["sealing"] and body["indexed"]


def test_schema_endpoint_serves_contract(live):
    code, body = _get(live["base"] + "/v1/schema", token=None)
    assert code == 200
    assert body["required"][:2] == ["schema_version", "alert_id"]


def test_unauthorized_without_token(live):
    code, body = _post(live["base"] + "/v1/triage", ALERT, token=None)
    assert code == 401 and body["code"] == "E_UNAUTHORIZED"


def test_triage_seals_and_indexes(live):
    code, body = _post(live["base"] + "/v1/triage?format=splunk", ALERT)
    assert code == 200, body
    assert body["triage"]["verdict"] == "suspicious"
    assert body["alert"]["asset"] == "build-runner-09"
    assert body["verification"]["verdict"] == "VALID_UNTRUSTED_KEY"
    assert body["seal"]["payload_sha256"]

    # 幂等：同一告警重复提交不重复签发
    code, again = _post(live["base"] + "/v1/triage?format=splunk", ALERT)
    assert code == 200
    assert again["seal"]["reused"] is True
    assert again["seal"]["seal_id"] == body["seal"]["seal_id"]

    code, listing = _get(live["base"] + "/v1/seals?limit=5")
    assert code == 200 and listing["count"] == 1
    seal_id = body["seal"]["seal_id"]

    code, one = _get(live["base"] + f"/v1/seals/{seal_id}")
    assert code == 200 and one["item"]["triage_verdict"] == "suspicious"



def test_bad_alert_returns_structured_errors(live):
    code, body = _post(live["base"] + "/v1/triage?format=generic", {"title": "t"})
    assert code == 400
    assert body["code"] == "E_ALERT_INVALID"
    assert body["errors"][0]["code"] == "E_MISSING_FIELD"


def test_bad_json_is_400(live):
    req = urllib.request.Request(live["base"] + "/v1/triage", data=b"{not json",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer t0ken"})
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=10)
    assert ei.value.code == 400
    assert json.loads(ei.value.read().decode("utf-8"))["code"] == "E_BAD_JSON"


def test_verify_endpoint_detects_tamper(live):
    code, body = _post(live["base"] + "/v1/triage?format=splunk", ALERT)
    seal_path = body["seal"]["seal_path"]
    with open(seal_path, encoding="utf-8") as f:
        seal = json.load(f)

    code, ok = _post(live["base"] + "/v1/verify", {"seal": seal})
    assert code == 200 and ok["ok"] is True

    seal["payload"]["verdict"] = "false_positive"
    code, bad = _post(live["base"] + "/v1/verify", {"seal": seal})
    assert code == 200 and bad["ok"] is False
    assert bad["verification"]["reason"] == "E_PAYLOAD_TAMPERED"


def test_bind_non_loopback_requires_token(tmp_path, keys):
    cfg = ServerConfig(host="0.0.0.0", port=0, key_path=keys["private_key_path"],
                       out_dir=str(tmp_path / "s"), token=None)
    with pytest.raises(SystemExit):
        build_server(cfg)


def test_store_query_filters(tmp_path, keys):
    store = Store(str(tmp_path / "i.db"))
    sealed = core.seal({"alert_id": "A-9", "verdict": "true_positive", "severity": "high"},
                       keys["private_key_path"], "issuer-x",
                       subject="A-9", out_path=str(tmp_path / "a.seal.json"))
    store.add_seal(sealed["seal_path"])
    assert store.query(verdict="true_positive")[0]["alert_id"] == "A-9"
    assert store.query(verdict="false_positive") == []
    assert store.stats()["total"] == 1
    assert store.get(sealed["seal_id"])["issuer"] == "issuer-x"
    store.close()
