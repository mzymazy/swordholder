import json
import os

import pytest

from swordholder import core
from swordholder.alert import AlertError, detect_format, normalize

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "..", "swordholder", "samples")


def _load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("name,fmt,alert_id,severity,asset", [
    ("splunk_01_egress.json", "splunk", "1728.4417", "high", "build-runner-07"),
    ("sentinel_01_token.json", "sentinel", "40211", "high", "ci-runner-12"),
    ("wazuh_01_supplychain.json", "wazuh", "92052", "critical", "dev-workstation-03"),
    ("alert_01_egress.json", "generic", "ALRT-2026-1102-0007", "high", "build-runner-07"),
])
def test_adapters_normalize(name, fmt, alert_id, severity, asset):
    raw = _load(name)
    assert detect_format(raw) == fmt
    a = normalize(raw)
    assert a["alert_id"] == alert_id
    assert a["severity"] == severity
    assert a["asset"] == asset
    assert a["source"]["format"] == fmt
    assert len(a["source"]["raw_sha256"]) == 64
    assert a["raw"] == raw  # 原始载荷原样保留


def test_unknown_format_not_guessed():
    with pytest.raises(AlertError) as ei:
        normalize({"foo": "bar", "baz": 1})
    assert ei.value.errors[0]["code"] == "E_UNKNOWN_FORMAT"


def test_missing_alert_id_is_explicit_failure():
    with pytest.raises(AlertError) as ei:
        normalize({"title": "some rule", "signal": "outbound"}, fmt="generic")
    codes = [e["code"] for e in ei.value.errors]
    assert "E_MISSING_FIELD" in codes
    assert ei.value.to_dict()["code"] == "E_ALERT_INVALID"


def test_non_object_rejected():
    with pytest.raises(AlertError) as ei:
        normalize(["not", "an", "object"])
    assert ei.value.errors[0]["code"] == "E_ALERT_NOT_OBJECT"


def test_severity_scales_mapped():
    assert normalize({"alert_id": "1", "title": "t", "severity": "P1"}, "generic")["severity"] == "critical"
    assert normalize({"alert_id": "1", "title": "t", "severity": "Informational"}, "generic")["severity"] == "low"
    wazuh = normalize({"rule": {"id": "1", "description": "d", "level": 4}, "id": "9"}, "wazuh")
    assert wazuh["severity"] == "medium"


def test_canonical_hash_is_stable_and_key_order_free():
    a = normalize({"alert_id": "x", "title": "t", "severity": "low", "asset": "h"}, "generic")
    b = normalize({"asset": "h", "severity": "low", "title": "t", "alert_id": "x"}, "generic")
    assert a["source"]["raw_sha256"] == b["source"]["raw_sha256"]


@pytest.mark.parametrize("name,fmt,verdict", [
    ("splunk_01_egress.json", "splunk", "suspicious"),
    ("sentinel_01_token.json", "sentinel", "true_positive"),
    ("wazuh_01_supplychain.json", "wazuh", "true_positive"),
])
def test_triage_event_end_to_end(name, fmt, verdict):
    res = core.triage_event(_load(name), fmt=fmt)
    assert res["verdict"] == verdict
    assert res["engine"].startswith("rules-v1")
    assert res["input"]["source"]["format"] == fmt
    assert res["schema_version"] == "1.0"
    # 原始日志不进凭证，只留 hash
    assert "raw" not in res["input"]

# ---- CLI 输入契约（stdin / 错误码）----------------------------------------
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _cli(args, stdin_text=None):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-m", "swordholder"] + args,
                          input=stdin_text, capture_output=True, text=True,
                          encoding="utf-8", cwd=ROOT, env=env)
    return proc


def test_cli_stdin_bad_json_returns_code():
    proc = _cli(["triage", "-"], "{oops")
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["code"] == "E_BAD_JSON"


def test_cli_stdin_unknown_format_is_rejected():
    proc = _cli(["triage", "-"], '{"foo": 1}')
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["code"] == "E_ALERT_INVALID"


def test_cli_missing_file_returns_structured_error():
    proc = _cli(["triage", "definitely_missing.json"])
    assert proc.returncode == 2
    body = json.loads(proc.stdout)
    assert body["code"] == "E_NOT_FOUND"
    assert "definitely_missing.json" in body["message"]


def test_cli_stdin_splunk_is_normalized():
    payload = json.dumps({"search_name": "egress", "sid": "9001", "urgency": "critical",
                          "dest": "h1", "signature": "outbound TLS",
                          "_time": "2026-11-06T00:00:00Z"})
    proc = _cli(["triage", "-", "--format", "splunk"], payload)
    assert proc.returncode == 0, proc.stderr
    body = json.loads(proc.stdout)
    assert body["alert_id"] == "9001"
    assert body["input"]["source"]["format"] == "splunk"
