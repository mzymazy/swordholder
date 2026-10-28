import json
import os
import subprocess
import sys

import pytest

from swordholder import SealError, core
from swordholder.rules import triage as rule_layer_triage

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "..", "agent", "samples")


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _seal(tmp_path, keys, record=None):
    record = record or {"alert_id": "A-1", "verdict": "true_positive", "confidence": 0.9}
    out = str(tmp_path / "rec.seal.json")
    return core.seal(record, keys["private_key_path"], "test-issuer", out_path=out)


def test_seal_verify_roundtrip(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    assert os.path.exists(sealed["seal_path"])
    res = core.verify(sealed["seal_path"], keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "VALID_UNTRUSTED_KEY"
    assert res["reason"] == "E_NO_TRUST_ANCHOR"


def test_trusted_key_promotes_to_valid(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    anchor = tmp_path / "trusted_keys.json"
    anchor.write_text(json.dumps({"keys": [{"public_key": keys["public_key_hex"]}]}), encoding="utf-8")
    res = core.verify(sealed["seal_path"], keys_path=str(anchor))
    assert res["verdict"] == "VALID"
    assert res["trust"] == "trusted"


def test_tampered_payload_detected(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    path = tmp_path / "bad.seal.json"
    data = json.loads(open(sealed["seal_path"], encoding="utf-8").read())
    data["payload"]["verdict"] = "false_positive"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    res = core.verify(str(path), keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_PAYLOAD_TAMPERED"


def test_tampered_header_breaks_signature(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    path = tmp_path / "bad2.seal.json"
    data = json.loads(open(sealed["seal_path"], encoding="utf-8").read())
    data["seal_header"]["issuer"] = "someone-else"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    res = core.verify(str(path), keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_BAD_SIGNATURE"


def test_verify_or_raise_rejects_invalid(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    data = json.loads(open(sealed["seal_path"], encoding="utf-8").read())
    data["payload"]["confidence"] = 0.1
    path = tmp_path / "bad3.seal.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(SealError):
        core.verify_or_raise(str(path), keys_path=str(tmp_path / "missing.json"))


def test_verify_or_raise_requires_trusted(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    with pytest.raises(SealError):
        core.verify_or_raise(sealed["seal_path"], keys_path=str(tmp_path / "missing.json"),
                             require_trusted=True)


@pytest.mark.parametrize("name,expected", [
    ("alert_01_egress.json", "suspicious"),
    ("alert_02_token.json", "true_positive"),
    ("alert_03_supplychain.json", "true_positive"),
])
def test_triage_baseline(name, expected):
    res = rule_layer_triage(json.loads(open(os.path.join(SAMPLES, name), encoding="utf-8").read()))
    assert res["verdict"] == expected
    assert res["engine"].startswith("rules-v1")
    assert 0 < res["confidence"] <= 1
    assert res["actions"]


def test_triage_never_claims_certainty_on_unknown():
    res = rule_layer_triage({"alert_id": "X", "signal": "weird thing", "severity": "low"})
    assert res["verdict"] == "suspicious"
    assert res["confidence"] == 0.5


def test_cli_demo_end_to_end(tmp_path):
    demo = tmp_path / "demo"
    proc = subprocess.run(
        [sys.executable, "-m", "swordholder", "demo", "--out", str(demo),
         "--keys", str(tmp_path / "keys")],
        capture_output=True, text=True, encoding="utf-8",
        cwd=os.path.join(HERE, ".."))
    assert proc.returncode == 0, proc.stderr
    assert (demo / "tampered.seal.json").exists()
    payload = json.loads(proc.stdout)
    assert payload["tamper"]["reason"] == "E_PAYLOAD_TAMPERED"
