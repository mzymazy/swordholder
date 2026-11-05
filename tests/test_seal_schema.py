"""凭证契约（seal.schema.json）与验证方挑战（A4）的行为测试。

要钉住的三件事：
1. 结构校验是**版本化 fail-closed**：不认识的 seal_version 一律拒收，不猜着解析。
2. 契约文件与代码里的版本登记表不许漂移（加了版本忘了文件 / 反过来）。
3. 挑战值必须**被签名覆盖**且**缺绑定不等于可放宽**——验证方要求挑战、凭证没绑，
   就判 E_CHALLENGE_MISSING，不降级成 VALID。
"""

import json
import os
import subprocess
import sys

import pytest

from swordholder import SealError, core, seal_schema

HERE = os.path.dirname(os.path.abspath(__file__))
CH = "chal-2026-11-05-abc"          # 合法挑战值（≥8 位、URL 安全字符）
CH_OTHER = "chal-2026-11-05-xyz"


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


def _seal(tmp_path, keys, challenge=None, name="rec.seal.json"):
    record = {"alert_id": "A-1", "verdict": "true_positive", "confidence": 0.9}
    out = str(tmp_path / name)
    return core.seal(record, keys["private_key_path"], "test-issuer",
                     out_path=out, challenge=challenge)


def _reload(path, mutate):
    data = json.loads(open(path, encoding="utf-8").read())
    mutate(data)
    p = path.replace(".seal.json", ".mut.seal.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return p


# ------------------------------------------------------------------ 契约版本化


def test_every_registered_version_has_a_loadable_schema():
    assert seal_schema.SUPPORTED_VERSIONS, "至少要登记一个版本"
    for v in seal_schema.SUPPORTED_VERSIONS:
        sch = seal_schema.load_schema(v)
        assert sch.get("$schema"), v
        assert sch.get("title"), v
        # 契约自己必须过 jsonschema 的元校验，否则等于没有契约
        import jsonschema
        jsonschema.Draft7Validator.check_schema(sch)


def test_registry_and_files_do_not_drift():
    """登记表里的每个版本都要有文件；包内 schema 文件也必须都在登记表里。"""
    for v, fn in seal_schema.SCHEMA_FILES.items():
        assert os.path.exists(os.path.join(seal_schema.SCHEMA_DIR, fn)), v
    on_disk = {f for f in os.listdir(seal_schema.SCHEMA_DIR) if f.startswith("seal.") and f.endswith(".schema.json")}
    assert on_disk == set(seal_schema.SCHEMA_FILES.values())


def test_issued_seal_passes_schema(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    doc = json.loads(open(sealed["seal_path"], encoding="utf-8").read())
    res = seal_schema.validate(doc)
    assert res["ok"], res
    assert res["seal_version"] == seal_schema.LATEST_VERSION


def test_unknown_version_rejected_without_guessing(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    path = _reload(sealed["seal_path"], lambda d: d["seal_header"].update({"seal_version": "9.9"}))
    res = core.verify(path, keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_UNSUPPORTED_SEAL_VERSION"


def test_wrong_type_rejected(tmp_path, keys):
    """摘要字段必须是 64 位小写十六进制；写成大写或被截断都算结构非法。"""
    sealed = _seal(tmp_path, keys)
    path = _reload(sealed["seal_path"],
                   lambda d: d["seal_header"].update({"payload_sha256": d["seal_header"]["payload_sha256"].upper()}))
    res = core.verify(path, keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_SCHEMA_INVALID"
    assert "payload_sha256" in res["detail"]


def test_missing_header_still_reports_malformed(tmp_path):
    p = tmp_path / "empty.seal.json"
    p.write_text(json.dumps({"payload": {}, "signature": {"alg": "ed25519", "value": "x"}}), encoding="utf-8")
    res = core.verify(str(p), keys_path=str(tmp_path / "missing.json"))
    assert res["reason"] == "E_MALFORMED_SEAL"


def test_signature_length_enforced(tmp_path, keys):
    sealed = _seal(tmp_path, keys)
    path = _reload(sealed["seal_path"], lambda d: d["signature"].update({"value": "c2hvcnQ="}))
    res = core.verify(path, keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_SCHEMA_INVALID"


# ------------------------------------------------------------------ 挑战值 A4


def test_challenge_is_recorded_in_signed_header(tmp_path, keys):
    sealed = _seal(tmp_path, keys, challenge=CH)
    doc = json.loads(open(sealed["seal_path"], encoding="utf-8").read())
    assert doc["seal_header"]["challenge"] == CH


def test_matching_challenge_verifies(tmp_path, keys):
    sealed = _seal(tmp_path, keys, challenge=CH)
    anchor = tmp_path / "trusted_keys.json"
    anchor.write_text(json.dumps({"keys": [{"public_key": keys["public_key_hex"]}]}), encoding="utf-8")
    res = core.verify(sealed["seal_path"], keys_path=str(anchor), expected_challenge=CH)
    assert res["verdict"] == "VALID"


def test_mismatched_challenge_rejected(tmp_path, keys):
    """把凭证挪到另一场会话：签名照样有效，但挑战值对不上，必须拒。"""
    sealed = _seal(tmp_path, keys, challenge=CH)
    res = core.verify(sealed["seal_path"], keys_path=str(tmp_path / "missing.json"),
                      expected_challenge=CH_OTHER)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_CHALLENGE_MISMATCH"


def test_expected_challenge_but_unbound_seal_rejected(tmp_path, keys):
    """未绑定挑战的凭证不能因为"验签通过"就放过——否则防重放形同虚设。"""
    sealed = _seal(tmp_path, keys)
    res = core.verify(sealed["seal_path"], keys_path=str(tmp_path / "missing.json"),
                      expected_challenge=CH)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_CHALLENGE_MISSING"


def test_challenge_cannot_be_swapped_in_place(tmp_path, keys):
    """挑战值在 header 里，被签名覆盖：改它就必然破坏签名。"""
    sealed = _seal(tmp_path, keys, challenge=CH)
    path = _reload(sealed["seal_path"], lambda d: d["seal_header"].update({"challenge": CH_OTHER}))
    res = core.verify(path, keys_path=str(tmp_path / "missing.json"), expected_challenge=CH_OTHER)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_BAD_SIGNATURE"


def test_no_challenge_requested_keeps_old_behaviour(tmp_path, keys):
    """不要求挑战时，老凭证照旧可验——新字段没有把老格式变严。"""
    sealed = _seal(tmp_path, keys)
    res = core.verify(sealed["seal_path"], keys_path=str(tmp_path / "missing.json"))
    assert res["verdict"] == "VALID_UNTRUSTED_KEY"
    assert res["reason"] == "E_NO_TRUST_ANCHOR"


@pytest.mark.parametrize("bad", ["short", "", "has space", "带中文", "a" * 129, "semi;colon"])
def test_bad_challenge_format_refused(tmp_path, keys, bad):
    with pytest.raises(SealError):
        _seal(tmp_path, keys, challenge=bad, name="badch.seal.json")


# ------------------------------------------------------------------ CLI 出口


def test_cli_schema_outputs_seal_contract(tmp_path):
    out = tmp_path / "seal.schema.json"
    r = subprocess.run([sys.executable, "-m", "swordholder.cli", "schema",
                        "--which", "seal", "-o", str(out)],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "credential" in doc["title"].lower()


def test_cli_verify_expect_challenge(tmp_path, keys):
    sealed = _seal(tmp_path, keys, challenge=CH)
    ok = subprocess.run([sys.executable, "-m", "swordholder.cli", "verify", sealed["seal_path"],
                         "--expect-challenge", CH],
                        capture_output=True, text=True, encoding="utf-8")
    assert ok.returncode == 0, ok.stderr
    bad = subprocess.run([sys.executable, "-m", "swordholder.cli", "verify", sealed["seal_path"],
                          "--expect-challenge", CH_OTHER],
                         capture_output=True, text=True, encoding="utf-8")
    assert bad.returncode == 1
    assert "E_CHALLENGE_MISMATCH" in bad.stdout
