"""信任锚治理测试：轮换窗口、吊销、体检、CLI 与 HTTP 出口。

这些用例守的是四条不能退让的语义：
    1. 老格式 trust 文件不炸（0.1–0.3 仓库可以原地升级）
    2. 轮换后旧凭证仍可验（按签发时刻判窗口，不按 now）
    3. 旧锚在停用窗口之后签的新凭证验不过（停用才是真停用）
    4. 吊销优先于一切（密钥吊销 / 凭证吊销 → INVALID）
"""

import base64
import json
import threading
import urllib.error
import urllib.request
import uuid

import pytest
from cryptography.hazmat.primitives import serialization

from mcp_server import server as srv
from swordholder import core, trust
from swordholder.cli import main as cli_main
from swordholder.serve import ServerConfig, build_server


@pytest.fixture()
def keys(tmp_path):
    return core.keygen(str(tmp_path / "keys"))


@pytest.fixture()
def anchor(tmp_path):
    return str(tmp_path / "trusted_keys.json")


def _seal(tmp_path, keys, name="rec.seal.json", record=None):
    record = record or {"alert_id": "A-1", "verdict": "true_positive", "confidence": 0.9}
    out = str(tmp_path / name)
    sealed = core.seal(record, keys["private_key_path"], "test-issuer", out_path=out)
    return sealed["seal_path"], sealed["seal_id"]


def _forge(tmp_path, keys, created_at, name="forged.seal.json", header_extra=None):
    """用私钥签一份自定义 created_at 的凭证（用于模拟"旧锚签新凭证"）。"""
    payload = {"alert_id": "A-2", "verdict": "suspicious", "confidence": 0.5}
    priv = serialization.load_pem_private_key(
        open(keys["private_key_path"], "rb").read(), None)
    header = {
        "seal_version": "1.0", "seal_id": str(uuid.uuid4()), "created_at": created_at,
        "issuer": "test-issuer", "subject": "A-2", "signature_alg": "ed25519",
        "canonicalization": "json-c14n-v1",
        "payload_sha256": srv.sha256_hex(srv.c14n(payload)),
        "public_key_hex": srv.public_hex_from_private(priv),
        "record_ref": "inline",
    }
    header.update(header_extra or {})
    signing_input = (srv.SEAL_DOMAIN + bytes.fromhex(header["payload_sha256"])
                     + b"\n" + srv.c14n(header))
    doc = {"seal_header": header, "payload": payload,
           "signature": {"alg": "ed25519",
                         "value": base64.b64encode(priv.sign(signing_input)).decode()}}
    path = tmp_path / name
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return str(path), header["seal_id"]


# ---------------------------------------------------------------- 兼容 / 基础

def test_legacy_anchor_without_status_still_trusted(tmp_path, keys, anchor):
    seal_path, _ = _seal(tmp_path, keys)
    with open(anchor, "w", encoding="utf-8") as f:
        json.dump({"keys": [{"public_key": keys["public_key_hex"]}]}, f)
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "VALID"
    assert res["trust"] == "trusted"


def test_anchor_file_missing_is_fail_closed(tmp_path, keys):
    seal_path, _ = _seal(tmp_path, keys)
    res = core.verify(seal_path, keys_path=str(tmp_path / "nope.json"))
    assert res["verdict"] == "VALID_UNTRUSTED_KEY"
    assert res["reason"] == "E_NO_TRUST_ANCHOR"


def test_corrupt_anchor_is_fail_closed(tmp_path, keys, anchor):
    seal_path, _ = _seal(tmp_path, keys)
    open(anchor, "w", encoding="utf-8").write("{not json")
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "VALID_UNTRUSTED_KEY"
    assert res["reason"] == "E_NO_TRUST_ANCHOR"
    assert trust.load(anchor)["loaded"] is False


def test_unknown_key_is_untrusted(tmp_path, keys, anchor):
    other = core.keygen(str(tmp_path / "keys2"))
    trust.add_key(anchor, other["public_key_hex"], key_id="k-other")
    seal_path, _ = _seal(tmp_path, keys)
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "VALID_UNTRUSTED_KEY"
    assert res["reason"] == "E_UNTRUSTED_KEY"


# ---------------------------------------------------------------- 登记

def test_add_key_reports_state(tmp_path, anchor, keys):
    added = trust.add_key(anchor, keys["public_key_hex"], key_id="k-2026a",
                          not_before="2026-01-01T00:00:00Z")
    assert added["key"]["status"] == "active"
    info = trust.summary(anchor)
    assert info["loaded"] and info["counts"]["total"] == 1
    assert info["keys"][0]["state"] == "usable"
    assert info["keys"][0]["key_id"] == "k-2026a"


def test_add_key_is_idempotent_on_same_pubkey(tmp_path, anchor, keys):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1", note="重新登记")
    assert trust.summary(anchor)["counts"]["total"] == 1


def test_add_key_rejects_bad_input(tmp_path, anchor):
    with pytest.raises(trust.TrustError):
        trust.add_key(anchor, "zz")
    with pytest.raises(trust.TrustError):
        trust.add_key(anchor, "0" * 64, not_before="2026-06-01T00:00:00Z",
                      not_after="2026-01-01T00:00:00Z")
    with pytest.raises(trust.TrustError):
        trust.add_key(anchor, "0" * 64, not_after="不是时间")


def test_add_key_keeps_unknown_fields(tmp_path, anchor):
    """不要在维护信任锚时把用户自定义字段清洗掉。"""
    with open(anchor, "w", encoding="utf-8") as f:
        json.dump({"trust_root": "acme/1.0", "custom": {"ticket": "SEC-42"}}, f)
    trust.add_key(anchor, "a" * 64, trust_root="acme/2.0")
    raw = json.load(open(anchor, encoding="utf-8"))
    assert raw["custom"]["ticket"] == "SEC-42"
    assert raw["trust_root"] == "acme/2.0"


# ---------------------------------------------------------------- 轮换窗口

def test_retired_key_still_validates_old_seal(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-old")
    seal_path, _ = _seal(tmp_path, keys)

    new = core.keygen(str(tmp_path / "keys_new"))
    trust.add_key(anchor, new["public_key_hex"], key_id="k-new",
                  not_before="2026-01-01T00:00:00Z")
    trust.retire_key(anchor, "k-old", at="2099-01-01T00:00:00Z", replaced_by="k-new")

    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "VALID"
    assert res["key_id"] == "k-old"
    assert res["key_status"] == "retired"


def test_retired_key_cannot_sign_after_window(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-old")
    trust.retire_key(anchor, "k-old", at="2026-01-01T00:00:00Z", replaced_by="k-new")
    seal_path, _ = _forge(tmp_path, keys, "2026-06-01T00:00:00Z")
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_KEY_EXPIRED"


def test_new_key_takes_over_after_rotation(tmp_path, keys, anchor):
    new = core.keygen(str(tmp_path / "keys_new"))
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-old")
    trust.add_key(anchor, new["public_key_hex"], key_id="k-new")
    trust.retire_key(anchor, "k-old", at="2026-01-01T00:00:00Z", replaced_by="k-new")

    seal_path = str(tmp_path / "new.seal.json")
    core.seal({"alert_id": "A-3", "verdict": "true_positive"}, new["private_key_path"],
              "test-issuer", out_path=seal_path)
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "VALID"
    assert res["key_id"] == "k-new"


def test_not_yet_valid_window_rejected(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-future",
                  not_before="2030-01-01T00:00:00Z")
    seal_path, _ = _forge(tmp_path, keys, "2026-06-01T00:00:00Z")
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_KEY_NOT_YET_VALID"


def test_seal_without_timestamp_needs_unbounded_anchor(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-window",
                  not_before="2026-01-01T00:00:00Z")
    seal_path, _ = _forge(tmp_path, keys, "")
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_SEAL_NO_TIMESTAMP"


# ---------------------------------------------------------------- 吊销

def test_revoked_key_invalidates_all_seals(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    seal_path, _ = _seal(tmp_path, keys)
    assert core.verify(seal_path, keys_path=anchor)["verdict"] == "VALID"

    trust.revoke_key(anchor, "k-1", reason="私钥疑似泄露")
    res = core.verify(seal_path, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_KEY_REVOKED"
    assert res["revoked_reason"] == "私钥疑似泄露"


def test_revoked_seal_invalidates_only_that_seal(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    bad_path, bad_id = _seal(tmp_path, keys, name="bad.seal.json")
    good_path, _ = _seal(tmp_path, keys, name="good.seal.json",
                         record={"alert_id": "A-9", "verdict": "false_positive"})

    trust.revoke_seal(anchor, bad_id, reason="误发")
    res = core.verify(bad_path, keys_path=anchor)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_SEAL_REVOKED"
    assert core.verify(good_path, keys_path=anchor)["verdict"] == "VALID"


def test_revoke_seal_is_idempotent_and_restorable(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    path, seal_id = _seal(tmp_path, keys)
    first = trust.revoke_seal(anchor, seal_id)
    again = trust.revoke_seal(anchor, seal_id)
    assert first["already"] is False and again["already"] is True
    assert trust.summary(anchor)["revoked_seal_count"] == 1

    trust.restore_seal(anchor, seal_id)
    assert trust.summary(anchor)["revoked_seal_count"] == 0
    assert core.verify(path, keys_path=anchor)["verdict"] == "VALID"


def test_revoke_unknown_key_raises(tmp_path, anchor):
    with pytest.raises(trust.TrustError):
        trust.revoke_key(anchor, "k-not-exist")


# ---------------------------------------------------------------- 体检

def test_check_rotation_warns_on_parallel_active_keys(tmp_path, keys, anchor):
    other = core.keygen(str(tmp_path / "keys2"))
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-a")
    trust.add_key(anchor, other["public_key_hex"], key_id="k-b")
    res = trust.check_rotation(anchor)
    assert res["active"] == 2 and res["warnings"]


def test_check_rotation_flags_retire_without_window(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-a")
    raw = json.load(open(anchor, encoding="utf-8"))
    raw["keys"][0]["status"] = "retired"
    json.dump(raw, open(anchor, "w", encoding="utf-8"))
    res = trust.check_rotation(anchor)
    assert any("not_after" in w for w in res["warnings"])


# ---------------------------------------------------------------- CLI

def test_cli_trust_roundtrip(tmp_path, keys, anchor, capsys):
    assert cli_main(["trust", "add", "--keys-file", anchor,
                     "--pubkey", keys["public_key_hex"], "--key-id", "k-cli"]) == 0
    capsys.readouterr()
    assert cli_main(["trust", "show", "--keys-file", anchor, "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["counts"]["total"] == 1

    assert cli_main(["trust", "retire", "k-cli", "--keys-file", anchor,
                     "--at", "2099-01-01T00:00:00Z"]) == 0
    capsys.readouterr()
    assert cli_main(["trust", "show", "--keys-file", anchor, "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["keys"][0]["status"] == "retired"


def test_cli_revoke_requires_explicit_flag(tmp_path, keys, anchor, capsys):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    assert cli_main(["trust", "revoke", "k-1", "--keys-file", anchor]) == 1
    assert "显式指定" in capsys.readouterr().err


def test_cli_revoke_by_seal_file(tmp_path, keys, anchor, capsys):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    seal_path, seal_id = _seal(tmp_path, keys)
    assert cli_main(["trust", "revoke", seal_path, "--seal",
                     "--keys-file", anchor, "--reason", "误发"]) == 0
    capsys.readouterr()
    assert trust.summary(anchor)["revoked_seals"][0]["seal_id"] == seal_id


def test_cli_check_exit_code_signals_warnings(tmp_path, keys, anchor, capsys):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-1")
    assert cli_main(["trust", "check", "--keys-file", anchor]) == 0
    capsys.readouterr()
    other = core.keygen(str(tmp_path / "keys2"))
    trust.add_key(anchor, other["public_key_hex"], key_id="k-2")
    assert cli_main(["trust", "check", "--keys-file", anchor]) == 2


# ---------------------------------------------------------------- HTTP

@pytest.fixture()
def live(tmp_path, keys, anchor):
    trust.add_key(anchor, keys["public_key_hex"], key_id="k-http")
    cfg = ServerConfig(port=0, out_dir=str(tmp_path / "seals"),
                       key_path=keys["private_key_path"], keys_file=anchor,
                       db=str(tmp_path / "index.db"), token="t0ken")
    httpd = build_server(cfg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()
    cfg.close()


def _get(url, token="t0ken"):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_http_trust_endpoint(live):
    code, body = _get(live + "/v1/trust")
    assert code == 200
    assert body["loaded"] is True
    assert body["counts"]["total"] == 1
    assert body["keys"][0]["key_id"] == "k-http"
    assert "keys_path" not in body


def test_http_trust_needs_token(live):
    code, _ = _get(live + "/v1/trust", token=None)
    assert code == 401
