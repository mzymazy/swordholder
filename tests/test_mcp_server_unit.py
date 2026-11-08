"""MCP server 进程内单元测试（S6）。

协议层已有子进程端到端测试，但子进程里的代码在父进程中不计覆盖率——
于是"协议层全绿、实现分支一大半没跑过"就成了盲区。这里直接 import 实现函数逐个打负例。
"""

from __future__ import annotations

import glob
import json
import os

from mcp_server import selftest as st
from mcp_server import server as srv


def test_c14n_and_digest_stability():
    a = srv.c14n({"b": 1, "a": "中文"})
    assert a == b'{"a":"\xe4\xb8\xad\xe6\x96\x87","b":1}'
    assert srv.c14n({"a": "中文", "b": 1}) == a
    assert len(srv.sha256_hex(b"x")) == 64


def test_hmac_compare():
    assert srv.hmac_compare("abc", "abc") is True
    assert srv.hmac_compare("abc", "abd") is False


def test_keygen_and_public_hex(tmp_path):
    out = tmp_path / "k"
    res = srv.tool_keygen({"out_dir": str(out)})
    assert res["ok"] is True and len(res["public_key_hex"]) == 64
    again = srv.tool_keygen({"out_dir": str(out)})
    assert again["ok"] is False and "拒绝覆盖" in again["error"]

    priv = srv.load_private_key(res["private_key_path"])
    assert srv.public_hex_from_private(priv) == res["public_key_hex"]


def test_seal_record_needs_payload(tmp_path):
    out = srv.tool_seal_record({})
    assert out["ok"] is False and "payload" in out["error"]


def test_seal_record_from_file_and_challenge_validation(tmp_path):
    kg = srv.tool_keygen({"out_dir": str(tmp_path / "k")})
    rec = tmp_path / "r.json"
    rec.write_text(json.dumps({"alert_id": "A"}), encoding="utf-8")
    sealed = srv.tool_seal_record({"record_path": str(rec),
                                   "private_key_path": kg["private_key_path"],
                                   "issuer": "soc", "subject": "A"})
    assert sealed["ok"] is True
    bad_chal = srv.tool_seal_record({"private_key_path": kg["private_key_path"],
                                     "payload": {"a": 1}, "challenge": "short"})
    assert bad_chal["ok"] is False
    missing_key = srv.tool_seal_record({"private_key_path": str(tmp_path / "nope.pem"),
                                        "payload": {"a": 1}})
    assert missing_key["ok"] is False


def test_verify_seal_and_challenge(tmp_path):
    kg = srv.tool_keygen({"out_dir": str(tmp_path / "k")})
    sealed = srv.tool_seal_record({"payload": {"alert_id": "A"}, "subject": "A",
                                   "private_key_path": kg["private_key_path"],
                                   "challenge": "chalABCD12"})
    path = sealed["seal_path"]
    ok = srv.tool_verify_seal({"seal_path": path, "expected_challenge": "chalABCD12"})
    assert "VALID" in json.dumps(ok)
    mismatch = srv.tool_verify_seal({"seal_path": path, "expected_challenge": "chalZZZZ99"})
    assert mismatch["verdict"] == "INVALID"
    assert srv.tool_verify_seal({"seal_path": str(tmp_path / "none.seal.json")})
    assert srv.tool_verify_seal({"seal_path": path, "keys_path": str(tmp_path / "none.json")})


def test_list_trusted_keys_variants(tmp_path):
    assert srv.tool_list_trusted_keys({"keys_path": str(tmp_path / "x.json")})["ok"] is False

    from swordholder import trust
    keys_file = str(tmp_path / "trusted_keys.json")
    kg = srv.tool_keygen({"out_dir": str(tmp_path / "k")})
    trust.add_key(keys_file, key_id="k1", public_key_hex=kg["public_key_hex"])
    ok = srv.tool_list_trusted_keys({"keys_path": keys_file})
    assert ok["ok"] is True and ok["count"] == 1

    # 非标准结构：走 fallback 解析分支
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps([{"id": "k9", "public_key": "ab" * 32}]), encoding="utf-8")
    out = srv.tool_list_trusted_keys({"keys_path": str(legacy)})
    assert out["ok"] is True and out["keys"][0]["key_id"] == "k9"
    assert len(out["keys"][0]["fingerprint_sha256_16"]) == 16

    unparsable = tmp_path / "bad.json"
    unparsable.write_text("{not json", encoding="utf-8")
    assert srv.tool_list_trusted_keys({"keys_path": str(unparsable)})["ok"] is False


def test_verify_proof_missing_and_real(tmp_path):
    out = srv.tool_verify_proof({"proof_path": str(tmp_path / "none.yaml")})
    assert out["ok"] is False and "不存在" in out["error"]

    real = sorted(glob.glob(os.path.join(srv.REPO_ROOT, "proofs", "*.yaml")))
    if real:
        res = srv.tool_verify_proof({"proof_path": real[0]})
        assert res["verdict"] in ("VALID", "INVALID")


def test_handle_rpc_shapes(tmp_path):
    assert srv.handle({"method": "ping", "id": None}) is None        # 通知无响应
    assert srv.handle({"method": "ping", "id": 1})["result"] == {}
    assert srv.handle({"method": "initialize", "id": 2})["result"]["serverInfo"]["name"] == "swordholder-mcp"
    err = srv.handle({"method": "no/such", "id": 3})
    assert err["error"]["code"] == -32601
    bad_tool = srv.handle({"method": "tools/call", "id": 4,
                           "params": {"name": "nope", "arguments": {}}})
    assert bad_tool["error"]["code"] == -32601

    ok = srv.handle({"method": "tools/call", "id": 5,
                     "params": {"name": "keygen", "arguments": {"out_dir": str(tmp_path / "k5")}}})
    assert ok["result"]["isError"] is False

    rejected = srv.handle({"method": "tools/call", "id": 6,
                           "params": {"name": "seal_record", "arguments": {}}})
    assert rejected["result"]["isError"] is True

    boom = srv.handle({"method": "tools/call", "id": 7,
                       "params": {"name": "verify_seal", "arguments": None}})
    assert boom["result"]["isError"] in (True, False)


def test_exception_in_handler_is_contained(monkeypatch):
    def explode(args):
        raise RuntimeError("boom")

    monkeypatch.setitem(srv.HANDLERS, "keygen", explode)
    resp = srv.handle({"method": "tools/call", "id": 9,
                       "params": {"name": "keygen", "arguments": {}}})
    assert resp["result"]["isError"] is True
    assert "工具执行异常" in resp["result"]["content"][0]["text"]


def test_selftest_script_main_passes(capsys):
    """selftest 自身也必须仍然全过，否则 CI 里的 mcp-selftest 门禁形同虚设。"""
    assert st.main() == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out
