"""MCP 协议层测试（S6）：把 selftest 之外的负例补上，钉住 JSON-RPC 层不会被轻易改坏。

复用 mcp_server.selftest 的 Client（真实子进程 + 真实 stdio），不引入 mock SDK。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from mcp_server import selftest as st


@pytest.fixture(scope="module")
def client():
    c = st.Client()
    yield c
    try:
        c.close()
    except Exception:
        c.p.kill()


@pytest.fixture(scope="module")
def keys_dir(tmp_path_factory):
    return str(tmp_path_factory.mktemp("mcp_keys"))


def _payload(resp):
    return json.loads(resp["result"]["content"][0]["text"])


def test_initialize_and_ping(client):
    init = client.rpc("initialize", {"protocolVersion": "2024-11-05",
                                     "clientInfo": {"name": "pytest", "version": "0"}})
    assert init["jsonrpc"] == "2.0"
    info = init["result"]
    assert info["serverInfo"]["name"] == "swordholder-mcp"
    assert info["protocolVersion"] == "2024-11-05"
    assert info["capabilities"]["tools"]["listChanged"] is False
    assert client.rpc("ping")["result"] == {}


def test_tools_list_schema_shape(client):
    tools = {t["name"]: t for t in client.rpc("tools/list")["result"]["tools"]}
    assert set(tools) == {"verify_proof", "seal_record", "verify_seal",
                          "list_trusted_keys", "keygen"}
    assert tools["seal_record"]["inputSchema"]["required"] == ["private_key_path"]
    assert tools["verify_proof"]["inputSchema"]["required"] == ["proof_path"]
    assert all(t.get("description") for t in tools.values())


def test_unknown_tool_and_method(client):
    bad = client.call("nope_tool", {})
    assert bad["error"]["code"] == -32601 and "未知工具" in bad["error"]["message"]
    bad2 = client.rpc("resources/list")
    assert bad2["error"]["code"] == -32601 and "未实现" in bad2["error"]["message"]


def test_notification_gets_no_response(client):
    """id 缺省的通知类消息不得产生响应行，否则客户端游标会错位。"""
    client.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "ping"}) + "\n")
    client.p.stdin.flush()
    # 紧跟一个正常请求：如果上一条被错误地回了响应，这里读到的就是它的 id
    resp = client.rpc("ping")
    assert resp["id"] == client._id


def test_bad_json_line_yields_parse_error():
    p = subprocess.Popen([sys.executable, st.SERVER], cwd=st.REPO_ROOT,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
    try:
        p.stdin.write("{not json\n")
        p.stdin.flush()
        line = json.loads(p.stdout.readline())
        assert line["error"]["code"] == -32700 and line["id"] is None
    finally:
        p.stdin.close()
        p.wait(timeout=10)


def test_keygen_refuses_overwrite(client, keys_dir):
    first = _payload(client.call("keygen", {"out_dir": keys_dir}))
    assert first["ok"] and len(first["public_key_hex"]) == 64
    assert os.path.exists(first["public_key_path"])
    second = _payload(client.call("keygen", {"out_dir": keys_dir}))
    assert second["ok"] is False and "拒绝覆盖" in second["error"]


def test_seal_and_verify_with_challenge(client, keys_dir):
    kg = _payload(client.call("keygen", {"out_dir": keys_dir + "_b"}))
    if not kg.get("ok"):
        pytest.skip("私钥已存在，复用上一用例产物")
    key = kg["private_key_path"]

    sealed = _payload(client.call("seal_record", {
        "private_key_path": key, "issuer": "soc@example",
        "subject": "ALRT-S6-MCP", "challenge": "chalS6AAAA1",
        "payload": {"alert_id": "ALRT-S6-MCP", "verdict": "true_positive"},
    }))
    assert sealed["ok"] is True
    seal_path = sealed["seal_path"]

    ok = _payload(client.call("verify_seal", {"seal_path": seal_path,
                                              "expected_challenge": "chalS6AAAA1"}))
    assert ok["verdict"] == "VALID" or "VALID" in str(ok)
    mismatch = _payload(client.call("verify_seal", {"seal_path": seal_path,
                                                    "expected_challenge": "chalS6BBBB2"}))
    assert mismatch["verdict"] == "INVALID" and "E_CHALLENGE_MISMATCH" in mismatch["reason"]
    missing = _payload(client.call("verify_seal", {"seal_path": seal_path,
                                                   "expected_challenge": "chalS6AAAA1",
                                                   "keys_path": "no_such_keys.json"}))
    assert missing["verdict"] in ("VALID_UNTRUSTED_KEY", "INVALID")


def test_seal_record_rejects_bad_input(client, keys_dir):
    assert _payload(client.call("seal_record", {}))["ok"] is False
    assert _payload(client.call("seal_record", {"private_key_path": "no/such/key.pem",
                                                "payload": {"a": 1}}))["ok"] is False
    out = _payload(client.call("seal_record", {"private_key_path": "no/such/key.pem",
                                              "payload": {"a": 1},
                                              "challenge": "short"}))
    assert out["ok"] is False


def test_verify_seal_missing_file(client):
    out = _payload(client.call("verify_seal", {"seal_path": "no_such.seal.json"}))
    assert str(out.get("verdict")) in ("INVALID", "False") or out.get("ok") is False


def test_list_trusted_keys_missing_anchor(client, tmp_path):
    out = _payload(client.call("list_trusted_keys",
                               {"keys_path": str(tmp_path / "absent.json")}))
    assert out["ok"] is False and "不存在" in out["error"]


def test_verify_proof_missing_file(client):
    out = _payload(client.call("verify_proof", {"proof_path": "no_such_proof.yaml"}))
    head = str(out.get("verdict", ""))
    assert head == "INVALID" or out.get("ok") is False


def test_exception_inside_tool_is_contained(client, tmp_path):
    """工具内部异常必须被协议层兜住并回 isError，不能让服务进程挂掉。"""
    bad = tmp_path / "bad.json"
    bad.write_text("{broken", encoding="utf-8")
    resp = client.call("seal_record", {"private_key_path": "no/such.pem",
                                       "record_path": str(bad)})
    assert resp["result"]["isError"] is True
    assert client.rpc("ping")["result"] == {}


def test_verify_proof_on_real_proofs(client):
    """仓库自带的 4 份证明必须仍然 4/4 VALID（防止桩测试掩盖真实回归）。"""
    proofs_dir = os.path.join(st.REPO_ROOT, "proofs")
    if not os.path.isdir(proofs_dir):
        pytest.skip("仓库无 proofs/ 目录")
    proofs = [os.path.join(proofs_dir, f) for f in sorted(os.listdir(proofs_dir))
              if f.endswith((".yaml", ".yml"))]
    if not proofs:
        pytest.skip("proofs/ 下无 yaml")
    verdicts = []
    for p in proofs:
        out = _payload(client.call("verify_proof", {"proof_path": p}))
        verdicts.append(out.get("verdict"))
    assert all(v == "VALID" for v in verdicts), verdicts
