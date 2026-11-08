"""CLI 表面覆盖测试（S6）：把 `swordholder` 每个子命令真跑一遍。

设计原则：
- 全部走 `cli.main(argv)` 真实入口，不 mock 内部函数，断言只看退出码 + 落盘事实；
- 每个用例自带 tmp_path，绝不触碰仓库内真实密钥/索引；
- 负例优先：错误码分支（E_BAD_JSON / E_EMPTY_BODY / 误吊销拦截）比 happy path 更容易悄悄坏掉。
"""

from __future__ import annotations

import io
import json
import os
import runpy
import sys

import pytest

from swordholder import cli, core


# ------------------------------------------------------------------ 工具

def _run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return str(path)


def _keys(tmp_path):
    """在临时目录里造一对密钥，返回 (私钥路径, 公钥 hex, keys 目录)。"""
    out = str(tmp_path / "keys")
    res = core.keygen(out)
    return res["private_key_path"], res["public_key_hex"], out


# ------------------------------------------------------------------ keygen / seal / verify / query

def test_keygen_seal_verify_query_roundtrip(tmp_path, capsys):
    key, pub_hex, _ = _keys(tmp_path)
    record = _write_json(tmp_path / "triage.json", {
        "alert_id": "ALRT-S6-001", "asset": "host-a", "verdict": "true_positive",
        "severity": "high", "actions": ["isolate"], "hypothesis": "test",
    })
    seal_path = str(tmp_path / "triage.seal.json")
    db = str(tmp_path / "index.db")

    code, out, _ = _run(["seal", record, "-k", key, "--issuer", "soc@example",
                         "--subject", "ALRT-S6-001", "-o", seal_path, "--db", db], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["seal_path"] == seal_path and payload["indexed"] is True
    assert os.path.exists(seal_path)

    # 无信任锚：签名自洽但未建立信任
    code, out, _ = _run(["verify", seal_path], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "VALID_UNTRUSTED_KEY"

    # 登记信任锚后应判 VALID
    keys_file = str(tmp_path / "trusted_keys.json")
    code, _, _ = _run(["trust", "add", "--keys-file", keys_file,
                       "--key-id", "k-s6", "--pubkey", pub_hex], capsys)
    assert code == 0
    code, out, _ = _run(["verify", seal_path, "--keys", keys_file], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "VALID"

    # 索引可查：json 与表格两种输出
    code, out, _ = _run(["query", "--db", db, "--json"], capsys)
    assert code == 0 and json.loads(out)["count"] == 1
    code, out, _ = _run(["query", "--db", db, "--verdict", "true_positive"], capsys)
    assert code == 0 and "ALRT-S6-001" in out
    code, out, _ = _run(["query", "--db", db, "--subject", "nobody"], capsys)
    assert code == 0 and "无匹配凭证" in out


def test_seal_error_paths(tmp_path, capsys):
    key, _, _ = _keys(tmp_path)
    code, out, _ = _run(["seal", str(tmp_path / "missing.json"), "-k", key,
                         "--issuer", "soc"], capsys)
    assert code == 2 and json.loads(out)["code"] == "E_NOT_FOUND"

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out, _ = _run(["seal", str(bad), "-k", key, "--issuer", "soc"], capsys)
    assert code == 2 and json.loads(out)["code"] == "E_BAD_JSON"


def test_seal_challenge_binding(tmp_path, capsys):
    key, _, _ = _keys(tmp_path)
    record = _write_json(tmp_path / "rec.json", {
        "alert_id": "ALRT-S6-002", "asset": "host-b", "verdict": "suspicious",
        "severity": "medium", "actions": ["review"], "hypothesis": "h",
    })
    seal_path = str(tmp_path / "rec.seal.json")
    code, out, _ = _run(["seal", record, "-k", key, "--issuer", "soc",
                         "--challenge", "chal-001", "-o", seal_path], capsys)
    assert code == 0 and json.loads(out)["challenge_bound"] is True

    code, out, _ = _run(["verify", seal_path, "--expect-challenge", "chal-001"], capsys)
    assert code == 0
    code, out, _ = _run(["verify", seal_path, "--expect-challenge", "other"], capsys)
    assert code == 1 and json.loads(out)["reason"] == "E_CHALLENGE_MISMATCH"


def test_verify_tampered_payload_via_cli(tmp_path, capsys):
    key, _, _ = _keys(tmp_path)
    record = _write_json(tmp_path / "rec.json", {
        "alert_id": "ALRT-S6-003", "asset": "host-c", "verdict": "true_positive",
        "severity": "high", "actions": ["isolate"], "hypothesis": "h",
    })
    seal_path = str(tmp_path / "rec.seal.json")
    assert _run(["seal", record, "-k", key, "--issuer", "soc", "-o", seal_path], capsys)[0] == 0

    doc = json.load(open(seal_path, encoding="utf-8"))
    doc["payload"]["verdict"] = "false_positive"
    tampered = _write_json(tmp_path / "tampered.seal.json", doc)
    code, out, _ = _run(["verify", tampered], capsys)
    assert code == 1 and json.loads(out)["reason"] == "E_PAYLOAD_TAMPERED"


# ------------------------------------------------------------------ triage

def test_triage_file_and_stdin(tmp_path, capsys, monkeypatch):
    key, _, _ = _keys(tmp_path)
    alert = _write_json(tmp_path / "alert.json", {
        "alert_id": "ALRT-S6-010", "asset": "host-a",
        "signal": "unexpected outbound TLS to unknown ASN",
        "severity": "high", "tags": ["outbound"],
    })
    code, out, _ = _run(["triage", alert], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "suspicious"

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "alert_id": "ALRT-S6-011", "asset": "host-b",
        "signal": "postinstall script executed", "severity": "critical"})))
    code, out, _ = _run(["triage", "-", "--out-dir", str(tmp_path / "stdin_out")], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "true_positive"

    # 盖章分支：stdin + --seal + -k + --db
    db = str(tmp_path / "index.db")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "alert_id": "ALRT-S6-012", "asset": "host-c",
        "signal": "ci token reused from new ASN", "severity": "high"})))
    code, out, _ = _run(["triage", "-", "--seal", "-k", key,
                         "--out-dir", str(tmp_path / "sealed"), "--db", db], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["indexed"] is True and os.path.exists(payload["seal"])


def test_triage_negative_paths(tmp_path, capsys, monkeypatch):
    # 空 stdin
    monkeypatch.setattr(sys, "stdin", io.StringIO("   "))
    code, out, _ = _run(["triage", "-"], capsys)
    assert code == 2 and json.loads(out)["code"] == "E_EMPTY_BODY"

    # stdin 非 JSON
    monkeypatch.setattr(sys, "stdin", io.StringIO("<html>"))
    code, out, _ = _run(["triage", "-"], capsys)
    assert code == 2 and json.loads(out)["code"] == "E_BAD_JSON"

    # 文件不存在
    code, out, _ = _run(["triage", str(tmp_path / "nope.json")], capsys)
    assert code == 2 and json.loads(out)["code"] == "E_NOT_FOUND"

    # 结构无法识别
    unknown = _write_json(tmp_path / "unknown.json", {"totally": "unrelated"})
    code, out, _ = _run(["triage", unknown], capsys)
    assert code == 2

    # --seal 缺 -k
    alert = _write_json(tmp_path / "alert.json", {
        "alert_id": "ALRT-S6-013", "asset": "host-a", "signal": "outbound beacon",
        "severity": "low"})
    code, _, err = _run(["triage", alert, "--seal"], capsys)
    assert code == 2 and "--seal 需要 -k" in err


# ------------------------------------------------------------------ exits / schema / demo

def test_exits_and_selftest(capsys):
    code, out, _ = _run(["exits", "--json"], capsys)
    assert code == 0 and json.loads(out)["exits"]
    code, out, _ = _run(["exits"], capsys)
    assert code == 0 and "出口合计" in out
    code, out, _ = _run(["exits", "--selftest"], capsys)
    assert code == 0 and json.loads(out)["coverage"] == 1.0


def test_schema_outputs(tmp_path, capsys):
    code, out, _ = _run(["schema"], capsys)
    assert code == 0 and json.loads(out)["$schema"] or code == 0
    target = tmp_path / "alert.schema.json"
    code, out, _ = _run(["schema", "-o", str(target)], capsys)
    assert code == 0 and json.loads(out)["ok"] is True and target.exists()

    seal_target = tmp_path / "seal.schema.json"
    code, out, _ = _run(["schema", "--which", "seal", "-o", str(seal_target)], capsys)
    assert code == 0 and seal_target.exists()
    code, out, _ = _run(["schema", "--which", "seal"], capsys)
    assert code == 0 and out.strip()


def test_demo_end_to_end(tmp_path, capsys):
    out_dir = tmp_path / "demo_out"
    keys = tmp_path / "demo_keys"
    code, out, _ = _run(["demo", "--out", str(out_dir), "--keys", str(keys)], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["tamper"]["reason"] == "E_PAYLOAD_TAMPERED"
    assert all(r["sealed"] in ("VALID", "VALID_UNTRUSTED_KEY") for r in payload["rows"])


# ------------------------------------------------------------------ policy

def test_policy_list_show_check(tmp_path, capsys):
    code, out, _ = _run(["policy", "list", "--json"], capsys)
    assert code == 0 and json.loads(out)
    code, out, _ = _run(["policy", "list"], capsys)
    assert code == 0 and "内置策略包目录" in out

    code, out, _ = _run(["policy", "show", "--json"], capsys)
    assert code == 0 and json.loads(out)["id"]
    code, out, _ = _run(["policy", "show"], capsys)
    assert code == 0 and "不变量" in out

    code, out, _ = _run(["policy", "show", "--path", str(tmp_path / "missing.yaml")], capsys)
    assert code == 2 and "策略不可用" in out

    code, out, _ = _run(["policy", "check", str(tmp_path / "missing.yaml")], capsys)
    assert code == 2 and "不合法" in out


def test_policy_check_valid_file(tmp_path, capsys):
    from swordholder import policy_loader
    src = policy_loader.resolve_path(None)
    code, out, _ = _run(["policy", "check", src], capsys)
    assert code == 0 and "合法" in out


# ------------------------------------------------------------------ trust 治理

def test_trust_lifecycle(tmp_path, capsys):
    keys_file = str(tmp_path / "trusted_keys.json")
    _, pub_hex, _ = _keys(tmp_path)

    # 缺文件时 show 返回 1 并给出警告
    code, out, _ = _run(["trust", "show", "--keys-file", keys_file], capsys)
    assert code == 1 and "信任根" in out
    code, out, _ = _run(["trust", "show", "--keys-file", keys_file, "--json"], capsys)
    assert code == 1 and json.loads(out)["loaded"] is False

    # 登记：--pubkey
    code, out, _ = _run(["trust", "add", "--keys-file", keys_file,
                         "--key-id", "k-a", "--pubkey", pub_hex], capsys)
    assert code == 0
    # 登记：--pubkey-file
    _, pub_hex2, keys_dir = _keys(tmp_path / "second")
    pub_pem = os.path.join(keys_dir, "swordholder_ed25519_public.pem")
    if os.path.exists(pub_pem):
        code, out, _ = _run(["trust", "add", "--keys-file", keys_file,
                             "--key-id", "k-b", "--pubkey-file", pub_pem], capsys)
        assert code == 0
    # 登记失败：两个参数都缺
    code, _, err = _run(["trust", "add", "--keys-file", keys_file], capsys)
    assert code == 1 and "必须提供" in err
    # 登记失败：不是 ed25519 的 pem
    bogus = tmp_path / "bogus.pem"
    bogus.write_text("-----BEGIN PUBLIC KEY-----\nnotakey\n-----END PUBLIC KEY-----\n",
                     encoding="utf-8")
    code, _, err = _run(["trust", "add", "--keys-file", keys_file,
                         "--pubkey-file", str(bogus)], capsys)
    assert code == 1 and "读取公钥失败" in err

    # 体检 / 查看
    code, out, _ = _run(["trust", "check", "--keys-file", keys_file], capsys)
    assert code in (0, 2)
    code, out, _ = _run(["trust", "show", "--keys-file", keys_file], capsys)
    assert code == 0 and "锚数量" in out

    # 轮换：停用旧锚
    code, out, _ = _run(["trust", "retire", "k-a", "--keys-file", keys_file,
                         "--replaced-by", "k-b"], capsys)
    assert code == 0 and "窗口" in out
    code, _, err = _run(["trust", "retire", "k-none", "--keys-file", keys_file], capsys)
    assert code == 1 and "停用失败" in err

    # 吊销锚
    code, out, _ = _run(["trust", "revoke", "k-a", "--key", "--keys-file", keys_file,
                         "--reason", "lost"], capsys)
    assert code == 0 and "注意" in out


def test_trust_revoke_guards(tmp_path, capsys):
    keys_file = str(tmp_path / "trusted_keys.json")
    _, pub_hex, _ = _keys(tmp_path)
    _run(["trust", "add", "--keys-file", keys_file, "--key-id", "k-a", "--pubkey", pub_hex], capsys)

    code, _, err = _run(["trust", "revoke", "--key", "--keys-file", keys_file], capsys)
    assert code == 1 and "需要给出" in err
    code, _, err = _run(["trust", "revoke", "k-a", "--key", "--seal",
                         "--keys-file", keys_file], capsys)
    assert code == 1 and "不能同时使用" in err
    code, _, err = _run(["trust", "revoke", "k-a", "--keys-file", keys_file], capsys)
    assert code == 1 and "必须显式指定" in err


def test_trust_revoke_and_restore_seal(tmp_path, capsys):
    key, pub_hex, _ = _keys(tmp_path)
    keys_file = str(tmp_path / "trusted_keys.json")
    _run(["trust", "add", "--keys-file", keys_file, "--key-id", "k-a", "--pubkey", pub_hex], capsys)

    record = _write_json(tmp_path / "rec.json", {
        "alert_id": "ALRT-S6-020", "asset": "host-a", "verdict": "true_positive",
        "severity": "high", "actions": ["isolate"], "hypothesis": "h"})
    seal_path = str(tmp_path / "rec.seal.json")
    _run(["seal", record, "-k", key, "--issuer", "soc", "-o", seal_path], capsys)
    seal_id = json.load(open(seal_path, encoding="utf-8"))["seal_header"]["seal_id"]

    # 用 seal.json 路径吊销
    code, out, _ = _run(["trust", "revoke", seal_path, "--seal",
                         "--keys-file", keys_file, "--reason", "incident"], capsys)
    assert code == 0 and json.loads(out)

    # 吊销后验签必须被判 E_SEAL_REVOKED（verdict=INVALID，trust=revoked 便于人读）
    code, out, _ = _run(["verify", seal_path, "--keys", keys_file], capsys)
    doc = json.loads(out)
    assert code == 1 and doc["verdict"] == "INVALID"
    assert doc["reason"] == "E_SEAL_REVOKED" and doc["trust"] == "revoked"

    # 翻出：恢复后重新 VALID
    code, out, _ = _run(["trust", "restore", seal_id, "--keys-file", keys_file], capsys)
    assert code == 0
    code, out, _ = _run(["verify", seal_path, "--keys", keys_file], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "VALID"

    # 恢复不存在的 seal_id → 1
    code, _, err = _run(["trust", "restore", "seal-nope", "--keys-file", keys_file], capsys)
    assert code == 1 and "回滚失败" in err


def test_revoke_seal_from_broken_file(tmp_path, capsys):
    keys_file = str(tmp_path / "trusted_keys.json")
    bogus = _write_json(tmp_path / "bogus.seal.json", {"seal_header": {}})
    code, _, err = _run(["trust", "revoke", bogus, "--seal", "--keys-file", keys_file], capsys)
    assert code == 1 and "吊销失败" in err


# ------------------------------------------------------------------ 入口

def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "swordholder" in capsys.readouterr().out


def test_missing_subcommand_exits_2():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_dunder_main_runs(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["swordholder", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("swordholder.__main__", run_name="__main__")
    assert exc.value.code == 0
