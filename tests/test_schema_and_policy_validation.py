"""凭证契约与策略包校验的负例覆盖（S6）。

这两层都是 fail-closed 的守门人：写错一个字段名就等于静默关掉一条防线，
所以每个 _fail 分支都必须有一条用例钉住"它确实会拒"。
"""

from __future__ import annotations

import copy
import json

import pytest

from swordholder import policy_loader, seal_schema


# ------------------------------------------------------------------ seal_schema

def _valid_seal():
    return {
        "seal_header": {
            "seal_version": "1.0",
            "seal_id": "11111111-2222-3333-4444-555555555555",
            "algorithm": "ed25519",
            "created_at": "2026-11-08T00:00:00Z",
            "issuer": "soc@test",
            "subject": "ALRT-1",
            "payload_sha256": "a" * 64,
            "signature": "A" * 88,
            "key_id": None,
        },
        "payload": {"alert_id": "ALRT-1"},
    }


def test_validate_accepts_real_seal(tmp_path):
    from swordholder import core
    out = tmp_path / "keys"
    kg = core.keygen(str(out))
    rec = tmp_path / "r.json"
    rec.write_text(json.dumps({"alert_id": "A", "verdict": "true_positive"}), encoding="utf-8")
    sealed = core.seal(str(rec), kg["private_key_path"], "soc@test",
                       out_path=str(tmp_path / "r.seal.json"))
    doc = json.load(open(sealed["seal_path"], encoding="utf-8"))
    res = seal_schema.validate(doc)
    assert res["ok"] is True and res["seal_version"] == seal_schema.LATEST_VERSION


def test_validate_rejects_missing_version():
    seal = _valid_seal()
    seal["seal_header"].pop("seal_version")
    res = seal_schema.validate(seal)
    assert res["ok"] is False and res["reason"] == "E_SCHEMA_INVALID"
    assert "seal_version" in res["detail"]


def test_validate_rejects_unknown_version():
    seal = _valid_seal()
    seal["seal_header"]["seal_version"] = "9.9"
    res = seal_schema.validate(seal)
    assert res["ok"] is False and res["reason"] == "E_UNSUPPORTED_SEAL_VERSION"


def test_validate_rejects_non_dict():
    assert seal_schema.validate("not-a-seal")["reason"] == "E_SCHEMA_INVALID"
    assert seal_schema.validate({"seal_header": "x"})["reason"] == "E_SCHEMA_INVALID"


def test_validate_rejects_bad_field_types():
    seal = _valid_seal()
    seal["seal_header"]["payload_sha256"] = "short"
    res = seal_schema.validate(seal)
    assert res["ok"] is False and res["reason"] == "E_SCHEMA_INVALID"
    assert res["detail"]


def test_validate_reports_validator_unavailable(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "jsonschema":
            raise ImportError("no jsonschema")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    res = seal_schema.validate(_valid_seal())
    assert res["ok"] is False and res["reason"] == "E_VALIDATOR_UNAVAILABLE"


def test_schema_helpers():
    assert seal_schema.seal_version_of(None) is None
    assert seal_schema.seal_version_of({"seal_header": {}}) is None
    assert seal_schema.seal_version_of({"seal_header": {"seal_version": "1.0"}}) == "1.0"
    assert seal_schema.schema_path("1.0").endswith("seal.schema.json")
    with pytest.raises(seal_schema.SealSchemaError) as e:
        seal_schema.schema_path("0.0")
    assert e.value.reason == "E_UNSUPPORTED_SEAL_VERSION"
    assert json.loads(seal_schema.dumps())["$schema"]


# ------------------------------------------------------------------ policy_loader

def _default():
    return copy.deepcopy(policy_loader.load(None))


@pytest.mark.parametrize("mutate,keyword", [
    (lambda p: p.pop("id"), "缺少必需字段"),
    (lambda p: p.__setitem__("schema", "other/v9"), "schema 不匹配"),
    (lambda p: p.__setitem__("verdicts", []), "verdicts 必须是"),
    (lambda p: p.__setitem__("severities", "high"), "severities 必须是"),
    (lambda p: p.__setitem__("limits", []), "limits 必须是映射"),
    (lambda p: p["limits"].pop("action_max_len"), "limits 缺少"),
    (lambda p: p["limits"].__setitem__("actions_min", -1), "非负整数"),
    (lambda p: p.__setitem__("confidence_text_map", {"high": 1.5}), "必须在 [0,1]"),
    (lambda p: p.__setitem__("confidence_text_map", "nope"), "必须是映射"),
    (lambda p: p.__setitem__("invariants", {}), "invariants 必须是列表"),
    (lambda p: p["invariants"].append("not-a-dict"), "必须是映射"),
    (lambda p: p["invariants"][0].pop("field"), "缺少 field"),
    (lambda p: p["invariants"][0].__setitem__("id", p["invariants"][1]["id"]), "id 重复"),
    (lambda p: p["invariants"][0].__setitem__("require", "made_up"), "不支持"),
    (lambda p: p["invariants"][0].__setitem__("when", "x"), "when 必须是映射"),
    (lambda p: p["invariants"][0]["when"].__setitem__("verdict", "nope"), "不在 verdicts 内"),
    (lambda p: p["invariants"][0]["when"].__setitem__("extra", 1), "含未知键"),
    (lambda p: p["invariants"][0].__setitem__("messages", {}), "必须给出 messages"),
    (lambda p: p["invariants"][2].__setitem__("field", "actionsX"), "必须为 actions"),
    (lambda p: p["invariants"][2].__setitem__("deny_patterns", []), "deny_patterns 必须"),
    (lambda p: p["invariants"][2].__setitem__("deny_patterns", ["[unclosed"]), "正则非法"),
    (lambda p: p["invariants"][2].__setitem__("exempt_when", []), "exempt_when 必须是映射"),
    (lambda p: p["invariants"][2]["exempt_when"].__setitem__("oops", 1), "exempt_when 含未知键"),
])
def test_policy_validate_rejects(mutate, keyword):
    p = _default()
    mutate(p)
    with pytest.raises(policy_loader.PolicyError) as e:
        policy_loader.validate(p, origin="test")
    assert keyword in str(e.value)


def test_policy_session_segment_validation():
    base = _default()
    base["session"] = {"schema": "wrong/v1"}
    with pytest.raises(policy_loader.PolicyError):
        policy_loader.validate(base)

    for seg, kw in [
        ({"turn_budget": -1}, "turn_budget"),
        ({"turn_budget": "5"}, "turn_budget"),
        ({"relax": []}, "relax 必须是映射"),
        ({"relax": {"max_relaxations": -1}}, "max_relaxations"),
        ({"relax": {"require_new_evidence": "yes"}}, "require_new_evidence"),
        ({"rules": "S1_claim_must_be_verified"}, "session.rules 必须是字符串列表"),
        ({"rules": ["NOPE"]}, "未知不变量"),
        ({"claims": {}}, "session.claims 必须是列表"),
        ({"claims": ["x"]}, "必须是映射"),
        ({"claims": [{"patterns": ["a"]}]}, "缺少 id"),
        ({"claims": [{"id": "c1", "patterns": ["a"]}, {"id": "c1", "patterns": ["b"]}]}, "id 重复"),
        ({"claims": [{"id": "c1", "patterns": []}]}, "patterns 必须"),
        ({"claims": [{"id": "c1", "patterns": ["[bad"]}]}, "正则非法"),
        ({"claims": [{"id": "c1", "patterns": ["a"], "keywords": "x"}]}, "keywords 必须是字符串列表"),
        ({"claims": [{"id": "c1", "patterns": ["a"], "verify_tool": 1}]}, "verify_tool"),
    ]:
        p = _default()
        p["session"] = seg
        with pytest.raises(policy_loader.PolicyError) as e:
            policy_loader.validate(p, origin="test")
        assert kw in str(e.value)


def test_policy_load_errors(tmp_path, monkeypatch):
    with pytest.raises(policy_loader.PolicyError) as e:
        policy_loader.load(str(tmp_path / "absent.yaml"))
    assert "不存在" in str(e.value)

    broken = tmp_path / "broken.yaml"
    broken.write_text("id: [unclosed\n", encoding="utf-8")
    with pytest.raises(policy_loader.PolicyError) as e:
        policy_loader.load(str(broken))
    assert "解析失败" in str(e.value) or "schema" in str(e.value)

    monkeypatch.setenv(policy_loader.ENV_VAR, str(tmp_path / "env.yaml"))
    assert policy_loader.resolve_path().endswith("env.yaml")
    monkeypatch.delenv(policy_loader.ENV_VAR)
    assert policy_loader.resolve_path() == policy_loader.DEFAULT_POLICY


def test_policy_list_builtin_and_invalid(tmp_path, monkeypatch):
    listing = policy_loader.list_builtin()
    assert listing and any(item[1] != "<invalid>" for item in listing)

    bad_dir = tmp_path / "policies"
    bad_dir.mkdir()
    (bad_dir / "bad.yaml").write_text("schema: wrong\n", encoding="utf-8")
    (bad_dir / "readme.txt").write_text("ignore me", encoding="utf-8")
    monkeypatch.setattr(policy_loader, "POLICY_DIR", str(bad_dir))
    rows = policy_loader.list_builtin()
    assert len(rows) == 1 and rows[0][1] == "<invalid>"

    monkeypatch.setattr(policy_loader, "POLICY_DIR", str(tmp_path / "nope"))
    assert policy_loader.list_builtin() == []
