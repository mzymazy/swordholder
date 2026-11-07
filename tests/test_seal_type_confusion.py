"""凭证验签的类型混淆与结构畸形路径（S3 回归）。

背景：S2 阶段的篡改基准把 ``seal["signature"]`` 整块替换成字符串 "deadbeef" 时，
验签端抛的是 ``AttributeError`` 而不是拒绝码。崩溃被基准记成了"检出"，等于用
异常冒充了安全结论。本文件钉住三件事：

1. 签名块类型被混淆时，必须给出 ``INVALID / E_MALFORMED_SEAL``，不得抛异常；
2. 签名值不是合法 base64 时，也必须归为结构问题（``E_MALFORMED_SEAL``），
   与"签名字节不对"（``E_BAD_SIGNATURE``）区分开；
3. 真正被签名字段（``seal_header`` 内的 subject/issuer/created_at）被改，
   必须判 ``E_BAD_SIGNATURE`` —— 这是"subject 绑定"该有的正确验证位置。
"""

import base64
import json

import pytest

from swordholder import core


@pytest.fixture()
def sealed(tmp_path):
    keys = core.keygen(str(tmp_path / "keys"))
    record = {"alert_id": "A-1", "verdict": "true_positive", "confidence": 0.9}
    out = str(tmp_path / "rec.seal.json")
    res = core.seal(record, keys["private_key_path"], "test-issuer",
                    out_path=out, challenge="chal-2026-11-08-abc")
    return res["seal_path"], str(tmp_path / "keys" / "trusted_keys.json"), keys


def _mutate(path, fn, tag):
    data = json.loads(open(path, encoding="utf-8").read())
    fn(data)
    p = path.replace(".seal.json", f".{tag}.seal.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return p


def _verify(seal_path, keys_path, **kw):
    # 先确保信任锚存在，避免落到 VALID_UNTRUSTED_KEY 干扰断言
    return core.verify(seal_path, keys_path=keys_path, **kw)


def _trust(keys, tmp_path):
    """把签发公钥登记进信任锚文件。"""
    tp = tmp_path / "trust.json"
    tp.write_text(json.dumps({"keys": [{"public_key_hex": keys["public_key_hex"],
                                        "issuer": "test-issuer",
                                        "key_id": "test-key",
                                        "status": "active"}]}), encoding="utf-8")
    return str(tp)


@pytest.mark.parametrize("payload", ["deadbeef", 123, [], None, {"value": 123},
                                     {"value": ""}, {"value": base64.b64encode(b"\x00" * 64).decode() + "!!"}])
def test_signature_block_type_confusion_is_structured_rejection(sealed, tmp_path, payload):
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["signature"] = payload

    p = _mutate(path, fn, "sigconf")
    res = _verify(p, tp)  # 不得抛异常
    assert res["verdict"] == "INVALID"
    assert str(res["reason"]).startswith("E_")
    if not isinstance(payload, dict):
        # 非对象整块替换由验签端的类型门挡住（schema 之前）
        assert res["reason"] == "E_MALFORMED_SEAL"


def test_signature_not_base64_is_malformed(sealed, tmp_path):
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["signature"]["value"] = "!!!not-base64!!!"

    p = _mutate(path, fn, "sigb64")
    res = _verify(p, tp)
    assert res["verdict"] == "INVALID"
    # 非 base64 归为结构问题或 schema 拒收，二者皆为 fail-closed 的结构化拒绝
    assert res["reason"] in ("E_MALFORMED_SEAL", "E_SCHEMA_INVALID")


def test_header_not_object_is_malformed(sealed, tmp_path):
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["seal_header"] = "not-an-object"

    p = _mutate(path, fn, "hdrconf")
    res = _verify(p, tp)
    assert res["verdict"] == "INVALID"
    assert res["reason"] in ("E_MALFORMED_SEAL", "E_SCHEMA_INVALID")


@pytest.mark.parametrize("field,value", [("subject", "tampered-subject"),
                                         ("issuer", "evil-issuer"),
                                         ("created_at", "2020-01-01T00:00:00Z"),
                                         ("record_ref", "/etc/passwd")])
def test_signed_header_fields_are_signature_bound(sealed, tmp_path, field, value):
    """subject 等 header 字段被签名字节覆盖，改动必然打穿签名。"""
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["seal_header"][field] = value

    p = _mutate(path, fn, "hdr_" + field)
    res = _verify(p, tp)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_BAD_SIGNATURE"


def test_payload_field_swap_is_payload_tampered(sealed, tmp_path):
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["payload"]["verdict"] = "false_positive"

    p = _mutate(path, fn, "payload_flip")
    res = _verify(p, tp)
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_PAYLOAD_TAMPERED"


def test_top_level_unsigned_extra_key_does_not_forge_signed_content(sealed, tmp_path):
    """未签名的外层附注可以随便加 —— 但不得改变已签内容与验签结论。

    这是已知边界（不是漏洞把戏）：凭证的可验证范围是 header+payload，
    外层附注不在承诺范围内，下游不得把它当可信元数据使用。
    """
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["subject"] = "tampered-subject"

    p = _mutate(path, fn, "outer_subject")
    res = _verify(p, tp)
    assert res["verdict"] == "VALID"
    assert res["subject"] == "A-1"  # 结论仍取自已签名 header，不取外层附注


def test_top_level_unsigned_extra_key_raises_warning(sealed, tmp_path):
    """外层附注虽然改不了判定，但必须显式告警，不能静默通过。

    S3 之前这里没有任何提示：往顶层塞一个 ``subject`` 就能让人以为签发对象变了，
    而验签输出与正常凭证一模一样。现在多给一条 ``W_OUTER_FIELDS_UNSIGNED``。
    """
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)

    def fn(d):
        d["subject"] = "tampered-subject"
        d["issuer"] = "evil-issuer"

    p = _mutate(path, fn, "outer_subject_warn")
    res = _verify(p, tp)
    assert res["verdict"] == "VALID"
    codes = [w["code"] for w in res.get("warnings", [])]
    assert "W_OUTER_FIELDS_UNSIGNED" in codes
    warned = [w for w in res["warnings"] if w["code"] == "W_OUTER_FIELDS_UNSIGNED"][0]
    assert warned["fields"] == ["issuer", "subject"]  # 排序后给出，便于比对


def test_clean_seal_has_no_warning(sealed, tmp_path):
    """正常凭证不得凭空多出 warning，否则告警会被无视。"""
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)
    res = _verify(path, tp)
    assert res["verdict"] == "VALID"
    assert not res.get("warnings")


def test_replay_binding_mismatch(sealed, tmp_path):
    path, _ks, keys = sealed
    tp = _trust(keys, tmp_path)
    res = _verify(path, tp, expected_challenge="chal-2026-11-08-other")
    assert res["verdict"] == "INVALID"
    assert res["reason"] == "E_CHALLENGE_MISMATCH"
