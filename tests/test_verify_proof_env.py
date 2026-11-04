"""verify_proof 失败归因测试（v0.5.1）：环境问题不得被报成"凭证被伪造"。

背景：本机不装 cryptography 的解释器上，原实现把"无法验签"归因为 E_BAD_SIGNATURE，
对外等价于指控"这份凭证是伪造/被篡改的"，而真实原因是环境缺库。安全工具的 fail-closed
是对的（仍不判 VALID），但归因必须正确，否则评审人/用户会误判项目证据造假。
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_proof as vp  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROOF = os.path.join(ROOT, "proofs", "deterrence_proof_baseline_ed25519.yaml")
TRUSTED = os.path.join(ROOT, "trusted_keys.json")


def test_missing_crypto_is_env_error_not_forgery(monkeypatch):
    """缺 cryptography 时：不判 VALID，但报环境错误码，不报 E_BAD_SIGNATURE。"""
    monkeypatch.setattr(vp, "HAS_CRYPTO", False)
    result = vp.verify(PROOF, trusted_keys_path=TRUSTED)
    assert result.startswith("INVALID")
    assert "E_CRYPTO_UNAVAILABLE" in result
    assert "E_BAD_SIGNATURE" not in result


def test_missing_crypto_exit_code_is_2(monkeypatch, capsys):
    """环境类失败退出码 2（用法/环境错误），与"凭证不合格"的 1 区分。"""
    monkeypatch.setattr(vp, "HAS_CRYPTO", False)
    code = vp.main([PROOF, "--trusted-keys", TRUSTED])
    assert code == 2
    err = capsys.readouterr().err
    assert "环境问题" in err


def test_missing_yaml_is_env_error(monkeypatch):
    """缺 pyyaml 时同样归为环境错误。"""
    monkeypatch.setattr(vp, "HAS_YAML", False)
    result = vp.verify(PROOF, trusted_keys_path=TRUSTED)
    assert result == "INVALID E_YAML_REQUIRED"
    monkeypatch.setattr(vp, "HAS_YAML", False)
    assert vp.main([PROOF, "--trusted-keys", TRUSTED]) == 2


def test_broken_yaml_is_bad_yaml_not_bad_signature(tmp_path, monkeypatch):
    """文件不可解析 → E_BAD_YAML，不再甩锅给签名。"""
    bad = tmp_path / "broken.yaml"
    bad.write_text("proof_header: [unclosed\n", encoding="utf-8")
    result = vp.verify(str(bad), trusted_keys_path=TRUSTED)
    assert "E_BAD_YAML" in result
    assert "E_BAD_SIGNATURE" not in result


def test_real_proof_still_valid_with_crypto():
    """归因修正不能改变正常路径：有 cryptography 时真实凭证仍判 VALID。"""
    if not vp.HAS_CRYPTO:
        pytest.skip("当前解释器未安装 cryptography，跳过正向验签")
    assert vp.verify(PROOF, trusted_keys_path=TRUSTED) == "VALID"
