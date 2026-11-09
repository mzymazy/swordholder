"""S12.1：交付清单必须能跨 checkout 复算。

背景（缺陷复盘）：S12 初版清单按"工作区原始字节"记 sha256，且把未被 git 跟踪的
``*.seal.json`` 也写进清单。结果第三方用 ``git archive`` 导出干净树后复算，
10 个文件因 CRLF/LF 差异哈希不符、1 个文件根本取不到，``ok=false``。
本文件把修复后的两条硬约束钉成测试：换行归一、只收跟踪文件。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from swordholder import reproduce as rp

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTERNAL_VERIFY = os.path.join(REPO, "scripts", "stage11", "external_verify.py")


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def test_canonical_hash_ignores_line_ending_style(tmp_path):
    body = b"alpha\nbeta\ngamma\n"
    crlf = _write(str(tmp_path / "crlf.txt"), body.replace(b"\n", b"\r\n"))
    lf = _write(str(tmp_path / "lf.txt"), body)
    assert rp.sha256_canonical_file(crlf) == rp.sha256_canonical_file(lf)
    assert rp.sha256_raw_file(crlf) != rp.sha256_raw_file(lf)


def test_canonical_hash_still_catches_content_change(tmp_path):
    lf = _write(str(tmp_path / "a.txt"), b"alpha\nbeta\n")
    changed = _write(str(tmp_path / "b.txt"), b"alpha\nbeta!\n")
    assert rp.sha256_canonical_file(lf) != rp.sha256_canonical_file(changed)


def test_manifest_canonical_verifies_across_eol_styles(tmp_path):
    crlf_dir = tmp_path / "crlf"
    lf_dir = tmp_path / "lf"
    body = b"one\ntwo\nthree\n"
    crlf = _write(str(crlf_dir / "m.txt"), body.replace(b"\n", b"\r\n"))
    _write(str(lf_dir / "m.txt"), body)
    manifest = rp.build_manifest(str(crlf_dir), [crlf], include_git=False,
                                 hash_mode=rp.HASH_MODE_CANONICAL)
    verdict = rp.verify_manifest(manifest, str(lf_dir))
    assert verdict["ok"] is True
    assert verdict["mismatched"] == []
    assert verdict["hash_mode"] == rp.HASH_MODE_CANONICAL


def test_raw_manifest_is_eol_sensitive(tmp_path):
    crlf_dir = tmp_path / "crlf"
    lf_dir = tmp_path / "lf"
    body = b"one\ntwo\nthree\n"
    crlf = _write(str(crlf_dir / "m.txt"), body.replace(b"\n", b"\r\n"))
    _write(str(lf_dir / "m.txt"), body)
    manifest = rp.build_manifest(str(crlf_dir), [crlf], include_git=False,
                                 hash_mode=rp.HASH_MODE_RAW)
    verdict = rp.verify_manifest(manifest, str(lf_dir))
    assert verdict["ok"] is False
    assert len(verdict["mismatched"]) == 1
    assert verdict["mismatched"][0]["eol_only"] is True


def test_manifest_records_hash_mode(tmp_path):
    f = _write(str(tmp_path / "a.txt"), b"x\n")
    manifest = rp.build_manifest(str(tmp_path), [f], include_git=False)
    assert manifest["hash_mode"] == rp.HASH_MODE_CANONICAL
    assert manifest["files"][0]["sha256"] == rp.sha256_canonical_file(f)[0]


def _git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True)


@pytest.mark.skipif(_git(["--version"], REPO).returncode != 0, reason="需要 git")
def test_tracked_only_excludes_untracked_product(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q"], str(repo))
    _git(["config", "user.email", "t@example.com"], str(repo))
    _git(["config", "user.name", "t"], str(repo))
    _write(str(repo / ".gitignore"), b"*.seal.json\n")
    _write(str(repo / "pkg" / "mod.py"), b"X = 1\n")
    _git(["add", "."], str(repo))
    _git(["commit", "-q", "-m", "base"], str(repo))
    leak = _write(str(repo / "pkg" / "tok.seal.json"), b'{"seal": 1}\n')

    tracked = rp.collect(str(repo), ["pkg/"])
    manifest = rp.build_manifest(str(repo), tracked, include_git=False, tracked_only=True)
    paths = {item["path"] for item in manifest["files"]}
    assert "pkg/mod.py" in paths
    assert "pkg/tok.seal.json" not in paths
    assert manifest["extra"]["tracked_only"] is True
    assert manifest["extra"]["untracked_excluded"] == ["pkg/tok.seal.json"]
    assert os.path.exists(leak)


@pytest.mark.skipif(_git(["--version"], REPO).returncode != 0, reason="需要 git")
def test_archive_export_tree_recomputes_same_digest(tmp_path):
    """``git archive`` 导出树 = 第三方真实取得路径，必须能复算出同一整树摘要。"""
    if _git(["rev-parse", "--verify", "HEAD"], REPO).returncode != 0:
        pytest.skip("仓库尚无提交")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q"], str(repo))
    _git(["config", "user.email", "t@example.com"], str(repo))
    _git(["config", "user.name", "t"], str(repo))
    _git(["config", "core.autocrlf", "false"], str(repo))
    _write(str(repo / "pkg" / "mod.py"), b"X = 1\nY = 2\n")
    _git(["add", "."], str(repo))
    _git(["commit", "-q", "-m", "base"], str(repo))
    # 工作区故意写成 CRLF，模拟 Windows 检出
    _write(str(repo / "pkg" / "mod.py"), b"X = 1\r\nY = 2\r\n")

    tracked = rp.collect(str(repo), ["pkg/"])
    manifest = rp.build_manifest(str(repo), tracked, include_git=False,
                                 hash_mode=rp.HASH_MODE_CANONICAL, tracked_only=True)
    export = tmp_path / "export"
    export.mkdir()
    tar = _git(["archive", "--format=tar", "HEAD"], str(repo))
    assert tar.returncode == 0
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(tar.stdout), mode="r:") as tf:
        tf.extractall(str(export))
    verdict = rp.verify_manifest(manifest, str(export))
    assert verdict["ok"] is True
    assert verdict["tree_digest_match"] is True
    assert verdict["checked"] == len(manifest["files"])


@pytest.mark.skipif(not os.path.exists(EXTERNAL_VERIFY), reason="缺少外部复算脚本")
def test_external_verify_honours_manifest_hash_mode(tmp_path):
    body = b"one\ntwo\n"
    crlf = _write(str(tmp_path / "src" / "m.txt"), body.replace(b"\n", b"\r\n"))
    _write(str(tmp_path / "dst" / "m.txt"), body)  # 相当于 LF 检出 / archive 导出
    manifest = rp.build_manifest(str(tmp_path / "src"), [crlf], include_git=False,
                                 hash_mode=rp.HASH_MODE_CANONICAL)
    mpath = tmp_path / "m.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    out_json = tmp_path / "out.json"
    proc = subprocess.run([sys.executable, "-I", EXTERNAL_VERIFY, "--manifest", str(mpath),
                           "--root", str(tmp_path / "dst"), "--json-out", str(out_json)],
                          capture_output=True)
    assert proc.returncode == 0, (proc.stdout or b"").decode("utf-8", "replace")
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["hashes"]["hash_mode"] == rp.HASH_MODE_CANONICAL
    assert report["hashes"]["ok"] is True


@pytest.mark.skipif(not os.path.exists(EXTERNAL_VERIFY), reason="缺少外部复算脚本")
def test_external_verify_defaults_to_raw_for_legacy_manifest(tmp_path):
    """老清单没有 hash_mode 字段，必须仍按原始字节比对（口径不能被静默改宽）。"""
    _write(str(tmp_path / "src" / "m.txt"), b"one\ntwo\n")
    manifest = rp.build_manifest(str(tmp_path / "src"), [str(tmp_path / "src" / "m.txt")],
                                 include_git=False, hash_mode=rp.HASH_MODE_RAW)
    manifest.pop("hash_mode", None)
    mpath = tmp_path / "m.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    _write(str(tmp_path / "dst" / "m.txt"), b"one\ntwo\n")
    ok_json = tmp_path / "ok.json"
    proc = subprocess.run([sys.executable, "-I", EXTERNAL_VERIFY, "--manifest", str(mpath),
                           "--root", str(tmp_path / "dst"), "--json-out", str(ok_json)],
                          capture_output=True)
    assert proc.returncode == 0
    assert json.loads(ok_json.read_text(encoding="utf-8"))["hashes"]["hash_mode"] == "raw"

    _write(str(tmp_path / "dst" / "m.txt"), b"one\ntwo\r\n")  # 只差换行
    bad_json = tmp_path / "bad.json"
    proc = subprocess.run([sys.executable, "-I", EXTERNAL_VERIFY, "--manifest", str(mpath),
                           "--root", str(tmp_path / "dst"), "--json-out", str(bad_json)],
                          capture_output=True)
    assert proc.returncode != 0
    report = json.loads(bad_json.read_text(encoding="utf-8"))
    assert report["hashes"]["mismatched"][0]["eol_only"] is True
