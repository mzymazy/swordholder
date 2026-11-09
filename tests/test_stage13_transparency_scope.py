# -*- coding: utf-8 -*-
"""S13 测试：透明日志锚定（离线段）+ 交付范围分账。

网络部分（真实提交到 Rekor / 用日志公钥验 SET）不在单测里跑——联网断言会变成
环境测试。这里锁死三件**不联网也必须成立**的事：

1. 锚点声明是规范 JSON，摘要稳定；改一个字节摘要就变（否则"重做可发现"是假的）；
2. FileBackend 只追加、可按摘要反查；对外部性的宣称**不冒充**（external=False）；
3. 回执核验的判据是合取：external=False 或 present=False 时绝不返回
   externally_checkable=True；hold 回执时 detect_rework 能认出重做，没回执时
   如实返回"查不出"而不是猜。
4. 交付范围分账：清单能覆盖仓库全部待提交文件，少交/多交/忽略不解释三种作弊被
   机械检出。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from swordholder import transparency as tp  # noqa: E402


# ------------------------------------------------------------------ 锚点声明
def test_anchor_doc_is_canonical_and_digest_stable():
    doc = tp.anchor_document(trace_id="T-1", seal_sha256="a" * 64,
                             tsa_token_sha256="b" * 64,
                             tsa_gen_time="20261109120000Z",
                             tsa_url="https://example.invalid/tsr")
    dig1 = tp.anchor_digest(doc)
    dig2 = tp.anchor_digest(dict(reversed(list(doc.items()))))
    assert dig1 == dig2, "键序不同必须得到同一摘要（规范 JSON）"
    assert dig1 == tp.sha256_bytes(tp.canonical_json(doc))
    # 规范字节必须紧凑：键值分隔用 ":"，逗号后不留空格（任何空格漂移都会换摘要）
    raw = tp.canonical_json(doc)
    assert b'": ' not in raw and b", " not in raw and b"\n" not in raw
    assert json.loads(raw.decode("utf-8")) == doc


def test_anchor_digest_changes_when_any_field_changes():
    base = tp.anchor_document(trace_id="T-1", seal_sha256="a" * 64,
                             tsa_token_sha256=None, tsa_gen_time=None, tsa_url=None)
    other = tp.anchor_document(trace_id="T-1", seal_sha256="a" * 63 + "c",
                               tsa_token_sha256=None, tsa_gen_time=None, tsa_url=None)
    assert tp.anchor_digest(base) != tp.anchor_digest(other)


def test_statement_carries_no_body_content():
    """日志是公开的：声明里只能有标识与摘要，不能带凭证正文。"""
    doc = tp.anchor_document(trace_id="T-1", seal_sha256="a" * 64,
                             tsa_token_sha256="b" * 64, tsa_gen_time="Z", tsa_url="u")
    dumped = json.dumps(doc, ensure_ascii=False)
    assert "payload" not in dumped and "entries" not in dumped
    assert doc["schema"].startswith("swordholder.anchor_statement/")


# ------------------------------------------------------------------ 后端
def test_null_backend_never_claims_external():
    be = tp.make_backend("none")
    assert be.external is False
    art, signer = b"x", tp.AnchorSigner.generate()
    with pytest.raises(tp.TransparencyError):
        be.submit(art, signer, trace_id="T")


def test_file_backend_is_append_only_and_idempotent(tmp_path):
    path = str(tmp_path / "log.jsonl")
    be = tp.make_backend("file", file_path=path)
    assert be.external is False, "本机文件只是桩，绝不能说成外部日志"
    signer = tp.AnchorSigner.generate()
    art = b'{"a":1}'
    r1 = be.submit(art, signer, trace_id="T-1")
    r2 = be.submit(art, signer, trace_id="T-1")
    # 同一份内容重复提交按幂等处理（与 Rekor 的 409 already exists 语义一致），
    # 但必须留在日志里、可查；不同内容则必须是另一条。
    assert r1["entry_uuid"] == r2["entry_uuid"]
    assert be.search(tp.sha256_bytes(art)) == [r1["entry_uuid"]]
    r3 = be.submit(b'{"a":2}', signer, trace_id="T-1")
    assert r3["entry_uuid"] != r1["entry_uuid"]
    assert be.fetch(r1["entry_uuid"]) is not None
    with open(path, "r", encoding="utf-8") as fh:
        assert len([l for l in fh.read().splitlines() if l.strip()]) == 2


def test_file_backend_receipt_is_not_externally_checkable(tmp_path):
    be = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    art = b'{"a":2}'
    rec = be.submit(art, tp.AnchorSigner.generate(), trace_id="T-2")
    chk = tp.verify_receipt(rec, art, backend=be, fetch=True)
    assert chk["digest_match"] is True
    assert chk["external"] is False
    assert chk["externally_checkable"] is False, "本机桩不得被算作外部可核验"


def test_verify_receipt_rejects_tampered_artifact(tmp_path):
    be = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    art = b'{"a":3}'
    rec = be.submit(art, tp.AnchorSigner.generate(), trace_id="T-3")
    chk = tp.verify_receipt(rec, art + b" ", backend=be, fetch=True)
    assert chk["digest_match"] is False
    assert chk["externally_checkable"] is False


def test_verify_receipt_missing_entry_not_checkable(tmp_path):
    be = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    art = b'{"a":4}'
    rec = be.submit(art, tp.AnchorSigner.generate(), trace_id="T-4")
    os.remove(os.path.join(str(tmp_path), "log.jsonl"))  # 日志被删
    be2 = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    chk = tp.verify_receipt(rec, art, backend=be2, fetch=True)
    assert chk["present"] is False
    assert chk["externally_checkable"] is False


# ------------------------------------------------------------------ 重做可发现
def test_detect_rework_without_receipt_is_honest():
    """手里没有历史回执时，重做不可发现——必须如实说查不出，不许猜。"""
    out = tp.detect_rework(None, b'{"x":1}')
    assert out["detectable"] is False
    assert "E_TLOG_NO_PRIOR_RECEIPT" in str(out["reason"])


def test_detect_rework_flags_rewritten_artifact(tmp_path):
    be = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    original = b'{"entries":[1,2,3]}'
    rec = be.submit(original, tp.AnchorSigner.generate(), trace_id="T-5")
    same = tp.detect_rework(rec, original, backend=be)
    assert same["detectable"] is False and same["mismatch"] is False
    forged = tp.detect_rework(rec, b'{"entries":[1,2,9]}', backend=be)
    assert forged["mismatch"] is True and forged["detectable"] is True


def test_receipt_json_roundtrip(tmp_path):
    be = tp.make_backend("file", file_path=str(tmp_path / "log.jsonl"))
    rec = be.submit(b'{"a":5}', tp.AnchorSigner.generate(), trace_id="T-6")
    path = tp.save_receipt(rec, str(tmp_path / "r.json"))
    back = tp.load_receipt(path)
    assert back["entry_uuid"] == rec["entry_uuid"]
    assert tp.receipt_to_json(back) == tp.receipt_to_json(rec)


# ------------------------------------------------------------------ 范围分账
def _manifest13():
    sys.path.insert(0, os.path.join(REPO, "scripts", "stage13"))
    import build_manifest13 as bm  # noqa: PLC0415

    return bm


def _git(root, *args):
    res = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=120)
    assert res.returncode == 0, res.stderr.decode("utf-8", "replace")
    return res.stdout.decode("utf-8", "replace")


def _declared_and_manifest():
    """按 stage13 构建脚本的同一口径拿清单，并返回「清单实际声明的路径」。"""
    from swordholder import reproduce as rp  # noqa: PLC0415

    bm = _manifest13()
    paths = list(rp.collect(REPO, bm.DELIVERY))
    m = rp.build_manifest(REPO, paths, hash_mode=rp.HASH_MODE_CANONICAL,
                          tracked_only=True, delivery_prefixes=bm.DELIVERY,
                          ignored_explained=bm.IGNORED_EXPLAINED)
    return bm, m, [f["path"] for f in m["files"]]


def test_scope_ledger_covers_every_committable_file():
    bm, m, declared = _declared_and_manifest()
    scope = m["extra"]["scope"]
    assert scope["ok"] is True, scope
    assert scope["declared_count"] == m["file_count"] == len(declared)
    assert scope["ignored_unexplained"] == []
    assert scope["not_in_repo"] == [] and scope["delivery_missing"] == []
    # 分账两半必须覆盖整个 universe（不留第三条暗道）
    assert scope["declared_count"] + scope["out_of_scope_count"] == scope["universe_count"]
    assert scope["universe_count"] >= scope["tracked_count"]


def test_scope_ledger_negative_cases():
    from swordholder import reproduce as rp  # noqa: PLC0415

    bm, m, declared = _declared_and_manifest()

    # ① 少交一个文件：交付前缀内出现缺口，必须点名
    under = rp.scope_report(REPO, declared[:-1], delivery_prefixes=bm.DELIVERY,
                            included_ignored=bm.IGNORED_EXPLAINED)
    assert under["ok"] is False and under["delivery_missing"] == [declared[-1]]

    # ② 忽略项不解释：必须报 unexplained
    noisy = rp.scope_report(REPO, declared, delivery_prefixes=bm.DELIVERY,
                            included_ignored=[])
    assert noisy["ok"] is False
    assert noisy["ignored_unexplained"] == bm.IGNORED_EXPLAINED

    # ③ 塞入不存在的文件：不许被静默忽略
    over = rp.scope_report(REPO, declared + ["swordholder/ghost_module.py"],
                           delivery_prefixes=bm.DELIVERY,
                           included_ignored=bm.IGNORED_EXPLAINED)
    assert over["ok"] is False and over["not_in_repo"] == ["swordholder/ghost_module.py"]

    # ④ 运行期产物（__pycache__/*.pyc）不算「需解释的忽略项」，否则真实排除项被淹没
    assert rp.is_intrinsic_ignored("swordholder/__pycache__/x.cpython-311.pyc") is True
    assert rp.is_intrinsic_ignored("swordholder/samples/alert_02_token.seal.json") is False


def test_external_verify_recomputes_scope_without_importing_project(tmp_path):
    """审计方那条路径：external_verify 不 import 本项目，也要重算得出同一结论。"""
    from swordholder import reproduce as rp  # noqa: PLC0415

    bm, m, declared = _declared_and_manifest()
    m = dict(m, extra=dict(m["extra"]))
    m["git"] = {}
    mpath = str(tmp_path / "m.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(m, fh)
    out = str(tmp_path / "report.json")
    res = subprocess.run([sys.executable, "-I",
                          os.path.join(REPO, "scripts", "stage11", "external_verify.py"),
                          "--manifest", mpath, "--root", REPO, "--check-scope",
                          "--json-out", out], capture_output=True, timeout=600)
    doc = json.load(open(out, encoding="utf-8"))
    assert doc["scope"]["ok"] is True, doc["scope"]
    assert doc["hashes"]["ok"] is True
    assert res.returncode == 0

    # 篡改清单里的一个哈希：必须被逐文件比对抓到
    m["files"][0] = dict(m["files"][0], sha256="0" * 64)
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(m, fh)
    res2 = subprocess.run([sys.executable, "-I",
                           os.path.join(REPO, "scripts", "stage11", "external_verify.py"),
                           "--manifest", mpath, "--root", REPO, "--check-scope",
                           "--json-out", out], capture_output=True, timeout=600)
    doc2 = json.load(open(out, encoding="utf-8"))
    assert doc2["hashes"]["ok"] is False
    assert res2.returncode == 1


def test_run_all_is_stdlib_only_and_help_works_isolated():
    """一键脚本必须能在干净解释器下启动（第三方 clone 里没有额外包）。"""
    import ast  # noqa: PLC0415

    src = open(os.path.join(REPO, "scripts", "stage13", "run_all.py"),
               encoding="utf-8").read()
    mods = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    third_party = {m for m in mods
                   if m not in (set(sys.stdlib_module_names) | {"__future__"})}
    assert third_party == set(), "run_all 只准用标准库，多出来的：%s" % third_party

    res = subprocess.run([sys.executable, "-I",
                          os.path.join(REPO, "scripts", "stage13", "run_all.py"),
                          "--help"], capture_output=True, timeout=120)
    assert res.returncode == 0
