# -*- coding: utf-8 -*-
"""verify_scope 的复算回归：清单声明的交付范围必须能被第三方机械重算出来。

``scope_report`` 负责把「交付了什么 / 没交付什么」算成一份可对账的分账，
``verify_scope`` 负责拿清单再复算一遍、逐项判真假——它对第三方是"我只信你声明的，
但我要自己算"。这条路此前没有回归用例，等于只有生产口径没有验收口径。

本文件直接拿仓库自身的真实清单做基线：先证明"自己算自己对得上"，再逐项证明
"任何一项被改动都会被复算抓出来"。
"""

from __future__ import annotations

import copy
import os
import sys

import pytest

from swordholder import reproduce as rp

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _manifest13():
    sys.path.insert(0, os.path.join(REPO, "scripts", "stage13"))
    import build_manifest13 as bm  # noqa: PLC0415

    return bm


@pytest.fixture(scope="module")
def base():
    """按 stage13 同一口径构建真实清单；整份基线只算一次。"""
    bm = _manifest13()
    paths = list(rp.collect(REPO, bm.DELIVERY))
    manifest = rp.build_manifest(REPO, paths, hash_mode=rp.HASH_MODE_CANONICAL,
                                 tracked_only=True, delivery_prefixes=bm.DELIVERY,
                                 ignored_explained=bm.IGNORED_EXPLAINED)
    return bm, manifest


def _verify(manifest: dict, bm) -> dict:
    return rp.verify_scope(manifest, REPO, delivery_prefixes=bm.DELIVERY)


def test_verify_scope_accepts_own_manifest(base):
    bm, manifest = base
    res = _verify(copy.deepcopy(manifest), bm)
    assert res["ok"] is True, res["checks"]
    assert set(res["checks"]) >= {
        "no_unbacked_entries", "no_delivery_gap", "all_out_of_scope_accounted",
        "out_of_scope_content_matches", "content_exclusion_safe",
        "no_untracked_in_repo", "ignored_all_explained", "declared_within_prefixes",
    }
    assert res["recomputed"]["declared_count"] == manifest["file_count"]


def test_verify_scope_detects_tampered_out_of_scope_digest(base):
    """范围外那半的路径摘要被改：分账对不上，必须判失败。"""
    bm, manifest = base
    tampered = copy.deepcopy(manifest)
    tampered["extra"]["scope"]["out_of_scope_digest"] = "0" * 64
    res = _verify(tampered, bm)
    assert res["ok"] is False
    assert res["checks"]["all_out_of_scope_accounted"] is False
    assert res["checks"]["no_delivery_gap"] is True


def test_verify_scope_detects_tampered_out_of_scope_content_digest(base):
    """只改「未交付文件」的内容摘要同样要被抓——否则改个没入册的文件就绕过整册校验。"""
    bm, manifest = base
    tampered = copy.deepcopy(manifest)
    tampered["extra"]["scope"]["out_of_scope_content_digest"] = "f" * 64
    res = _verify(tampered, bm)
    assert res["ok"] is False
    assert res["checks"]["out_of_scope_content_matches"] is False


def test_verify_scope_detects_entry_not_in_repo(base):
    bm, manifest = base
    tampered = copy.deepcopy(manifest)
    tampered["files"].append({"path": "swordholder/ghost_module.py", "sha256": "0" * 64})
    res = _verify(tampered, bm)
    assert res["ok"] is False
    assert res["checks"]["no_unbacked_entries"] is False
    assert res["recomputed"]["not_in_repo"] == ["swordholder/ghost_module.py"]


def test_verify_scope_detects_declared_path_outside_prefixes(base):
    """清单里塞一条交付前缀之外的路径：声明越界，不认。"""
    bm, manifest = base
    tampered = copy.deepcopy(manifest)
    tampered["files"].append({"path": "docs/not_delivered.md", "sha256": "0" * 64})
    res = _verify(tampered, bm)
    assert res["ok"] is False
    assert res["checks"]["declared_within_prefixes"] is False


def test_verify_scope_reports_error_when_root_is_not_a_repo(base, tmp_path):
    """非 git 目录不能静默当"空仓库"通过，要给出结构化错误。"""
    bm, manifest = base
    res = rp.verify_scope(manifest, str(tmp_path), delivery_prefixes=bm.DELIVERY)
    assert res["ok"] is False
    assert "error" in res
