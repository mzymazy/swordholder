"""把策略变更门禁（scripts/regress_policy.py）接进 pytest，让 CI 自动守门。

判定规则已经外置到 swordholder/policy/*.yaml，改 YAML 就等于改系统行为。
这里保证两件事永远成立：
1. 案例库完整性没被悄悄动过（digest 与 manifest 一致）；
2. 当前生效策略跑下来 6 条案例全部符合人工确认过的期望。
"""

import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "regress_policy.py")
sys.path.insert(0, ROOT)


def _load_module():
    spec = importlib.util.spec_from_file_location("regress_policy", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def regress():
    if not os.path.exists(SCRIPT):
        pytest.skip("缺少 scripts/regress_policy.py")
    return _load_module()


def test_case_library_is_frozen(regress):
    """案例库必须全部登记在 manifest 里，且 digest 一致。"""
    cases = regress.load_cases()
    assert len(cases) >= 6, f"案例太少，基线不足以守住策略：{len(cases)}"
    problems = regress.check_integrity(cases)
    assert not problems, "案例库完整性校验未通过：" + "；".join(problems)


def test_every_case_declares_a_signer(regress):
    """每条案例都要有人工签名痕迹，否则不能作为判据。"""
    for c in regress.load_cases():
        assert c.get("signed_by"), f"{c['_file']} 缺 signed_by"
        assert c.get("signed_at"), f"{c['_file']} 缺 signed_at"
        assert c.get("why"), f"{c['_file']} 缺 why（写清为什么这条案例值得守）"


def test_default_policy_passes_all_cases(regress):
    """默认策略必须 6/6 通过；任何一条失败都说明策略改动破坏了已确认的行为。"""
    assert regress.main([]) == 0


def test_manifest_hashes_match_files(regress):
    """manifest 里的每一条都要能对上磁盘文件，且没有孤立条目。"""
    with open(regress.MANIFEST, encoding="utf-8") as f:
        man = json.load(f)
    cases = {c["_file"]: c["_sha256"] for c in regress.load_cases()}
    assert set(man["cases"]) == set(cases), "manifest 与磁盘案例不一致"
    for name, digest in cases.items():
        assert man["cases"][name] == digest, f"{name} digest 不匹配"
