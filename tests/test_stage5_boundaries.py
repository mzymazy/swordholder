"""S5 边界断言：把第五阶段的三条结论钉成测试，防止以后悄悄回退。

1. 凭证文件不存在必须返回 ``verdict=INVALID`` + ``E_SEAL_NOT_FOUND``（旧行为返回 ``ok=False``，
   调用方按 ``res["verdict"]`` 判定时会直接 KeyError，等于最该 fail-closed 的路径绕过了契约）。
2. ``import swordholder`` 不得把网络栈拉进进程（``rules.py`` 曾经在模块顶层 ``import urllib.request``）。
3. 轨迹篡改必须给出**被改的那一步**的步号（单凭证覆盖全链的定位能力）。
"""

import json
import os
import subprocess
import sys

import pytest

from swordholder import core, trace_ledger


# ---------------------------------------------------------------- 1. 不存在的凭证

def test_missing_seal_returns_structured_refusal(tmp_path):
    missing = str(tmp_path / "not-there.seal.json")
    res = core.verify(missing, keys_path=None)
    assert res["verdict"] == "INVALID", res
    assert res["reason"] == "E_SEAL_NOT_FOUND", res


# ---------------------------------------------------------------- 2. 导入期零网络栈

def test_import_does_not_pull_network_stack():
    code = (
        "import sys, swordholder, swordholder.core, swordholder.rules, swordholder.trace_ledger\n"
        "mods = ('ssl', 'http.client', 'urllib.request', 'asyncio',\n"
        "        'requests', 'urllib3', 'httpx', 'aiohttp')\n"
        "print(','.join(m for m in mods if m in sys.modules))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "", f"import 期加载了网络模块: {out.stdout.strip()}"


# ---------------------------------------------------------------- 3. 步级定位

TRUST_TEMPLATE = {"trust_root": "test-s5", "keys": [{
    "key_id": "test-s5-001", "algorithm": "ed25519", "public_key_hex": None}]}


def _trace(n):
    led = trace_ledger.TraceLedger(trace_id="TEST-S5", actor="test:s5")
    for i in range(n):
        led.append("get_process_tree", {"pid": 100 + i}, {"ok": True, "weight": i})
    return led.body()


def _write_trust(tmp_path, pub_hex):
    doc = json.loads(json.dumps(TRUST_TEMPLATE))
    doc["keys"][0]["public_key_hex"] = pub_hex
    p = tmp_path / "trusted_keys.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("index", [0, 3, 7])
def test_first_break_points_at_tampered_step(tmp_path, index):
    keys = core.keygen(out_dir=str(tmp_path / "keys"))
    trust = _write_trust(tmp_path, keys["public_key_hex"])

    body = _trace(10)
    seal_path = str(tmp_path / "trace.seal.json")
    trace_ledger.seal_trace(body, keys["private_key_path"], "test-s5", out_path=seal_path)

    ok = trace_ledger.verify_sealed_trace(body, seal_path, keys_path=trust)
    assert ok["verdict"] == "VALID", ok

    body["entries"][index]["observation"]["ok"] = False
    bad = trace_ledger.verify_sealed_trace(body, seal_path, keys_path=trust)
    assert bad["verdict"] == "INVALID", bad
    assert bad["chain"]["first_break"] == index, bad["chain"]


def test_truncation_is_caught_at_credential_level(tmp_path):
    keys = core.keygen(out_dir=str(tmp_path / "keys"))
    trust = _write_trust(tmp_path, keys["public_key_hex"])

    body = _trace(10)
    seal_path = str(tmp_path / "trace.seal.json")
    trace_ledger.seal_trace(body, keys["private_key_path"], "test-s5", out_path=seal_path)

    # 砍掉尾部 3 步并同步改声明（step_count / head），让**剩下部分的链自洽**——
    # 这时链层已经看不出问题，只有凭证层（头与摘要不匹配）能拦住。若不改声明，
    # 链层自己就会以 E_TRACE_BREAK: step_count 不符 拒绝，那是另一条路径，不是本测试要的。
    del body["entries"][7:]
    body["step_count"] = len(body["entries"])
    body["head"] = body["entries"][-1]["hash"]
    res = trace_ledger.verify_sealed_trace(body, seal_path, keys_path=trust)
    assert res["verdict"] == "INVALID", res
    assert res["reason"] == "E_TRACE_HEAD_MISMATCH", res
