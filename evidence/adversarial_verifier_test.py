# -*- coding: utf-8 -*-
"""
验证器对抗自测 v0.5（17 用例）
=============================
对 verify_proof.py v0.5 做对抗性自测：合法凭证必须放行，各类伪造/篡改/降级/过期/绑定破坏
必须被拒绝并给出正确原因码。全部用例在**临时工作目录**内构造，使用**独立测试信任锚**
（不污染仓库主 trusted_keys.json），其中"过期"用例由测试私钥**真实签发过期时间戳**，
不再使用"签名钥不在锚"的等价替代（修复 CloseAI 报告 X-8/P2-7 指出的自测失真问题）。

结果 JSON：evidence/adversarial_verifier_test_v05.json
退出码：0 = 全部用例符合预期；1 = 存在不符合预期用例
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import re
import tempfile
import uuid
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "evidence" else HERE
OUT_JSON = os.path.join(HERE, "adversarial_verifier_test_v05.json")


def load_verify_module(root):
    path = os.path.join(root, "verify_proof.py")
    spec = importlib.util.spec_from_file_location("verify_proof_v05", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build_artifacts(workdir, n=6):
    """构造最小可校验工件集：结果文件 + artifact 目录（每文件含真实字节）。"""
    art_dir = os.path.join(workdir, "artifacts_demo")
    os.makedirs(art_dir, exist_ok=True)
    for i in range(n):
        with open(os.path.join(art_dir, f"case-{i:02d}.txt"), "w", encoding="utf-8") as f:
            f.write(f"case {i} response sample bytes\n")
    result_path = os.path.join(workdir, "evaluation_results_demo.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump({"model": "qwen3:8b", "suite": "demo"}, f)
    return result_path, art_dir


def make_binding(workdir, result_path, art_dir):
    names = sorted(n for n in os.listdir(art_dir)
                   if os.path.isfile(os.path.join(art_dir, n)))
    lines = "".join("%s\t%s\n" % (n, sha256_bytes(open(os.path.join(art_dir, n), "rb").read()))
                    for n in names)
    return {
        "result_file": os.path.basename(result_path),
        "result_sha256": sha256_bytes(open(result_path, "rb").read()),
        "artifact_dir": os.path.basename(art_dir),
        "artifact_count": len(names),
        "artifact_index_sha256": sha256_bytes(lines.encode("utf-8")),
    }, len(names)


def build_proof(workdir, binding, count, key, pub_hex, issued_at,
                algo="ed25519", sig_override=None, tamper=None):
    doc = {
        "proof_header": {
            "proof_version": "0.1",
            "proof_id": str(uuid.uuid4()),
            "model_id": "qwen3:8b@0.1.0",
            "issuer": "swordholder-eval/0.1.0",
            "issued_at": issued_at,
            "schema_ref": "swordholder-boundary-map.schema.yaml@0.1",
            "signature_alg": algo,
            "canonicalization": "json-c14n-v1",
            "issuance_status": "combined",
            "public_key": pub_hex,
        },
        "evidence": [
            {"test": "recitation", "summary": "s", "metrics": {"exact_match_rate": 0.66},
             "evidence_count": 2, "passed_count": 1, "artifact_ref": "artifacts_demo/case-00.txt"},
            {"test": "behavior", "summary": "s", "metrics": {"refusal_rate": 1.0},
             "evidence_count": 2, "passed_count": 2, "artifact_ref": "artifacts_demo/case-01.txt"},
            {"test": "adversarial", "summary": "s", "metrics": {"injection_success_rate": 0.0},
             "evidence_count": 1, "passed_count": 1, "artifact_ref": "artifacts_demo/case-02.txt"},
            {"test": "reasoning", "summary": "s", "metrics": {"axiom_reference_rate": 1.0},
             "evidence_count": 1, "passed_count": 1, "artifact_ref": "artifacts_demo/case-03.txt"},
        ],
        "artifact_binding": binding,
        "boundary_map": {
            "schema_version": "0.1",
            "boundary_map_ref": "sha256:swordholder-boundary-map-v0.1.yaml",
            "covered_domains": ["data_integrity", "authority", "truthfulness", "supervision"],
        },
    }
    if tamper:
        tamper(doc)
    body = MOD.canonical_body({k: v for k, v in doc.items() if k != "signature"})
    if sig_override is not None:
        doc["signature"] = sig_override(body, doc)
    elif algo == "sha256-demo":
        doc["signature"] = {"alg": "sha256-demo",
                            "value": "sha256-demo:" + sha256_bytes(body)}
    else:
        doc["signature"] = {"alg": "ed25519",
                            "value": base64.b64encode(key.sign(body)).decode("ascii")}
    return doc


def dump_yaml(doc, path, text_override=None):
    if text_override is not None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text_override)
        return
    import yaml
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True, default_flow_style=False)


def main():
    global MOD
    MOD = load_verify_module(REPO_ROOT)
    if not MOD.HAS_CRYPTO:
        print("需要 cryptography：pip install cryptography")
        return 1
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    work = tempfile.mkdtemp(prefix="sh_v05_advtest_")
    result_path, art_dir = build_artifacts(work, n=6)
    binding, art_count = make_binding(work, result_path, art_dir)
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 独立测试信任锚（不污染仓库主 trusted_keys.json）
    test_key = Ed25519PrivateKey.generate()
    test_pub = test_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
    anchor_path = os.path.join(work, "_test_trusted_keys.json")
    with open(anchor_path, "w", encoding="utf-8") as f:
        json.dump({"keys": [{"key_id": "k-test-adv", "algorithm": "ed25519",
                             "public_key_hex": test_pub,
                             "fingerprint_sha256": sha256_bytes(test_pub.encode("ascii")),
                             "note": "对抗自测专用测试锚（临时）"}]}, f)

    other_key = Ed25519PrivateKey.generate()
    other_pub = other_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()

    cases = []

    def run(name, doc, expect, *, trusted=anchor_path, demo=False,
            text_override=None, expect_extra=""):
        p = os.path.join(work, f"{name}.yaml")
        dump_yaml(doc, p, text_override)
        got = MOD.verify(p, allow_demo=demo, trusted_keys_path=trusted,
                         max_age_days=365, base_dir=work)
        ok = got.startswith(expect) and (not expect_extra or expect_extra in got)
        cases.append({"case": name, "expected": (expect + (" " + expect_extra if expect_extra else "")),
                      "actual": got, "pass": bool(ok)})

    # 01 合法凭证（测试锚内）→ VALID（失败路径已展开）
    run("01_legal_ed25519",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at),
        "VALID")

    # 02 伪造 sha256-demo（默认模式拒绝；--demo 放行）
    run("02_forged_sha256demo_default",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at, algo="sha256-demo"),
        "INVALID", expect_extra="E_BAD_SIGNATURE")
    run("03_explicit_demo_mode",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at, algo="sha256-demo"),
        "VALID", demo=True)

    # 04 篡改证据块（先签发合法凭证，签名后再改 passed_count）→ 签名失配
    base_ok = build_proof(work, binding, art_count, test_key, test_pub, issued_at)
    d04 = copy.deepcopy(base_ok)
    d04["evidence"][0]["passed_count"] = 0
    run("04_tampered_evidence", d04, "INVALID", expect_extra="E_BAD_SIGNATURE")

    # 05 篡改 artifact_ref（签名后改引用为不存在文件）→ E_BAD_EVIDENCE
    d05 = copy.deepcopy(base_ok)
    d05["evidence"][1]["artifact_ref"] = "artifacts_demo/no_such_case.txt"
    run("05_tampered_artifact_ref", d05, "INVALID", expect_extra="E_BAD_EVIDENCE")

    # 06 替换公钥（换钥，未命中信任锚）→ E_UNTRUSTED_KEY
    run("06_replaced_public_key",
        build_proof(work, binding, art_count, test_key, other_pub, issued_at),
        "INVALID", expect_extra="E_UNTRUSTED_KEY")

    # 07 算法降级（header 写 ed25519，签名块用 sha256-demo）→ E_BAD_SIGNATURE
    run("07_alg_downgrade",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at,
                    sig_override=lambda body, d: {
                        "alg": "sha256-demo",
                        "value": "sha256-demo:" + sha256_bytes(body)}),
        "INVALID", expect_extra="E_BAD_SIGNATURE")

    # 08 真实过期：测试锚私钥真实签发 400 天前时间戳 → E_STALE_TIMESTAMP
    stale_at = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    run("08_real_expired_400d",
        build_proof(work, binding, art_count, test_key, test_pub, stale_at),
        "INVALID", expect_extra="E_STALE_TIMESTAMP")

    # 09 无信任锚（信任锚文件不存在）→ E_UNTRUSTED_KEY
    run("09_no_trust_anchor",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at),
        "INVALID", trusted=os.path.join(work, "missing_anchor.json"),
        expect_extra="E_UNTRUSTED_KEY")

    # 10 重复顶层键（后块覆盖式伪造）
    doc10 = build_proof(work, binding, art_count, test_key, test_pub, issued_at,
                        algo="sha256-demo")
    import yaml as _y
    dup_text = _y.safe_dump(doc10, sort_keys=False, allow_unicode=True, default_flow_style=False)
    dup_text += "\nproof_header:\n  proof_version: \"0.1\"\n  proof_id: \"x\"\n"
    run("10_duplicate_top_key", doc10, "INVALID", text_override=dup_text,
        expect_extra="E_DUPLICATE_KEY")

    # 11 缺少 artifact_binding 绑定块 → E_BINDING_MISMATCH
    run("11_missing_binding",
        build_proof(work, binding, art_count, test_key, test_pub, issued_at,
                    tamper=lambda d: d.pop("artifact_binding")),
        "INVALID", expect_extra="E_BINDING_MISMATCH")

    # 12 绑定 result_sha256 不符（只改哈希不绑定工件）→ E_BINDING_MISMATCH
    bad12 = copy.deepcopy(binding)
    bad12["result_sha256"] = sha256_bytes(b"forged")
    run("12_binding_result_hash_mismatch",
        build_proof(work, bad12, art_count, test_key, test_pub, issued_at),
        "INVALID", expect_extra="E_BINDING_MISMATCH")

    # 13 绑定 artifact_count 不符 → E_BINDING_MISMATCH
    bad13 = copy.deepcopy(binding)
    bad13["artifact_count"] = art_count + 1
    run("13_binding_count_mismatch",
        build_proof(work, bad13, art_count, test_key, test_pub, issued_at),
        "INVALID", expect_extra="E_BINDING_MISMATCH")

    # 14 非法时间戳（不可解析）→ E_BAD_TIMESTAMP
    run("14_bad_timestamp_literal",
        build_proof(work, binding, art_count, test_key, test_pub, "not-a-date"),
        "INVALID", expect_extra="E_BAD_TIMESTAMP")

    # 15 未来时间戳 → E_BAD_TIMESTAMP
    future_at = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    run("15_future_timestamp",
        build_proof(work, binding, art_count, test_key, test_pub, future_at),
        "INVALID", expect_extra="E_BAD_TIMESTAMP")

    # 16 带引号键重复（行首文本层检测）
    doc16 = build_proof(work, binding, art_count, test_key, test_pub, issued_at,
                        algo="sha256-demo")
    t16 = _y.safe_dump(doc16, sort_keys=False, allow_unicode=True, default_flow_style=False)
    t16 += "\n\"proof_header\":\n  proof_version: \"0.1\"\n"
    run("16_quoted_duplicate_key", doc16, "INVALID", text_override=t16,
        expect_extra="E_DUPLICATE_KEY")

    # 17 流式映射内重复键（构造层检测，文本层行首正则无法捕获）
    raw16 = _y.safe_dump(doc16, sort_keys=False, allow_unicode=True,
                         default_flow_style=False)
    flow_map = ('boundary_map: {schema_version: "0.1", schema_version: "0.1", '
                'boundary_map_ref: "sha256:x", covered_domains: ["data_integrity", '
                '"authority", "truthfulness", "supervision"]}\n')
    t17 = re.sub(r"boundary_map:\n(?:  [^\n]*\n)+", flow_map, raw16)
    run("17_flow_mapping_duplicate_key", doc16, "INVALID",
        text_override=t17, expect_extra="E_DUPLICATE_KEY")

    passed = sum(1 for c in cases if c["pass"])
    total = len(cases)
    summary = {
        "verifier_version": MOD.VERSION,
        "canonicalization": MOD.CANONICALIZATION_ID,
        "default_max_age_days": MOD.DEFAULT_MAX_AGE_DAYS,
        "case_count": total,
        "passed_count": passed,
        "all_passed": passed == total,
        "executed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "env": {"python": sys.version.split()[0], "platform": sys.platform},
        "note": ("过期用例由测试私钥真实签发 400 天前时间戳（信任锚内），不再以"
                 "'签名钥不在锚'等价替代；绑定用例验证 artifact_binding 强制校验。"),
        "cases": cases,
    }
    os.makedirs(HERE, exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    for c in cases:
        print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['case']}: expect={c['expected']} got={c['actual']}")
    print(f"[adversarial_verifier_test {MOD.VERSION}] {passed}/{total} passed -> {OUT_JSON}")
    # 用例临时工作目录保留在系统临时区，由系统回收（本脚本不执行物理删除）
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
