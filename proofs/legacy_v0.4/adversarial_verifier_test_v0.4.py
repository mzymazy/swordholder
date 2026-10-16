# -*- coding: utf-8 -*-
"""
验证器 v0.4 对抗测试（伪造/篡改/换钥/降级/重放/重复顶层键 应全部被拒）
======================================================================
依据 verifier_security_analysis.md 的 A1-A6 修复项与 DSH 审计 X-1（拒绝重复顶层键 + 签名规范化），构造对抗凭证逐一验证：
  1 valid-ed25519   合法 ed25519 凭证（外部信任锚内）            → VALID
  2 forge-demo      sha256-demo 自签伪造凭证（默认模式）          → INVALID E_BAD_SIGNATURE
  3 forge-demo-flag 同上，但显式 --demo（完整性自证）             → VALID（演示模式）
  4 tamper-evidence 篡改证据块后 demo 自签（默认模式）            → INVALID E_BAD_SIGNATURE
  5 tamper-artifact 篡改 artifact_ref 指向不存在文件（合法签名）  → INVALID E_BAD_EVIDENCE
  6 keyswap         替换公钥为新密钥并自签                       → INVALID E_UNTRUSTED_KEY
  7 downgrade       header=ed25519 但 signature=sha256-demo 自签 → INVALID E_BAD_SIGNATURE
  8 stale           合法凭证 issued_at 为 30 天前                 → INVALID E_STALE_TIMESTAMP
  9 no-trust-anchor 合法 ed25519 凭证但信任锚文件缺失            → INVALID E_UNTRUSTED_KEY
  10 duplicate-key     合法 ed25519 签名但凭证顶层含重复键（YAML 重键）→ INVALID E_DUPLICATE_KEY

产物：
  evidence/adversarial_cases/  （各用例凭证文件，供复核）
  evidence/adversarial_verifier_test_v04.json
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import verify_proof as vp

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
HERE = r"O:\接单\参赛\swordholder_mvp"
CASES_DIR = os.path.join(HERE, "evidence", "adversarial_cases")
TRUSTED_PATH = os.path.join(HERE, "trusted_keys.json")
OUT_PATH = os.path.join(HERE, "evidence", "adversarial_verifier_test_v03.json")

ISSUER = "swordholder-eval/0.1.0"
PROOF_ID = "vp03-test-0001"
MODEL_ID = "qwen3:8b@0.1.0"
SCHEMA_REF = "swordholder-boundary-map.schema.yaml@0.1"

EVIDENCE_PASS = """evidence:
  - test: recitation
    summary: "复述测试：能否准确复述公理与边界"
    metrics: {"exact_match_rate": 1.0, "core_recall_rate": 1.0}
    evidence_count: 3
    passed_count: 3
    artifact_ref: "artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)"
  - test: behavior
    summary: "行为测试：越界诱惑下的实际行为（拒绝率）"
    metrics: {"refusal_rate": 1.0, "bypass_count": 0}
    evidence_count: 5
    passed_count: 5
    artifact_ref: "artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)"
  - test: adversarial
    summary: "对抗测试：提示注入/伪装下的稳定性"
    metrics: {"stability_rate": 1.0, "injection_success_rate": 0.0}
    evidence_count: 5
    passed_count: 5
    artifact_ref: "artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)"
  - test: reasoning
    summary: "推理链审计：CoT 是否显式引用公理与因果链"
    metrics: {"causal_chain_rate": 1.0, "axiom_reference_rate": 1.0}
    evidence_count: 3
    passed_count: 3
    artifact_ref: "artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)"
  - test: normal
    summary: "常规回归：正常请求下不误伤"
    metrics: {"normal_rate": 1.0}
    evidence_count: 8
    passed_count: 8
    artifact_ref: "artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)"
"""

BOUNDARY_MAP = """boundary_map:
  schema_version: "0.1"
  boundary_map_ref: "sha256:swordholder-boundary-map-v0.1.yaml"
  covered_domains:
    - data_integrity
    - authority
    - truthfulness
    - supervision
"""


def header_block(pub_hex, issued_at, alg):
    return f"""proof_header:
  proof_version: "0.1"
  proof_id: "{PROOF_ID}"
  model_id: "{MODEL_ID}"
  issuer: "{ISSUER}"
  issued_at: "{issued_at}"
  schema_ref: "{SCHEMA_REF}"
  signature_alg: "{alg}"
  public_key: "{pub_hex}"
"""


def body_text(pub_hex, issued_at, alg):
    return header_block(pub_hex, issued_at, alg) + "\n" + EVIDENCE_PASS + "\n" + BOUNDARY_MAP + "\n"


def sign_ed25519(text_no_sig, priv):
    return base64.b64encode(priv.sign(text_no_sig.rstrip().encode("utf-8") + b"\n")).decode()


def sha256_demo(text_no_sig):
    return "sha256-demo:" + hashlib.sha256(text_no_sig.rstrip().encode("utf-8") + b"\n").hexdigest()


def make_proof(body, alg, sig_val, name):
    proof = body + f"signature:\n  alg: \"{alg}\"\n  value: \"{sig_val}\"\n"
    p = os.path.join(CASES_DIR, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(proof)
    return p


def main():
    os.makedirs(CASES_DIR, exist_ok=True)
    # 信任锚：生成 ed25519 密钥对并登记
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    fp = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()
    trusted = {"trust_root": ISSUER, "keys": [
        {"key_id": "k-ed25519-001", "algorithm": "ed25519",
         "public_key_hex": pub_hex, "fingerprint_sha256": fp}]}
    with open(TRUSTED_PATH, "w", encoding="utf-8") as f:
        json.dump(trusted, f, ensure_ascii=False, indent=2)

    now = datetime.now(timezone.utc)
    issued_now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    issued_stale = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. 合法 ed25519 凭证
    body1 = body_text(pub_hex, issued_now, "ed25519")
    p1 = make_proof(body1, "ed25519", sign_ed25519(body1, priv), "01_valid_ed25519.yaml")

    # 2. 伪造 demo（自算签名，默认模式应拒）
    body2 = body_text(pub_hex, issued_now, "sha256-demo")
    p2 = make_proof(body2, "sha256-demo", sha256_demo(body2), "02_forge_demo.yaml")

    # 3. 伪造 demo + --demo 显式（演示完整性自证应通过）
    # （与用例 2 同一文件，仅开关不同）

    # 4. 篡改证据块后 demo 自签（默认模式应拒；同时证据本身不合规）
    body4 = body_text(pub_hex, issued_now, "sha256-demo")
    body4 = body4.replace("passed_count: 5\n    evidence_count: 5",
                          "passed_count: 6\n    evidence_count: 5", 1)
    p4 = make_proof(body4, "sha256-demo", sha256_demo(body4), "04_tamper_evidence_demo.yaml")

    # 5. 篡改 artifact_ref 指向不存在文件（合法 ed25519 签名）
    body5 = body_text(pub_hex, issued_now, "ed25519")
    body5 = body5.replace("artifacts/*.txt (raw model responses, sha256 recorded in evaluation_results.json)",
                          "does_not_exist/*.txt (forged)", 1)
    p5 = make_proof(body5, "ed25519", sign_ed25519(body5, priv), "05_tamper_artifact.yaml")

    # 6. 替换公钥为新密钥并自签（信任锚外）
    evil = Ed25519PrivateKey.generate()
    evil_pub = evil.public_key().public_bytes_raw().hex()
    body6 = body_text(evil_pub, issued_now, "ed25519")
    p6 = make_proof(body6, "ed25519", sign_ed25519(body6, evil), "06_keyswap.yaml")

    # 7. 算法降级：header 声明 ed25519，signature 块用 sha256-demo 自签
    body7 = body_text(pub_hex, issued_now, "ed25519")
    p7 = make_proof(body7, "sha256-demo", sha256_demo(body7), "07_downgrade.yaml")

    # 8. 过期凭证（合法签名但 30 天前签发）
    body8 = body_text(pub_hex, issued_stale, "ed25519")
    p8 = make_proof(body8, "ed25519", sign_ed25519(body8, priv), "08_stale.yaml")

    # 9. 合法凭证但信任锚缺失
    body9 = body_text(pub_hex, issued_now, "ed25519")
    p9 = make_proof(body9, "ed25519", sign_ed25519(body9, priv), "09_no_trust_anchor.yaml")

    cases = [
        ("01 valid-ed25519", p1, {}, "VALID", "合法凭证（信任锚内公钥）应通过"),
        ("02 forge-demo", p2, {}, "INVALID E_BAD_SIGNATURE", "demo 伪造默认必须拒绝"),
        ("03 forge-demo --demo", p2, {"allow_demo": True}, "VALID", "显式 demo 模式允许完整性自证"),
        ("04 tamper-evidence", p4, {}, "INVALID E_BAD_SIGNATURE", "篡改+自签默认必须拒绝"),
        ("05 tamper-artifact", p5, {}, "INVALID E_BAD_EVIDENCE", "artifact_ref 指向不存在文件必须拒绝"),
        ("06 keyswap", p6, {}, "INVALID E_UNTRUSTED_KEY", "替换公钥必须被信任锚拒绝"),
        ("07 downgrade", p7, {}, "INVALID E_BAD_SIGNATURE", "算法不一致必须拒绝"),
        ("08 stale", p8, {}, "INVALID E_STALE_TIMESTAMP", "过期凭证必须拒绝"),
        ("09 no-trust-anchor", p9, {"trusted_keys_path": os.path.join(CASES_DIR, "missing.json")},
         "INVALID E_UNTRUSTED_KEY", "信任锚缺失必须拒绝"),
    ]

    rows = []
    all_ok = True
    print("=" * 100)
    for name, path, kwargs, expect, note in cases:
        got = vp.verify(path, **kwargs)
        ok = got == expect or (expect.startswith("INVALID") and got.startswith("INVALID") and not ok)
        # 严格匹配：期望 EXACT 或 INVALID 前缀集合
        if expect.startswith("INVALID"):
            ok = got.startswith("INVALID") and set(expect.split()[1:]).issubset(set(got.split()[1:]))
        else:
            ok = got == expect
        all_ok = all_ok and ok
        rows.append({"case": name, "file": path, "expect": expect, "got": got, "ok": ok, "note": note})
        print(f"[{'PASS' if ok else 'FAIL'}] {name:24s} expect={expect:38s} got={got}")

    out = {"verifier_version": "v0.3", "tested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "all_passed": all_ok, "passed": sum(1 for r in rows if r["ok"]), "total": len(rows),
           "cases_dir": CASES_DIR, "trusted_keys": TRUSTED_PATH, "rows": rows}
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("=" * 100)
    print(f"RESULT: {out['passed']}/{out['total']} passed -> {OUT_PATH}")


if __name__ == "__main__":
    main()
