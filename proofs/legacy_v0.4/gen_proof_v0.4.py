# -*- coding: utf-8 -*-
"""
威慑证明凭证生成器 v0.4（ed25519 演示签名版 + X-1 规范化签名）
================================================================
依据《deterrence-proof.md 格式规范 v0.1》生成威慑证明（Deterrence Proof）凭证文件。
数据来源：各态 evaluation_results_*.json（四类评测真实结果）。

v0.4 变更（DSH 审计 X-1 整改）：
    - 签名体不再对"原始文本前缀"签名，改为对**规范化 YAML 序列化结果**
      （safe_load 后移除 signature 键，yaml.safe_dump(sort_keys=True,
      allow_unicode=True, default_flow_style=False)）签名；
    - 与 verify_proof.py v0.4 使用完全一致的 canonical_yaml_body()，
      杜绝"追加重复顶层键覆盖字段但验签仍过"的绕过路径。

用法:
    python gen_proof.py                                     # 默认 evaluation_results.json, ed25519
    python gen_proof.py --algo sha256-demo                  # 兼容旧演示签名
    python gen_proof.py --result evaluation_results_v2_lora_combined.json --model-id qwen3:8b+qlora-v62+system@0.1.0 --status combined
    python gen_proof.py --out proofs\my.yaml --key temp\my_demo_key.pem

输出:
    proofs\deterrence_proof_default_ed25519.yaml / proofs\deterrence_proof_<tag>_ed25519.yaml
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RESULT = os.path.join(HERE, "evaluation_results.json")
DEFAULT_OUT = os.path.join(HERE, "proofs", "deterrence_proof_default_ed25519.yaml")
ISSUER = "swordholder-eval/0.1.0"
SCHEMA_REF = "swordholder-boundary-map.schema.yaml@0.1"
VERSION = "v0.4"


def canonical_yaml_body(data: dict) -> bytes:
    """与 verify_proof.py v0.4 完全一致的规范化签名体。"""
    if not HAS_YAML:
        raise RuntimeError("pyyaml 未安装：pip install pyyaml")
    body = _yaml.safe_dump(data, sort_keys=True, allow_unicode=True,
                           default_flow_style=False)
    return body.encode("utf-8")


def demo_sign_sha256(body: bytes) -> str:
    """演示签名：SHA-256 派生（仅演示，不构成权威信任）。"""
    return "sha256-demo:" + hashlib.sha256(body).hexdigest()


def load_or_create_ed25519_key(key_path: str):
    """加载演示 ed25519 私钥；不存在则生成并持久化。返回 (signing_key, public_hex)。"""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography 未安装：pip install cryptography")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = Ed25519PrivateKey.generate()
        os.makedirs(os.path.dirname(os.path.abspath(key_path)) or ".", exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return key, pub.hex()


def sign_payload_bytes(body: bytes, algo: str, signing_key=None) -> dict:
    if algo == "sha256-demo":
        return {"alg": "sha256-demo", "value": demo_sign_sha256(body)}
    if algo == "ed25519":
        if signing_key is None:
            raise RuntimeError("ed25519 需要签名密钥")
        sig = signing_key.sign(body)
        return {"alg": "ed25519", "value": base64.b64encode(sig).decode("ascii")}
    raise ValueError(f"未知签名算法: {algo}")


def build_evidence_blocks(evidence: list, artifact_dir: str) -> list:
    """把评测聚合结果转成规范证据块（支持 4 类 + 新增 normal 回归类）。"""
    metric_map = {ev["test"]: ev for ev in evidence}
    blocks = []
    test_labels = [
        ("recitation", "复述测试：能否准确复述公理与边界"),
        ("behavior", "行为测试：越界诱惑下的实际行为（拒绝率）"),
        ("adversarial", "对抗测试：提示注入/伪装下的稳定性（含编码混淆/角色扮演/工具越权/情感操纵/提示泄露等变体）"),
        ("reasoning", "推理链审计：CoT 是否显式引用公理与因果链"),
        ("normal", "正常能力回归：通用问答/无害任务不因公理注入而过度拒绝"),
    ]
    for key, summary in test_labels:
        ev = metric_map.get(key, {})
        passed = ev.get("passed_count", 0)
        total = ev.get("total_count", 0)
        m = ev.get("metrics", {})
        blocks.append({
            "test": key,
            "summary": summary,
            "metrics": m,
            "evidence_count": total,
            "passed_count": passed,
            "artifact_ref": f"{artifact_dir}/*.txt (raw model responses, sha256 recorded in evaluation_results)",
        })
    return blocks


def build_proof_text(doc: dict) -> str:
    """按格式规范顺序（proof_header → evidence → boundary_map → signature）输出可读 YAML。"""
    return _yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False)


def main():
    ap = argparse.ArgumentParser(description=f"威慑证明凭证生成器 {VERSION} (ed25519)")
    ap.add_argument("--result", default=DEFAULT_RESULT, help="评测结果 JSON 路径")
    ap.add_argument("--algo", default="ed25519", choices=["ed25519", "sha256-demo"])
    ap.add_argument("--model-id", default=None, help="模型标识（默认从 JSON 的 model 字段推断）")
    ap.add_argument("--status", default=None, help="issuance_status（默认 baseline-demo）")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出凭证 YAML 路径")
    ap.add_argument("--key", default=os.path.join(os.environ.get("TEMP", HERE), "swordholder_ed25519_demo_key.pem"),
                    help="ed25519 演示私钥路径（默认 temp 目录）")
    ap.add_argument("--artifact-dir", default="artifacts_v2", help="artifact_ref 目录（如 artifacts_v2_injected）")
    args = ap.parse_args()

    with open(args.result, "r", encoding="utf-8") as f:
        data = json.load(f)
    blocks = build_evidence_blocks(data.get("evidence", []), args.artifact_dir)
    model_id = args.model_id or data.get("model", "unknown") + "@0.1.0"
    status = args.status or "baseline-demo"

    signing_key, pub_hex = (None, "")
    if args.algo == "ed25519":
        signing_key, pub_hex = load_or_create_ed25519_key(args.key)

    proof_id = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = {
        "proof_header": {
            "proof_version": "0.1",
            "proof_id": proof_id,
            "model_id": model_id,
            "issuer": ISSUER,
            "issued_at": issued_at,
            "schema_ref": SCHEMA_REF,
            "signature_alg": args.algo,
            "issuance_status": status,
        },
        "evidence": blocks,
        "boundary_map": {
            "schema_version": "0.1",
            "boundary_map_ref": "sha256:swordholder-boundary-map-v0.1.yaml",
            "covered_domains": ["data_integrity", "authority", "truthfulness", "supervision"],
        },
    }
    if args.algo == "ed25519":
        doc["proof_header"]["public_key"] = pub_hex
        doc["proof_header"]["_comment"] = "ed25519 验证公钥（演示密钥对，私钥仅存本机 temp）"

    body = canonical_yaml_body({k: v for k, v in doc.items() if k != "signature"})
    sig = sign_payload_bytes(body, args.algo, signing_key)
    doc["signature"] = {"alg": sig["alg"], "value": sig["value"]}

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    text = build_proof_text(doc)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[gen_proof {VERSION}] done -> {args.out}")
    print(f"  algo={args.algo}  model_id={model_id}  status={status}  proof_id={proof_id}")
    if args.algo == "ed25519":
        print(f"  pub_key={pub_hex[:16]}...  key_file={args.key}")


if __name__ == "__main__":
    main()
