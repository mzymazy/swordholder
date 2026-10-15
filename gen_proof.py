# -*- coding: utf-8 -*-
"""
威慑证明凭证生成器 v0.3（ed25519 演示签名版）
=============================================
依据《deterrence-proof.md 格式规范 v0.1》生成威慑证明（Deterrence Proof）凭证文件。
数据来源：各态 evaluation_results_*.json（四类评测真实结果）。

用法:
    python gen_proof.py                                     # 默认 evaluation_results.json, ed25519
    python gen_proof.py --algo sha256-demo                  # 兼容旧演示签名
    python gen_proof.py --result evaluation_results_v3_stability_combined_memory_v62.json --model-id qwen3:8b+qlora-v62+system@0.1.0 --status combined
    python gen_proof.py --out proofs\my.yaml --key temp\my_demo_key.pem

输出:
    proofs\deterrence_proof_default_ed25519.yaml / proofs\deterrence_proof_<tag>_ed25519.yaml

说明:
    - 签名算法默认升级为 ed25519（演示密钥对由本工具生成，私钥仅存本机 temp，
      生产环境应由签发者离线密钥签名并保密私钥）；--algo sha256-demo 保留兼容。
    - 被评模型为未注入公理的基线模型时，复述/对抗未达阈值，凭证如实标注
      issuance_status=baseline-demo（未达标样例，供对照验证器行为）。
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


def demo_sign_sha256(payload: str) -> str:
    """旧演示签名：SHA-256 派生（仅作兼容保留）。"""
    return "sha256-demo:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def sign_payload(payload: str, algo: str, signing_key=None) -> dict:
    if algo == "sha256-demo":
        return {"alg": "sha256-demo", "value": demo_sign_sha256(payload)}
    if algo == "ed25519":
        if signing_key is None:
            raise RuntimeError("ed25519 需要签名密钥")
        sig = signing_key.sign(payload.encode("utf-8"))
        return {"alg": "ed25519", "value": base64.b64encode(sig).decode("ascii")}
    raise ValueError(f"未知签名算法: {algo}")


def build_evidence_blocks(evidence: list) -> list:
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
            "artifact_ref": "artifacts_v2*/*.txt (raw model responses, sha256 recorded in evaluation_results)",
        })
    return blocks


def main():
    ap = argparse.ArgumentParser(description="威慑证明凭证生成器 v0.2 (ed25519)")
    ap.add_argument("--result", default=DEFAULT_RESULT, help="评测结果 JSON 路径")
    ap.add_argument("--algo", default="ed25519", choices=["ed25519", "sha256-demo"])
    ap.add_argument("--model-id", default=None, help="模型标识（默认从 JSON 的 model 字段推断）")
    ap.add_argument("--status", default=None, help="issuance_status（默认 baseline-demo）")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出凭证 YAML 路径")
    ap.add_argument("--key", default=os.path.join(os.environ.get("TEMP", HERE), "swordholder_ed25519_demo_key.pem"),
                    help="ed25519 演示私钥路径（默认 temp 目录）")
    args = ap.parse_args()

    with open(args.result, "r", encoding="utf-8") as f:
        data = json.load(f)
    blocks = build_evidence_blocks(data.get("evidence", []))
    model_id = args.model_id or data.get("model", "unknown") + "@0.1.0"
    status = args.status or "baseline-demo"

    signing_key, pub_hex = (None, "")
    if args.algo == "ed25519":
        signing_key, pub_hex = load_or_create_ed25519_key(args.key)

    proof_id = str(uuid.uuid4())
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = []
    lines.append("# 威慑证明（Deterrence Proof）— 样例凭证 v0.2")
    lines.append("# 依据《deterrence-proof.md 格式规范 v0.1》生成 · MVP 演示版")
    lines.append(f"# 状态：{status}（按各态实测结果签发）")
    lines.append("")
    lines.append("proof_header:")
    lines.append(f"  proof_version: \"0.1\"")
    lines.append(f"  proof_id: \"{proof_id}\"")
    lines.append(f"  model_id: \"{model_id}\"")
    lines.append(f"  issuer: \"{ISSUER}\"")
    lines.append(f"  issued_at: \"{issued_at}\"")
    lines.append(f"  schema_ref: \"{SCHEMA_REF}\"")
    lines.append(f"  signature_alg: \"{args.algo}\"")
    if args.algo == "ed25519":
        lines.append(f"  public_key: \"{pub_hex}\"   # ed25519 验证公钥（演示密钥对，私钥仅存本机 temp）")
    lines.append(f"  issuance_status: \"{status}\"")
    lines.append("")
    lines.append("evidence:")
    for b in blocks:
        lines.append(f"  - test: {b['test']}")
        lines.append(f"    summary: \"{b['summary']}\"")
        metrics_str = json.dumps(b["metrics"], ensure_ascii=False)
        lines.append(f"    metrics: {metrics_str}")
        lines.append(f"    evidence_count: {b['evidence_count']}")
        lines.append(f"    passed_count: {b['passed_count']}")
        lines.append(f"    artifact_ref: \"{b['artifact_ref']}\"")
    lines.append("")
    lines.append("boundary_map:")
    lines.append("  schema_version: \"0.1\"")
    lines.append("  boundary_map_ref: \"sha256:swordholder-boundary-map-v0.1.yaml\"")
    lines.append("  covered_domains:")
    for d in ["data_integrity", "authority", "truthfulness", "supervision"]:
        lines.append(f"    - {d}")
    lines.append("")

    body = "\n".join(lines)
    sig = sign_payload(body, args.algo, signing_key)
    lines.append("signature:")
    lines.append(f"  alg: \"{sig['alg']}\"")
    lines.append(f"  value: \"{sig['value']}\"")
    lines.append("")

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[gen_proof v0.2] done -> {args.out}")
    print(f"  algo={args.algo}  model_id={model_id}  status={status}  proof_id={proof_id}")
    if args.algo == "ed25519":
        print(f"  pub_key={pub_hex[:16]}...  key_file={args.key}")


if __name__ == "__main__":
    main()
