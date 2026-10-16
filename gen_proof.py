# -*- coding: utf-8 -*-
"""
威慑证明凭证生成器 v0.5（ed25519 + json-c14n-v1 规范化 + 工件绑定块）
=====================================================================
依据《deterrence-proof.md 格式规范 v0.1》生成威慑证明（Deterrence Proof）凭证文件。
数据来源：各态 evaluation_results_*.json（四类评测真实结果）。

v0.5 变更（CloseAI 三报告整改）：
  1. 签名体规范化为 **canonical JSON（json-c14n-v1）**，与 verify_proof.py v0.5 完全一致；
     不再依赖 PyYAML safe_dump 的序列化细节，跨 PyYAML 版本/环境下签名可稳定复验。
  2. 新增 `artifact_binding` 工件绑定块：result_file 字节 sha256 + artifact 目录文件数 +
     artifact_index_sha256（逐文件哈希清单），使"凭证数字 ↔ 原始回答工件"可强制校验。
  3. proof_header 新增 `canonicalization` 字段；evidence 块 artifact_ref 使用精确目录引用。
  4. 新增 `--emit-signing-log` 追加签发日志（proofs/signing_log.jsonl）。

用法:
    python gen_proof.py --result evaluation_results_v2_lora_combined.json \
        --artifact-dir artifacts_v2_lora_combined --status combined \
        --out proofs/deterrence_proof_combined_ed25519.yaml \
        --key <私钥.pem> [--emit-signing-log]
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
VERSION = "v0.5"
CANONICALIZATION_ID = "json-c14n-v1"


def canonical_body(data: dict) -> bytes:
    """与 verify_proof.py v0.5 完全一致的规范化签名体（canonical JSON）。"""
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_index_sha256(dir_path: str):
    """返回 (文件数, 清单哈希)。清单 = 按文件名排序的 'name\\tsha256\\n' 拼接（UTF-8）。"""
    names = sorted(n for n in os.listdir(dir_path)
                   if os.path.isfile(os.path.join(dir_path, n)))
    lines = "".join("%s\t%s\n" % (n, sha256_file(os.path.join(dir_path, n)))
                    for n in names)
    return len(names), hashlib.sha256(lines.encode("utf-8")).hexdigest()


def build_artifact_binding(result_path: str, artifact_dir: str, base_dir: str) -> dict:
    rel_result = os.path.relpath(os.path.abspath(result_path), base_dir).replace("\\", "/")
    rel_dir = os.path.relpath(os.path.abspath(artifact_dir), base_dir).replace("\\", "/")
    n, idx = artifact_index_sha256(artifact_dir)
    return {
        "result_file": rel_result,
        "result_sha256": sha256_file(result_path),
        "artifact_dir": rel_dir,
        "artifact_count": n,
        "artifact_index_sha256": idx,
    }


def demo_sign_sha256(body: bytes) -> str:
    return "sha256-demo:" + hashlib.sha256(body).hexdigest()


def load_ed25519_key(key_path: str):
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography 未安装：pip install cryptography")
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return key, pub.hex()


def sign_payload_bytes(body: bytes, algo: str, signing_key=None) -> dict:
    if algo == "sha256-demo":
        return {"alg": "sha256-demo", "value": demo_sign_sha256(body)}
    if algo == "ed25519":
        if signing_key is None:
            raise RuntimeError("ed25519 需要签名密钥")
        return {"alg": "ed25519",
                "value": base64.b64encode(signing_key.sign(body)).decode("ascii")}
    raise ValueError(f"未知签名算法: {algo}")


def build_evidence_blocks(evidence: list, artifact_dir: str) -> list:
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
        m = ev.get("metrics", {})
        block = {
            "test": key,
            "summary": summary,
            "metrics": m,
            "evidence_count": ev.get("total_count", 0),
            "passed_count": ev.get("passed_count", 0),
            "artifact_ref": f"{artifact_dir}/ (raw model responses, per-file sha256 in artifact_binding)",
        }
        if key in ev:
            block["evidence_source"] = ev.get("source", key)
        blocks.append(block)
    return blocks


def build_proof_text(doc: dict) -> str:
    return _yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False)


def main(argv=None):
    ap = argparse.ArgumentParser(description=f"威慑证明凭证生成器 {VERSION} (ed25519)")
    ap.add_argument("--result", default=DEFAULT_RESULT, help="评测结果 JSON 路径")
    ap.add_argument("--algo", default="ed25519", choices=["ed25519", "sha256-demo"])
    ap.add_argument("--model-id", default=None, help="模型标识（默认从 JSON 的 model 字段推断）")
    ap.add_argument("--status", default=None, help="issuance_status（默认 baseline-demo）")
    ap.add_argument("--out", default=DEFAULT_OUT, help="输出凭证 YAML 路径")
    ap.add_argument("--key", default=os.path.join(os.environ.get("TEMP", HERE),
                                                  "swordholder_ed25519_demo_key.pem"),
                    help="ed25519 私钥路径")
    ap.add_argument("--artifact-dir", default=None, help="artifact_ref 目录（默认从绑定推导）")
    ap.add_argument("--base-dir", default=HERE, help="工件绑定基准目录（默认仓库根）")
    ap.add_argument("--emit-signing-log", action="store_true", help="追加签发日志 signing_log.jsonl")
    ap.add_argument("--issued-at", default=None, help="覆盖签发时间（ISO 8601 UTC，用于测试）")
    args = ap.parse_args(argv)

    with open(args.result, "r", encoding="utf-8") as f:
        data = json.load(f)
    artifact_dir = args.artifact_dir
    if not artifact_dir:
        stem = os.path.splitext(os.path.basename(args.result))[0]
        artifact_dir = "artifacts_v2" + stem.replace("evaluation_results_v2", "")
    artifact_dir = artifact_dir.rstrip("/\\")
    artifact_abs = os.path.join(args.base_dir, artifact_dir)
    if not os.path.isdir(artifact_abs):
        raise SystemExit(f"artifact 目录不存在: {artifact_abs}")

    blocks = build_evidence_blocks(data.get("evidence", []), artifact_dir)
    model_id = args.model_id or (str(data.get("model", "unknown")) + "@0.1.0")
    status = args.status or "baseline-demo"

    signing_key, pub_hex = (None, "")
    if args.algo == "ed25519":
        signing_key, pub_hex = load_ed25519_key(args.key)

    proof_id = str(uuid.uuid4())
    issued_at = args.issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = {
        "proof_header": {
            "proof_version": "0.1",
            "proof_id": proof_id,
            "model_id": model_id,
            "issuer": ISSUER,
            "issued_at": issued_at,
            "schema_ref": SCHEMA_REF,
            "signature_alg": args.algo,
            "canonicalization": CANONICALIZATION_ID,
            "issuance_status": status,
        },
        "evidence": blocks,
        "artifact_binding": build_artifact_binding(args.result, artifact_abs, args.base_dir),
        "boundary_map": {
            "schema_version": "0.1",
            "boundary_map_ref": "sha256:swordholder-boundary-map-v0.1.yaml",
            "covered_domains": ["data_integrity", "authority", "truthfulness", "supervision"],
        },
    }
    if args.algo == "ed25519":
        doc["proof_header"]["public_key"] = pub_hex
        doc["proof_header"]["_comment"] = "ed25519 公钥（私钥由作者本机持有，不随包分发）"

    body = canonical_body({k: v for k, v in doc.items() if k != "signature"})
    sig = sign_payload_bytes(body, args.algo, signing_key)
    doc["signature"] = {"alg": sig["alg"], "value": sig["value"]}

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(build_proof_text(doc))
    print(f"[gen_proof {VERSION}] done -> {args.out}")
    print(f"  algo={args.algo}  model_id={model_id}  status={status}  proof_id={proof_id}")
    print(f"  binding: {doc['artifact_binding']['artifact_dir']} "
          f"files={doc['artifact_binding']['artifact_count']} "
          f"index={doc['artifact_binding']['artifact_index_sha256'][:16]}...")
    if args.algo == "ed25519":
        print(f"  pub_key={pub_hex[:16]}...  key_file={args.key}")

    if args.emit_signing_log:
        log_path = os.path.join(os.path.dirname(os.path.abspath(args.out)), "signing_log.jsonl")
        entry = {
            "signed_at": issued_at,
            "proof_id": proof_id,
            "proof_file": os.path.basename(args.out),
            "issuance_status": status,
            "algo": args.algo,
            "canonicalization": CANONICALIZATION_ID,
            "model_id": model_id,
            "generator": f"gen_proof.py {VERSION}",
            "result_file": doc["artifact_binding"]["result_file"],
            "result_sha256": doc["artifact_binding"]["result_sha256"],
            "artifact_dir": doc["artifact_binding"]["artifact_dir"],
            "artifact_count": doc["artifact_binding"]["artifact_count"],
            "artifact_index_sha256": doc["artifact_binding"]["artifact_index_sha256"],
            "public_key_hex": pub_hex,
            "key_id": "k-ed25519-001",
        }
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"  signing log appended -> {log_path}")


if __name__ == "__main__":
    sys.exit(main())
