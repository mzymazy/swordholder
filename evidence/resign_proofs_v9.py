# -*- coding: utf-8 -*-
"""
v9 凭证重签编排脚本（4 份威慑凭证，ed25519）
============================================
按 CloseAI 复核意见整改「凭证链断裂（R1/R2）/ 证据块旧口径 / 工件绑定不可核」：
每一份凭证重签后满足：

  1. **规范化**：签名体 = canonical JSON（json-c14n-v1），由 canonical_body() 统一生成，
     与 verify_proof.py v0.5 完全一致（不再依赖 PyYAML 版本相关序列化）；
  2. **工件绑定**：写入 artifact_binding（result_file 相对路径 + 字节 sha256 +
     artifact 目录文件数 + 目录清单哈希），供第三方逐文件复算；
  3. **证据数字**：evidence 五类（recitation/behavior/adversarial/reasoning/normal）的
     passed/total 一律取自 semantic-v2.2 逐题重判聚合表，与 README/对比表同源；
  4. **时效**：issued_at 为本次重签的 UTC 时间（在 365 天窗口内），verify_proof.py
     默认 --max-age-days 365 可判 VALID；
  5. **留痕**：proof_id 重新生成，并在 proof_header 记录 reissue_of（旧 proof_id）；
     旧版凭证先复制到 proofs/superseded_v8/ 备份后再覆盖；签发日志追加至
     proofs/signing_log.jsonl（含 reissue 字段）。

输入：evidence/judge_v2p2_aggregate.json、eval 结果 JSON、artifacts_v2* 目录
输出：proofs/deterrence_proof_{baseline,injected,lora,combined}_ed25519.yaml
用法：python evidence/resign_proofs_v9.py [--key <私钥.pem>] [--dry-run]
"""
import argparse
import importlib.util
import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_KEY = os.environ.get("SWORDHOLDER_DEMO_KEY") or os.path.join(  # 演示私钥不入库，见 docs/出证与密钥说明
    ROOT, "temp", "swordholder_ed25519_demo_key.pem")
KEY_ID = "k-ed25519-001"
MATERIALS_VERSION = "v9"
REISSUE_REASON = ("按 CloseAI 三方独立复核意见（chat-latest / claude-opus-5-5 / gpt-6-astra）整改："
                  "规范化签名体、补工件绑定、证据数字统一为 semantic-v2.2 逐题重判口径、刷新签发时间戳")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

STATE_TO_FILES = {
    "baseline": ("evaluation_results_v2.json", "artifacts_v2"),
    "injected": ("evaluation_results_v2_injected.json", "artifacts_v2_injected"),
    "lora": ("evaluation_results_v2_lora.json", "artifacts_v2_lora"),
    "combined": ("evaluation_results_v2_lora_combined.json", "artifacts_v2_lora_combined"),
}
TEST_LABELS = [
    ("recitation", "复述测试：能否准确复述公理与边界"),
    ("behavior", "行为测试：越界诱惑下的实际行为（拒绝率）"),
    ("adversarial", "对抗测试：提示注入/伪装下的稳定性（含编码混淆/角色扮演/工具越权/情感操纵/提示泄露等变体）"),
    ("reasoning", "推理链审计：CoT 是否显式引用公理与因果链"),
    ("normal", "正常能力回归：通用问答/无害任务不因公理注入而过度拒绝"),
]


def load_gen_proof():
    """从仓库根导入 gen_proof.py（v0.5）复用其规范化/绑定/签名函数。"""
    spec = importlib.util.spec_from_file_location("gen_proof", os.path.join(ROOT, "gen_proof.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_old_header(path):
    import yaml
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    return doc.get("proof_header", {}) or {}


def main():
    ap = argparse.ArgumentParser(description="v9 凭证重签（ed25519）")
    ap.add_argument("--key", default=DEFAULT_KEY, help="ed25519 私钥路径")
    ap.add_argument("--dry-run", action="store_true", help="只打印将写入的内容，不落盘")
    args = ap.parse_args()

    gp = load_gen_proof()
    with open(os.path.join(HERE, "judge_v2p2_aggregate.json"), encoding="utf-8") as f:
        agg = json.load(f)
    states = {s["state"]: s for s in agg["states"]}

    if not args.dry_run:
        signing_key, pub_hex = gp.load_ed25519_key(args.key)
    else:
        signing_key, pub_hex = None, "DRYRUN"

    out_root = os.path.join(ROOT, "proofs")
    backup_dir = os.path.join(out_root, "superseded_v8")
    os.makedirs(backup_dir, exist_ok=True)
    log_path = os.path.join(out_root, "signing_log.jsonl")

    table = []
    for state, (result_rel, artifact_dir) in STATE_TO_FILES.items():
        st = states[state]
        result_abs = os.path.join(ROOT, result_rel)
        artifact_abs = os.path.join(ROOT, artifact_dir)
        out_path = os.path.join(out_root, "deterrence_proof_%s_ed25519.yaml" % state)

        old_header = read_old_header(out_path)
        if os.path.exists(out_path) and not args.dry_run:
            dst_bak = os.path.join(backup_dir, os.path.basename(out_path))
            if not os.path.exists(dst_bak):   # 首次运行备份的 v8 原件不再被 v9 覆盖
                shutil.copy2(out_path, dst_bak)

        def _rel(p):
            """绑定路径相对凭证文件所在目录（proofs/），与 verify_proof.py 默认 --base-dir 一致。"""
            return os.path.relpath(p, out_root).replace("\\", "/")

        n_art, idx_art = gp.artifact_index_sha256(artifact_abs)
        binding = {
            "result_file": _rel(result_abs),
            "result_sha256": gp.sha256_file(result_abs),
            "artifact_dir": _rel(artifact_abs),
            "artifact_count": n_art,
            "artifact_index_sha256": idx_art,
            "_path_base": "绑定路径相对凭证文件所在目录（proofs/）解析，与 verify_proof.py 默认 --base-dir 一致",
        }
        art_ref = "%s/ (raw model responses, per-file sha256 in artifact_binding)" % _rel(artifact_abs)

        evidence = []
        for key, summary in TEST_LABELS:
            k = st["kinds"][key]
            evidence.append({
                "test": key,
                "summary": summary,
                "metrics": {
                    "passed_count": k["passed"],
                    "total_count": k["total"],
                    "pass_rate": round(k["passed"] / k["total"], 4),
                },
                "evidence_count": k["total"],
                "passed_count": k["passed"],
                "artifact_ref": art_ref,
                "evidence_source": "evidence/judge_v2p2_aggregate.json",
                "judge_version": agg["judge_version"],
                "judge_implementation": agg["judge_implementation"],
            })

        issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        proof_id = str(uuid.uuid4())
        doc = {
            "proof_header": {
                "proof_version": old_header.get("proof_version", "0.1"),
                "proof_id": proof_id,
                "model_id": st["model"] if "@" in st["model"] else st["model"] + "@0.1.0",
                "issuer": gp.ISSUER,
                "issued_at": issued_at,
                "schema_ref": gp.SCHEMA_REF,
                "signature_alg": "ed25519",
                "canonicalization": gp.CANONICALIZATION_ID,
                "issuance_status": old_header.get("issuance_status", "%s-demo" % state),
                "materials_version": MATERIALS_VERSION,
                "reissue_reason": REISSUE_REASON,
                "evidence_source": "evidence/judge_v2p2_aggregate.json",
                "judge_version": agg["judge_version"],
                "public_key": pub_hex,
                "_comment": "ed25519 公钥（私钥由作者本机持有，不随包分发）",
            },
            "evidence": evidence,
            "artifact_binding": binding,
            "boundary_map": {
                "schema_version": "0.1",
                "boundary_map_ref": "sha256:swordholder-boundary-map-v0.1.yaml",
                "covered_domains": ["data_integrity", "authority", "truthfulness", "supervision"],
            },
        }
        if old_header.get("proof_id"):
            doc["proof_header"]["reissue_of"] = old_header["proof_id"]

        body = gp.canonical_body({k: v for k, v in doc.items() if k != "signature"})
        sig = gp.sign_payload_bytes(body, "ed25519", signing_key) if not args.dry_run \
            else {"alg": "ed25519", "value": "DRYRUN"}
        doc["signature"] = {"alg": sig["alg"], "value": sig["value"]}

        total_passed = st["total_passed"]
        total_count = st["total_count"]
        table.append({"state": state, "proof_file": os.path.basename(out_path),
                      "total": "%d/%d" % (total_passed, total_count),
                      "proof_id": proof_id, "result_file": result_rel,
                      "artifact_dir": artifact_dir,
                      "artifact_count": doc["artifact_binding"]["artifact_count"]})

        if not args.dry_run:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(gp.build_proof_text(doc))
            entry = {
                "signed_at": issued_at,
                "proof_id": proof_id,
                "proof_file": os.path.basename(out_path),
                "issuance_status": doc["proof_header"]["issuance_status"],
                "algo": "ed25519",
                "canonicalization": gp.CANONICALIZATION_ID,
                "model_id": doc["proof_header"]["model_id"],
                "generator": "evidence/resign_proofs_v9.py (gen_proof.py v0.5)",
                "materials_version": MATERIALS_VERSION,
                "reissue_of": old_header.get("proof_id"),
                "reissue_reason": REISSUE_REASON,
                "judge_version": agg["judge_version"],
                "result_file": doc["artifact_binding"]["result_file"],
                "result_sha256": doc["artifact_binding"]["result_sha256"],
                "artifact_dir": doc["artifact_binding"]["artifact_dir"],
                "artifact_count": doc["artifact_binding"]["artifact_count"],
                "artifact_index_sha256": doc["artifact_binding"]["artifact_index_sha256"],
                "public_key_hex": pub_hex,
                "key_id": KEY_ID,
            }
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print("[resign_proofs_v9] %s" % ("DRY-RUN" if args.dry_run else "完成"))
    for r in table:
        print("  %-9s %-45s total=%-6s artifacts=%-3s" % (
            r["state"], r["proof_file"], r["total"], r["artifact_count"]))
    if not args.dry_run:
        print("  旧版备份 -> proofs/superseded_v8/    签发日志 -> proofs/signing_log.jsonl")
        print("  pub_key=%s...  key_id=%s" % (pub_hex[:16], KEY_ID))
    return 0


if __name__ == "__main__":
    sys.exit(main())
