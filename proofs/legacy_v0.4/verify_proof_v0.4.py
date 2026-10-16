# -*- coding: utf-8 -*-
"""
威慑证明验证器 v0.4（ed25519 + 外部信任锚 + 算法一致性 + 新鲜度检查 + 防重复键规范化签名）
==========================================================================================
依据《deterrence-proof.md 格式规范 v0.1》§5 验证规则实现，并在 v0.3 基础上修复
DSH 第三方审计 X-1 规范级缺陷：

  X-1 修复（核心）：
    - 签名体不再使用"原始文本前缀"（text.split("signature:")[0]），
      改为对**规范化 YAML 序列化结果**（safe_load 后移除 signature 键，
      再 yaml.safe_dump(sort_keys=True, allow_unicode=True)）签名；
    - **拒绝重复顶层键**：PyYAML safe_load 对重复顶层键默认取最后一块，
      旧实现可被"签名块后追加伪造 header/evidence"绕过；v0.4 显式检测
      顶层键重复并返回 E_DUPLICATE_KEY；
    - 校验签名块必须是文件最后一块（签名块之后不得再出现顶层键）。

其余保留 v0.3 全部能力：
  A1 伪造凭证  → sha256-demo 默认拒绝，仅显式 --demo 模式可用
  A2 篡改证据  → artifact_ref 文件存在性校验 + metrics 数值范围校验
  A3 替换公钥  → 公钥必须命中外部信任锚 trusted_keys.json（sha256 指纹校验）
  A4 重放攻击  → issued_at 新鲜度检查（超过阈值 → E_STALE_TIMESTAMP）
  A5 算法降级  → signature.alg 与 header.signature_alg 严格一致 + 白名单
  A6 解析器    → pyyaml 完整解析（v0.4 强制要求 pyyaml）

输出：VALID 或 INVALID + 失败原因码（E_MISSING_HEADER / E_MISSING_EVIDENCE /
      E_BAD_EVIDENCE / E_BAD_MAP_REF / E_BAD_SIGNATURE / E_UNTRUSTED_KEY /
      E_STALE_TIMESTAMP / E_UNKNOWN_ALG / E_DUPLICATE_KEY / E_YAML_REQUIRED）

用法:
    python verify_proof.py [proofs/deterrence_proof_combined_ed25519.yaml] [--demo] \
        [--trusted-keys trusted_keys.json] [--max-age-days 7]
"""
import base64
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROOF = os.path.join(HERE, "proofs", "deterrence_proof_combined_ed25519.yaml")
DEFAULT_TRUSTED_KEYS = os.path.join(HERE, "trusted_keys.json")
DEFAULT_MAX_AGE_DAYS = 7
VERSION = "v0.4"

REQUIRED_HEADER = ["proof_version", "proof_id", "model_id", "issuer",
                   "issued_at", "schema_ref", "signature_alg"]
# 核心证据域（v0.1 格式为 4 类；v0.2+ 新增 normal 为可选回归域）
CORE_EVIDENCE = ["recitation", "behavior", "adversarial", "reasoning"]
COVERED_DOMAINS = ["data_integrity", "authority", "truthfulness", "supervision"]
ALLOWED_ALGS_DEFAULT = ["ed25519"]
ALLOWED_ALGS_DEMO = ["ed25519", "sha256-demo"]
KEY_ID_FIELD = "key_id"
FINGERPRINT_FIELD = "fingerprint_sha256"
TOP_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):")


# ----------------------------------------------------------------------------
# X-1 修复：规范化 YAML 签名体（gen_proof.py v0.4 必须使用同一函数）
# ----------------------------------------------------------------------------
def canonical_yaml_body(data: dict) -> bytes:
    """对规范化 YAML 序列化结果签名：safe_load 后的 dict（不含 signature 键）
    经 yaml.safe_dump(sort_keys=True, allow_unicode=True, default_flow_style=False)
    得到确定性的规范体。攻击者追加重复顶层键后，safe_load 得到的 dict 被覆盖，
    规范化体随之改变 → 验签必然失败。"""
    body = _yaml.safe_dump(data, sort_keys=True, allow_unicode=True,
                           default_flow_style=False)
    return body.encode("utf-8")


def find_duplicate_top_keys(text: str):
    """拒绝重复顶层键：行首无缩进的 `key:` 出现多次即重复（含签名块后追加的伪造块）。
    注释与空行忽略。返回重复键列表；空列表表示无重复。"""
    seen = {}
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line[0].isspace():
            m = TOP_KEY_RE.match(line)
            if m:
                k = m.group(1)
                seen[k] = seen.get(k, 0) + 1
    return [k for k, v in seen.items() if v > 1]


def check_signature_is_last_block(text: str):
    """校验签名块必须是文件最后一块：'signature:' 首次出现之后不得再出现
    行首无缩进的顶层键（重复键检测兜底：此时直接视为 X-1 攻击）。"""
    idx = text.find("signature:")
    if idx < 0:
        return True  # 缺失 signature 由后续 E_BAD_SIGNATURE 处理
    tail = text[idx:].splitlines()
    for i, line in enumerate(tail):
        if i == 0:
            continue  # 第一行即 signature: 块自身
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line[0].isspace():
            return False  # 签名块之后还有顶层键
    return True


# ----------------------------------------------------------------------------
# 签名原语
# ----------------------------------------------------------------------------
def verify_ed25519(body: bytes, b64_sig: str, pub_hex: str) -> bool:
    if not HAS_CRYPTO:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(base64.b64decode(b64_sig), body)
        return True
    except Exception:
        return False


def verify_sha256_demo(body: bytes, sig_val: str) -> bool:
    return sig_val == "sha256-demo:" + hashlib.sha256(body).hexdigest()


# ----------------------------------------------------------------------------
# A3 外部信任锚
# ----------------------------------------------------------------------------
def load_trusted_keys(path: str):
    """加载外部信任锚；不存在则返回空列表（即无任何受信公钥）。"""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("keys", [])
    except Exception:
        return []


def trust_anchor_match(pub_hex: str, trusted_keys: list) -> bool:
    """A3 修复：公钥必须命中信任锚，且 sha256(公钥hex) 与登记指纹一致。"""
    if not pub_hex:
        return False
    fp = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()
    for tk in trusted_keys:
        if tk.get("algorithm") != "ed25519":
            continue
        if tk.get("public_key_hex", "").lower() == pub_hex.lower():
            reg_fp = tk.get(FINGERPRINT_FIELD, "")
            return bool(reg_fp) and reg_fp.lower() == fp
    return False


# ----------------------------------------------------------------------------
# A4 新鲜度检查
# ----------------------------------------------------------------------------
def parse_issued_at(raw: str):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception:
        return None


def is_fresh(issued_at_dt, now=None, max_age_days=DEFAULT_MAX_AGE_DAYS):
    if issued_at_dt is None:
        return None  # 无法解析，交由缺失字段逻辑
    now = now or datetime.now(timezone.utc)
    if issued_at_dt.tzinfo is None:
        issued_at_dt = issued_at_dt.replace(tzinfo=timezone.utc)
    return (now - issued_at_dt) <= timedelta(days=max_age_days)


# ----------------------------------------------------------------------------
# 主验证流程
# ----------------------------------------------------------------------------
def verify(path: str, allow_demo: bool = False,
           trusted_keys_path: str = DEFAULT_TRUSTED_KEYS,
           max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> str:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    failures = []

    # ---- X-1：先拒绝重复顶层键（攻击者可在签名块后追加伪造块覆盖字段）----
    dups = find_duplicate_top_keys(text)
    if dups:
        return "INVALID E_DUPLICATE_KEY"
    if not check_signature_is_last_block(text):
        return "INVALID E_DUPLICATE_KEY"

    # ---- X-1：强制 pyyaml 规范化解析（不再使用极简正则降级解析）----
    if not HAS_YAML:
        return "INVALID E_YAML_REQUIRED"
    try:
        data = _yaml.safe_load(text)
    except Exception:
        return "INVALID E_BAD_SIGNATURE"
    if not isinstance(data, dict) or not data:
        return "INVALID E_MISSING_HEADER"

    allowed_algs = ALLOWED_ALGS_DEMO if allow_demo else ALLOWED_ALGS_DEFAULT

    # ---- 1. 完整性：header / evidence / boundary_map / signature ----
    header = data.get("proof_header", {})
    if not isinstance(header, dict) or not header:
        return "INVALID E_MISSING_HEADER"
    for field in REQUIRED_HEADER:
        if field not in header or header[field] in (None, ""):
            failures.append("E_MISSING_HEADER")

    ev_items = data.get("evidence", [])
    if not isinstance(ev_items, list):
        ev_items = []
    ev_names = [str(it.get("test")) for it in ev_items if isinstance(it, dict) and it.get("test")]
    for t in CORE_EVIDENCE:
        if t not in ev_names:
            failures.append("E_MISSING_EVIDENCE")
    n_tests = len(ev_names)
    if n_tests not in (4, 5):
        failures.append("E_MISSING_EVIDENCE")

    # ---- 2. 合规性：字段齐全 + passed<=count + metrics 数值范围 + artifact 存在性（A2）----
    for it in ev_items:
        if not isinstance(it, dict) or not it.get("test"):
            failures.append("E_BAD_EVIDENCE")
            continue
        nm = str(it.get("test"))
        for field in ["metrics", "evidence_count", "artifact_ref"]:
            if field not in it or it[field] in (None, ""):
                failures.append("E_BAD_EVIDENCE")
        try:
            pc = int(it.get("passed_count", -1))
            tc = int(it.get("evidence_count", -1))
            if tc >= 0 and (pc < 0 or pc > tc):
                failures.append("E_BAD_EVIDENCE")
        except Exception:
            failures.append("E_BAD_EVIDENCE")
        metrics = it.get("metrics")
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    failures.append("E_BAD_EVIDENCE")
                elif isinstance(v, int) and k.endswith("count") and tc >= 0:
                    # 计数类指标（bypass_count 等）：按样本总数上界校验
                    if v < 0 or v > tc:
                        failures.append("E_BAD_EVIDENCE")
                elif not (0.0 <= float(v) <= 1.0):
                    failures.append("E_BAD_EVIDENCE")
        art = str(it.get("artifact_ref", ""))
        refs = re.findall(r"[A-Za-z0-9_./*?\-\\]+/[A-Za-z0-9_./*?\-\\]*\.[A-Za-z0-9*]+", art)
        if refs:
            hit = any(len(glob.glob(os.path.join(HERE, r))) > 0 for r in refs)
            if not hit:
                failures.append("E_BAD_EVIDENCE")

    # ---- 3. boundary_map 引用一致 ----
    bm = data.get("boundary_map", {})
    if not isinstance(bm, dict) or not bm:
        failures.append("E_BAD_MAP_REF")
    else:
        if str(bm.get("schema_version", "")).strip('"') != "0.1":
            failures.append("E_BAD_MAP_REF")
        covered = bm.get("covered_domains", [])
        if isinstance(covered, list):
            names = [str(x) for x in covered]
        else:
            names = []
        for d in COVERED_DOMAINS:
            if d not in names:
                failures.append("E_BAD_MAP_REF")

    # ---- 4. 签名链：X-1 规范化签名体 + A5 算法一致性 + A3 信任锚 ----
    sig_block = data.get("signature", {})
    if isinstance(sig_block, list):
        sig_block = sig_block[0] if sig_block else {}
    sig_alg = sig_block.get("alg") if isinstance(sig_block, dict) else None
    sig_val = sig_block.get("value") if isinstance(sig_block, dict) else None
    if sig_alg is None or sig_val is None:
        failures.append("E_BAD_SIGNATURE")
    else:
        sig_alg = str(sig_alg).strip('"')
        sig_val = str(sig_val).strip('"')
        hdr_alg = str(header.get("signature_alg", "")).strip('"')
        if sig_alg != hdr_alg:
            failures.append("E_BAD_SIGNATURE")
        elif sig_alg not in allowed_algs:
            failures.append("E_UNKNOWN_ALG" if sig_alg not in ("ed25519", "sha256-demo") else "E_BAD_SIGNATURE")
        else:
            # X-1：签名体 = 规范化 YAML 序列化（移除 signature 键）
            body_data = {k: v for k, v in data.items() if k != "signature"}
            try:
                body = canonical_yaml_body(body_data)
            except Exception:
                body = b""
            ok = False
            if sig_alg == "ed25519":
                pub_hex = str(header.get("public_key", "")).strip('"')
                trusted = load_trusted_keys(trusted_keys_path)
                if not trust_anchor_match(pub_hex, trusted):
                    failures.append("E_UNTRUSTED_KEY")
                elif not verify_ed25519(body, sig_val, pub_hex):
                    failures.append("E_BAD_SIGNATURE")
                else:
                    ok = True
            elif sig_alg == "sha256-demo":
                if not allow_demo:
                    failures.append("E_BAD_SIGNATURE")
                elif not verify_sha256_demo(body, sig_val):
                    failures.append("E_BAD_SIGNATURE")
                else:
                    ok = True
            if ok and failures:
                pass

    # ---- 5. A4 新鲜度检查 ----
    issued_dt = parse_issued_at(str(header.get("issued_at", "")).strip('"'))
    if issued_dt is not None and not is_fresh(issued_dt, max_age_days=max_age_days):
        failures.append("E_STALE_TIMESTAMP")

    if failures:
        return "INVALID " + " ".join(sorted(set(failures)))
    return "VALID"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=f"Swordholder 威慑证明验证器 {VERSION}")
    ap.add_argument("proof", nargs="?", default=DEFAULT_PROOF)
    ap.add_argument("--demo", action="store_true", help="允许 sha256-demo 演示签名（默认拒绝）")
    ap.add_argument("--trusted-keys", default=DEFAULT_TRUSTED_KEYS, help="外部信任锚文件路径")
    ap.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS, help="凭证新鲜度阈值（天）")
    args = ap.parse_args()
    result = verify(args.proof, allow_demo=args.demo,
                    trusted_keys_path=args.trusted_keys, max_age_days=args.max_age_days)
    print(f"[verify_proof {VERSION}] {os.path.basename(args.proof)} -> {result}")
