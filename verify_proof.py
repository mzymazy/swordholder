# -*- coding: utf-8 -*-
"""
威慑证明验证器 v0.3（ed25519 + 外部信任锚 + 算法一致性 + 新鲜度检查）
========================================================================
依据《deterrence-proof.md 格式规范 v0.1》§5 验证规则实现，并在 v0.2 基础上
修复 verifier_security_analysis.md 列出的 6 类弱点：

  A1 伪造凭证  → sha256-demo 默认拒绝，仅显式 --demo 模式可用（演示完整性自证）
  A2 篡改证据  → artifact_ref 文件存在性校验 + metrics 数值范围校验
  A3 替换公钥  → 公钥必须命中外部信任锚 trusted_keys.json（sha256 指纹校验），
                 文件内公钥不再自举为信任根
  A4 重放攻击  → issued_at 新鲜度检查（超过阈值 → E_STALE_TIMESTAMP）
  A5 算法降级  → signature.alg 与 header.signature_alg 必须严格一致，
                 且算法必须在白名单内（默认仅 ed25519）
  A6 解析器    → 优先 pyyaml 完整解析 + 结构校验；无 pyyaml 时降级极简解析

输出：VALID 或 INVALID + 失败原因码（E_MISSING_HEADER / E_MISSING_EVIDENCE /
      E_BAD_EVIDENCE / E_BAD_MAP_REF / E_BAD_SIGNATURE / E_UNTRUSTED_KEY /
      E_STALE_TIMESTAMP / E_UNKNOWN_ALG）

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

REQUIRED_HEADER = ["proof_version", "proof_id", "model_id", "issuer",
                   "issued_at", "schema_ref", "signature_alg"]
# 核心证据域（v0.1 格式为 4 类；v0.2+ 新增 normal 为可选回归域）
CORE_EVIDENCE = ["recitation", "behavior", "adversarial", "reasoning"]
COVERED_DOMAINS = ["data_integrity", "authority", "truthfulness", "supervision"]
ALLOWED_ALGS_DEFAULT = ["ed25519"]
ALLOWED_ALGS_DEMO = ["ed25519", "sha256-demo"]
KEY_ID_FIELD = "key_id"
FINGERPRINT_FIELD = "fingerprint_sha256"


# ----------------------------------------------------------------------------
# A6 解析层：优先 pyyaml；无 pyyaml 时降级极简正则（并防缩进/注释注入）
# ----------------------------------------------------------------------------
def parse_sections(text: str):
    """A6 修复：pyyaml 完整解析；fallback 到 v0.2 极简解析（行首锚定防缩进注入）。"""
    if HAS_YAML:
        try:
            data = _yaml.safe_load(text)
            if isinstance(data, dict):
                return data, True
        except Exception:
            pass
    sections = {}
    current = None
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m and not line.startswith(" ") and not line.startswith("\t"):
            current = m.group(1)
            sections.setdefault(current, []).append(line)
        elif current is not None:
            sections[current].append(line)
    return sections, False


def _as_dict(sections, block):
    """把极简解析的块行转为 dict 风格：递归处理缩进子项。"""
    if isinstance(block, dict):
        return block
    out = {}
    stack = [out]
    for line in block if isinstance(block, list) else []:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        while len(stack) > indent // 2 + 1:
            stack.pop()
        m = re.match(r"^(?:- )?([A-Za-z0-9_]+):\s*(.*)$", stripped)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            stack[-1][key] = val
            if not val or val.startswith("#") or re.match(r"^[\[{]", val) is None:
                stack.append({})
    return out


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


def verify_sha256_demo(body: str, sig_val: str) -> bool:
    return sig_val == "sha256-demo:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _signing_body(text: str, sig_marker: str = "signature:") -> bytes:
    return text.split(sig_marker)[0].rstrip().encode("utf-8") + b"\n"


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
    sections, used_yaml = parse_sections(text)
    failures = []

    allowed_algs = ALLOWED_ALGS_DEMO if allow_demo else ALLOWED_ALGS_DEFAULT

    # ---- 1. 完整性：header / evidence / boundary_map / signature ----
    header = _as_dict(sections, sections.get("proof_header", [])) if not used_yaml else sections.get("proof_header", {})
    if not header:
        return "INVALID E_MISSING_HEADER"
    for field in REQUIRED_HEADER:
        if field not in header or header[field] in (None, ""):
            failures.append("E_MISSING_HEADER")

    evidence_block = sections.get("evidence", []) if not used_yaml else sections.get("evidence", [])
    ev_items = sections.get("evidence", [])
    if not isinstance(ev_items, list):
        ev_items = []
    # 兼容极简解析的 list-of-lines 与 pyyaml 的 list-of-dict
    ev_names = []
    for it in ev_items:
        if isinstance(it, dict) and it.get("test"):
            ev_names.append(str(it["test"]))
    if not used_yaml:
        for ln in ev_items if isinstance(ev_items, list) else []:
            m = re.search(r"- test:\s*(\w+)", str(ln))
            if m:
                ev_names.append(m.group(1))
    for t in CORE_EVIDENCE:
        if t not in ev_names:
            failures.append("E_MISSING_EVIDENCE")
    n_tests = len(ev_names)
    if n_tests not in (4, 5):
        failures.append("E_MISSING_EVIDENCE")

    # ---- 2. 合规性：字段齐全 + passed<=count + metrics 数值范围 + artifact 存在性（A2）----
    for it in ev_items:
        if not isinstance(it, dict) or not it.get("test"):
            if used_yaml:
                continue
            # 极简解析行
            line = str(it)
            m = re.search(r"- test:\s*(\w+)", line)
            if not m:
                continue
            nm = m.group(1)
            it = _as_dict({}, [line])
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
        # metrics 数值必须为 0~1 范围内的数值
        metrics = it.get("metrics")
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                if not isinstance(v, (int, float)) or not (0.0 <= float(v) <= 1.0):
                    failures.append("E_BAD_EVIDENCE")
        # A2 修复：artifact_ref 指向的路径必须真实存在（glob 非空）
        # 仅检查含路径层级(/ 或 \)或通配符的引用，避免误抓注释中的顶层文件名
        art = str(it.get("artifact_ref", ""))
        refs = re.findall(r"[A-Za-z0-9_./*?\-\\]+/[A-Za-z0-9_./*?\-\\]*\.[A-Za-z0-9*]+", art)
        if refs:
            hit = any(len(glob.glob(os.path.join(HERE, r))) > 0 for r in refs)
            if not hit:
                failures.append("E_BAD_EVIDENCE")

    # ---- 3. boundary_map 引用一致 ----
    bm = _as_dict(sections, sections.get("boundary_map", [])) if not used_yaml else sections.get("boundary_map", {})
    if not bm:
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

    # ---- 4. 签名链：A5 算法一致性 + 白名单；A3 外部信任锚；A1 demo 显式化 ----
    sig_alg = None
    sig_val = None
    sig_block = sections.get("signature", [])
    if isinstance(sig_block, list) and sig_block and isinstance(sig_block[0], dict):
        sig_alg = sig_block[0].get("alg")
        sig_val = sig_block[0].get("value")
    elif isinstance(sig_block, dict):
        sig_alg = sig_block.get("alg")
        sig_val = sig_block.get("value")
    if sig_alg is None or sig_val is None:
        failures.append("E_BAD_SIGNATURE")
    else:
        sig_alg = str(sig_alg).strip('"')
        sig_val = str(sig_val).strip('"')
        hdr_alg = str(header.get("signature_alg", "")).strip('"')
        # A5：算法必须严格一致且在白名单
        if sig_alg != hdr_alg:
            failures.append("E_BAD_SIGNATURE")
        elif sig_alg not in allowed_algs:
            failures.append("E_UNKNOWN_ALG" if sig_alg not in ("ed25519", "sha256-demo") else "E_BAD_SIGNATURE")
        else:
            body = _signing_body(text)
            ok = False
            if sig_alg == "ed25519":
                pub_hex = str(header.get("public_key", "")).strip('"')
                trusted = load_trusted_keys(trusted_keys_path)
                # A3：公钥必须命中外部信任锚
                if not trust_anchor_match(pub_hex, trusted):
                    failures.append("E_UNTRUSTED_KEY")
                elif not verify_ed25519(body, sig_val, pub_hex):
                    failures.append("E_BAD_SIGNATURE")
                else:
                    ok = True
            elif sig_alg == "sha256-demo":
                # A1：demo 仅显式开启时允许（完整性自证，不构成权威信任）
                if not allow_demo:
                    failures.append("E_BAD_SIGNATURE")
                elif not verify_sha256_demo(body.decode("utf-8"), sig_val):
                    failures.append("E_BAD_SIGNATURE")
                else:
                    ok = True
            if ok and failures:
                # 其他结构失败仍以 INVALID 为准
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
    ap = argparse.ArgumentParser(description="Swordholder 威慑证明验证器 v0.3")
    ap.add_argument("proof", nargs="?", default=DEFAULT_PROOF)
    ap.add_argument("--demo", action="store_true", help="允许 sha256-demo 演示签名（默认拒绝）")
    ap.add_argument("--trusted-keys", default=DEFAULT_TRUSTED_KEYS, help="外部信任锚文件路径")
    ap.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS, help="凭证新鲜度阈值（天）")
    args = ap.parse_args()
    result = verify(args.proof, allow_demo=args.demo,
                    trusted_keys_path=args.trusted_keys, max_age_days=args.max_age_days)
    print(f"[verify_proof v0.3] {os.path.basename(args.proof)} -> {result}")
