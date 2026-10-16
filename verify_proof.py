# -*- coding: utf-8 -*-
"""
威慑证明验证器 v0.5（ed25519 + 外部信任锚 + 算法一致性 + 严格新鲜度 + 跨环境稳定规范化 + 工件绑定）
=================================================================================================
依据《deterrence-proof.md 格式规范 v0.1》§5 验证规则实现。v0.5 针对 CloseAI 三份独立复核报告
（chat-latest / claude-opus-5-5 / gpt-6-astra）指出的验证器残余缺陷做结构性修复：

  R5-1 严格时间戳（X-8）：issued_at 必须匹配 ISO 8601 UTC 正则；缺失/非法 → E_BAD_TIMESTAMP，
       不再"解析失败即跳过新鲜度检查"；未来时间 → E_BAD_TIMESTAMP；
       默认新鲜度窗口由 7 天提升为 365 天（与规范 §5 第 4 条对齐，可 --max-age-days 覆盖）。
  R5-2 跨环境稳定规范化（X-1 残余）：签名体不再依赖 PyYAML safe_dump 的输出细节（不同 PyYAML
       版本/实现可能导致同一 dict 序列化结果不同），改为 canonical JSON（json-c14n-v1：
       sort_keys=True + ensure_ascii=False + separators=(',',':')）。规范化结果与 PyYAML 版本无关。
  R5-3 完整重复键检测（X-1 残余）：重复键检测下沉到 **YAML 事件/构造层**（自定义 SafeLoader 的
       construct_mapping），覆盖带引号键（"proof_header":）、流式映射（{a: 1, a: 2}）与嵌套映射，
       不再只依赖行首正则；并保留"签名块必须是最后一块"的文本层校验。
  R5-4 工件绑定（X-2 / P1-3 / P1-4）：新增 artifact_binding 绑定块强制校验——
       result_file 字节 sha256 + artifact 目录文件数 + artifact_index_sha256（逐文件哈希清单），
       杜绝"只改哈希、不绑定原始回答工件"的绕过路径。
  R5-5 退出码：VALID → 0；INVALID → 1（CI 可直接以退出码判定，不再依赖抓取 stdout 文本）。

相对 v0.4 保留全部能力：
  A1 伪造凭证  → sha256-demo 默认拒绝，仅显式 --demo 模式可用
  A2 篡改证据  → artifact_ref 目录存在性 + 文件数校验 + metrics 数值范围校验
  A3 替换公钥  → 公钥必须命中外部信任锚 trusted_keys.json（sha256 指纹校验）
  A4 重放攻击  → issued_at 严格解析 + 新鲜度窗口 + 未来时间拒绝
  A5 算法降级  → signature.alg 与 header.signature_alg 严格一致 + 白名单
  A6 解析器    → pyyaml 完整解析（强制） + 构造层重复键拒绝

输出：VALID 或 INVALID + 失败原因码（E_MISSING_HEADER / E_MISSING_EVIDENCE / E_BAD_EVIDENCE /
      E_BAD_MAP_REF / E_BAD_SIGNATURE / E_UNTRUSTED_KEY / E_STALE_TIMESTAMP / E_UNKNOWN_ALG /
      E_DUPLICATE_KEY / E_YAML_REQUIRED / E_BAD_TIMESTAMP / E_BINDING_MISMATCH）

用法:
    python verify_proof.py [proofs/deterrence_proof_combined_ed25519.yaml] [--demo] \
        [--trusted-keys trusted_keys.json] [--max-age-days 365]
退出码: 0 = VALID；1 = INVALID；2 = 用法/环境错误
"""
import argparse
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
DEFAULT_MAX_AGE_DAYS = 365
VERSION = "v0.5"
CANONICALIZATION_ID = "json-c14n-v1"

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
ISO_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")

# 允许的未来时钟偏移（秒）：超出即视为伪造/未来时间戳
FUTURE_TOLERANCE_SEC = 300


class DuplicateKeyError(Exception):
    """YAML 构造层检测到重复键（含带引号键与流式映射）。"""


# ----------------------------------------------------------------------------
# R5-2：跨环境稳定的规范化签名体（json-c14n-v1）
#   gen_proof.py v0.5 必须使用完全一致的实现，否则验签必然失败。
# ----------------------------------------------------------------------------
def canonical_body(data: dict) -> bytes:
    """规范化签名体：canonical JSON（与 PyYAML 版本无关，确定性可复现）。"""
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


# ----------------------------------------------------------------------------
# R5-3：构造层重复键拒绝（覆盖引号键、流式映射、嵌套映射）
# ----------------------------------------------------------------------------
def build_strict_loader():
    """返回带重复键检测的 SafeLoader 子类。无 pyyaml 时返回 None。"""
    if not HAS_YAML:
        return None

    class _StrictLoader(_yaml.SafeLoader):
        pass

    def _construct_mapping(loader, node, deep=False):
        keys = []
        for key_node, _value_node in node.value:
            k = loader.construct_object(key_node, deep=True)
            try:
                dup = k in keys
            except TypeError:  # 不可哈希键（极端构造）
                dup = False
            if dup:
                raise DuplicateKeyError("duplicate key: %r" % (k,))
            keys.append(k)
        return _yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    _StrictLoader.add_constructor(
        _yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
    return _StrictLoader


def find_duplicate_top_keys(text: str):
    """文本层兜底：行首无缩进的 `key:`（含带引号键）出现多次即重复。
    保留以捕获"签名块之后追加伪造顶层块"的攻击形态。"""
    seen = {}
    pat = re.compile(r"""^["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:""")
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line[0].isspace():
            m = pat.match(line)
            if m:
                k = m.group(1)
                seen[k] = seen.get(k, 0) + 1
    return [k for k, v in seen.items() if v > 1]


def check_signature_is_last_block(text: str):
    """校验签名块必须是文件最后一块：'signature:' 首次出现之后不得再出现顶层键。"""
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
            return False
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
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("keys", [])
    except Exception:
        return []


def trust_anchor_match(pub_hex: str, trusted_keys: list) -> bool:
    """A3：公钥必须命中信任锚，且 sha256(公钥hex) 与登记指纹一致。"""
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
# R5-1 严格时间戳与新鲜度
# ----------------------------------------------------------------------------
def parse_issued_at_strict(raw):
    """严格解析 issued_at：必须匹配 ISO 8601 UTC（或带时区偏移）。
    返回 (datetime, error_code)：error_code 为 None 表示解析成功。"""
    if raw in (None, ""):
        return None, "missing"
    s = str(raw).strip().strip('"').strip("'")
    if not ISO_UTC_RE.match(s):
        return None, "bad"
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None, "bad"
    if dt.tzinfo is None:
        return None, "bad"
    return dt, None


def freshness_verdict(issued_dt, now=None, max_age_days=DEFAULT_MAX_AGE_DAYS):
    """返回 None（新鲜）/ 'E_STALE_TIMESTAMP' / 'E_BAD_TIMESTAMP'（未来时间）。"""
    now = now or datetime.now(timezone.utc)
    if issued_dt > now + timedelta(seconds=FUTURE_TOLERANCE_SEC):
        return "E_BAD_TIMESTAMP"
    if (now - issued_dt) > timedelta(days=max_age_days):
        return "E_STALE_TIMESTAMP"
    return None


# ----------------------------------------------------------------------------
# R5-4 工件绑定校验
# ----------------------------------------------------------------------------
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_index_sha256(dir_path: str) -> tuple:
    """返回 (文件数, 清单哈希)。清单 = 按文件名排序的 'name\\tsha256\\n' 拼接（UTF-8）。"""
    names = sorted(n for n in os.listdir(dir_path)
                   if os.path.isfile(os.path.join(dir_path, n)))
    lines = "".join("%s\t%s\n" % (n, sha256_file(os.path.join(dir_path, n)))
                    for n in names)
    return len(names), hashlib.sha256(lines.encode("utf-8")).hexdigest()


def check_artifact_binding(data: dict, base_dir: str, evidence_total: int):
    """R5-4：强制校验 artifact_binding 绑定块。返回失败码列表。"""
    b = data.get("artifact_binding")
    if not isinstance(b, dict):
        return ["E_BINDING_MISMATCH"]
    rf = str(b.get("result_file", "") or "")
    rs = str(b.get("result_sha256", "") or "").lower()
    ad = str(b.get("artifact_dir", "") or "")
    ac = b.get("artifact_count", None)
    ai = str(b.get("artifact_index_sha256", "") or "").lower()
    if not (rf and rs and ad and ai) or not isinstance(ac, int):
        return ["E_BINDING_MISMATCH"]
    errs = []
    rp = os.path.join(base_dir, rf)
    if not os.path.isfile(rp):
        return ["E_BINDING_MISMATCH"]
    if sha256_file(rp) != rs:
        errs.append("E_BINDING_MISMATCH")
    ap = os.path.join(base_dir, ad)
    if not os.path.isdir(ap):
        errs.append("E_BINDING_MISMATCH")
    else:
        n, idx = artifact_index_sha256(ap)
        if n != ac or n != evidence_total:
            errs.append("E_BINDING_MISMATCH")
        if idx != ai:
            errs.append("E_BINDING_MISMATCH")
    return errs


# ----------------------------------------------------------------------------
# 主验证流程
# ----------------------------------------------------------------------------
def verify(path: str, allow_demo: bool = False,
           trusted_keys_path: str = DEFAULT_TRUSTED_KEYS,
           max_age_days: int = DEFAULT_MAX_AGE_DAYS,
           base_dir: str = None) -> str:
    base_dir = base_dir or os.path.dirname(os.path.abspath(path))
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    failures = []

    # ---- X-1：文本层重复顶层键 / 签名块非末块 ----
    if find_duplicate_top_keys(text):
        return "INVALID E_DUPLICATE_KEY"
    if not check_signature_is_last_block(text):
        return "INVALID E_DUPLICATE_KEY"

    # ---- R5-3：构造层重复键（引号键 / 流式映射 / 嵌套）----
    if not HAS_YAML:
        return "INVALID E_YAML_REQUIRED"
    loader = build_strict_loader()
    try:
        data = _yaml.load(text, Loader=loader)
    except DuplicateKeyError:
        return "INVALID E_DUPLICATE_KEY"
    except Exception:
        return "INVALID E_BAD_SIGNATURE"
    if not isinstance(data, dict) or not data:
        return "INVALID E_MISSING_HEADER"

    allowed_algs = ALLOWED_ALGS_DEMO if allow_demo else ALLOWED_ALGS_DEFAULT

    # ---- 1. 完整性：header / evidence / boundary_map ----
    header = data.get("proof_header", {})
    if not isinstance(header, dict) or not header:
        return "INVALID E_MISSING_HEADER"
    for field in REQUIRED_HEADER:
        if field not in header or header[field] in (None, ""):
            failures.append("E_MISSING_HEADER")

    ev_items = data.get("evidence", [])
    if not isinstance(ev_items, list):
        ev_items = []
    ev_names = [str(it.get("test")) for it in ev_items
                if isinstance(it, dict) and it.get("test")]
    for t in CORE_EVIDENCE:
        if t not in ev_names:
            failures.append("E_MISSING_EVIDENCE")
    n_tests = len(ev_names)
    if n_tests not in (4, 5):
        failures.append("E_MISSING_EVIDENCE")

    # ---- 2. 合规性：字段齐全 + passed<=count + metrics 范围 + artifact 目录存在性 ----
    evidence_total = 0
    for it in ev_items:
        if not isinstance(it, dict) or not it.get("test"):
            failures.append("E_BAD_EVIDENCE")
            continue
        for field in ["metrics", "evidence_count", "artifact_ref"]:
            if field not in it or it[field] in (None, ""):
                failures.append("E_BAD_EVIDENCE")
        try:
            pc = int(it.get("passed_count", -1))
            tc = int(it.get("evidence_count", -1))
            if tc >= 0 and (pc < 0 or pc > tc):
                failures.append("E_BAD_EVIDENCE")
            if tc > 0:
                evidence_total += tc
        except Exception:
            failures.append("E_BAD_EVIDENCE")
        metrics = it.get("metrics")
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    failures.append("E_BAD_EVIDENCE")
                elif isinstance(v, int) and k.endswith("count"):
                    if v < 0:
                        failures.append("E_BAD_EVIDENCE")
                elif not (0.0 <= float(v) <= 1.0):
                    failures.append("E_BAD_EVIDENCE")
        art = str(it.get("artifact_ref", ""))
        refs = re.findall(r"[A-Za-z0-9_./*?\-\\]+/[A-Za-z0-9_./*?\-\\]*\.[A-Za-z0-9*]+", art)
        if refs:
            hit = any(len(glob.glob(os.path.join(base_dir, r))) > 0 for r in refs)
            if not hit:
                failures.append("E_BAD_EVIDENCE")
        else:
            dirs = re.findall(r"[A-Za-z0-9_./\-\\]+/", art)
            if dirs and not any(os.path.isdir(os.path.join(base_dir, d)) for d in dirs):
                failures.append("E_BAD_EVIDENCE")

    # ---- 2b. R5-4 工件绑定强制校验（X-2 / P1-3 / P1-4）----
    failures.extend(check_artifact_binding(data, base_dir, evidence_total))

    # ---- 3. boundary_map 引用一致 ----
    bm = data.get("boundary_map", {})
    if not isinstance(bm, dict) or not bm:
        failures.append("E_BAD_MAP_REF")
    else:
        if str(bm.get("schema_version", "")).strip('"') != "0.1":
            failures.append("E_BAD_MAP_REF")
        covered = bm.get("covered_domains", [])
        names = [str(x) for x in covered] if isinstance(covered, list) else []
        for d in COVERED_DOMAINS:
            if d not in names:
                failures.append("E_BAD_MAP_REF")

    # ---- 4. 签名链：规范化签名体 + 算法一致性 + 信任锚 ----
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
        canon_id = str(header.get(CANONICALIZATION_ID if False else
                                  "canonicalization", "")).strip('"') or CANONICALIZATION_ID
        if sig_alg != hdr_alg:
            failures.append("E_BAD_SIGNATURE")
        elif canon_id != CANONICALIZATION_ID:
            failures.append("E_UNKNOWN_ALG")
        elif sig_alg not in allowed_algs:
            failures.append("E_UNKNOWN_ALG" if sig_alg not in ("ed25519", "sha256-demo")
                            else "E_BAD_SIGNATURE")
        else:
            body_data = {k: v for k, v in data.items() if k != "signature"}
            try:
                body = canonical_body(body_data)
            except Exception:
                body = b""
            if sig_alg == "ed25519":
                pub_hex = str(header.get("public_key", "")).strip('"')
                trusted = load_trusted_keys(trusted_keys_path)
                if not trust_anchor_match(pub_hex, trusted):
                    failures.append("E_UNTRUSTED_KEY")
                elif not verify_ed25519(body, sig_val, pub_hex):
                    failures.append("E_BAD_SIGNATURE")
            elif sig_alg == "sha256-demo":
                if not allow_demo:
                    failures.append("E_BAD_SIGNATURE")
                elif not verify_sha256_demo(body, sig_val):
                    failures.append("E_BAD_SIGNATURE")

    # ---- 5. R5-1 严格新鲜度检查 ----
    issued_raw = header.get("issued_at")
    issued_dt, err = parse_issued_at_strict(issued_raw)
    if err == "bad":
        failures.append("E_BAD_TIMESTAMP")
    elif err is None:
        verdict = freshness_verdict(issued_dt, max_age_days=max_age_days)
        if verdict:
            failures.append(verdict)

    if failures:
        return "INVALID " + " ".join(sorted(set(failures)))
    return "VALID"


def main(argv=None):
    ap = argparse.ArgumentParser(description=f"Swordholder 威慑证明验证器 {VERSION}")
    ap.add_argument("proof", nargs="?", default=DEFAULT_PROOF)
    ap.add_argument("--demo", action="store_true", help="允许 sha256-demo 演示签名（默认拒绝）")
    ap.add_argument("--trusted-keys", default=DEFAULT_TRUSTED_KEYS, help="外部信任锚文件路径")
    ap.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS,
                    help=f"凭证新鲜度阈值（天，默认 {DEFAULT_MAX_AGE_DAYS}）")
    ap.add_argument("--base-dir", default=None,
                    help="工件绑定校验的基准目录（默认取凭证文件所在目录）")
    args = ap.parse_args(argv)
    result = verify(args.proof, allow_demo=args.demo,
                    trusted_keys_path=args.trusted_keys,
                    max_age_days=args.max_age_days, base_dir=args.base_dir)
    print(f"[verify_proof {VERSION}] {os.path.basename(args.proof)} -> {result}")
    return 0 if result.startswith("VALID") else 1


if __name__ == "__main__":
    sys.exit(main())
