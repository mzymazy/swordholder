# -*- coding: utf-8 -*-
"""生成用于演示 / 自签的 ed25519 密钥对（本仓库不携带任何私钥）。

用途
----
让外部开发者在**本机**完成「出证 → 验签」闭环：仓库只提供签名与验证代码，
签名私钥由使用者自行生成、自行保管、不入库。

安全边界（重要）
----------------
本脚本生成的密钥**不在**仓库信任锚 ``trusted_keys.json`` 内：

* 用官方信任锚校验你自签的凭证 → ``INVALID``（``E_UNTRUSTED_KEY``）——这是预期行为；
* 想得到 ``VALID`` 需自建本地信任锚（``--trusted-out`` 会生成一份可直接使用的示例）。

用法
----
::

    # 1) 生成私钥（默认写 $env:TEMP / $TMPDIR，也可指定到任意路径）
    python scripts/gen_demo_key.py --key temp/demo_ed25519_key.pem

    # 2) 顺带导出本地信任锚，便于自签凭证被判 VALID
    python scripts/gen_demo_key.py --key temp/demo_ed25519_key.pem \
        --trusted-out temp/demo_trusted_keys.json

    # 3) 出证（演示口径，不可与官方四态凭证混用）
    python gen_proof.py --result evaluation_results_v2.json --algo ed25519 \
        --key temp/demo_ed25519_key.pem --status demo-self-signed \
        --out temp/demo_proof.yaml

    # 4) 自验（自建锚 → VALID；官方锚 → INVALID E_UNTRUSTED_KEY）
    python verify_proof.py temp/demo_proof.yaml --trusted-keys temp/demo_trusted_keys.json --base-dir .
"""
import argparse
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def main(argv=None):
    ap = argparse.ArgumentParser(description="生成演示用 ed25519 密钥对（不入库）")
    default_key = os.path.join(os.environ.get("TEMP", "."), "swordholder_ed25519_demo_key.pem")
    ap.add_argument("--key", default=default_key, help="私钥输出路径（PEM/PKCS8，无口令）")
    ap.add_argument("--trusted-out", default=None,
                    help="可选：同时导出本地信任锚 JSON（仅含本次生成的公钥）")
    ap.add_argument("--key-id", default="k-ed25519-demo-local", help="信任锚里登记的 key_id")
    args = ap.parse_args(argv)

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = os.path.abspath(args.key)
    parent = os.path.dirname(key_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(pem)
    try:  # 仅 POSIX 生效；Windows 请自行用 ACL 收紧
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    pub_hex = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    fingerprint = hashlib.sha256(pub_hex.encode("ascii")).hexdigest()

    print("已生成演示私钥（请勿提交到版本库）：%s" % key_path)
    print("  public_key_hex      : %s" % pub_hex)
    print("  fingerprint_sha256  : %s" % fingerprint)
    print("  [注意] 该公钥不在仓库信任锚内，自签凭证在官方锚下会被判 INVALID (E_UNTRUSTED_KEY)")

    if args.trusted_out:
        doc = {
            "trust_root": "swordholder-eval/0.1.0 (local demo anchor)",
            "keys": [{
                "key_id": args.key_id,
                "algorithm": "ed25519",
                "public_key_hex": pub_hex,
                "fingerprint_sha256": fingerprint,
            }],
        }
        out = os.path.abspath(args.trusted_out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("已写出本地信任锚（用于自验自签凭证）：%s" % out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
