"""Swordholder MCP Server 自测：走真实 stdio 协议，不做任何 mock。

覆盖：initialize → tools/list → keygen → seal_record → verify_seal（正常 / 篡改 payload /
篡改 header / 未登记公钥）→ verify_proof（真实凭证 4 份）→ 未知工具报错。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SERVER = os.path.join(HERE, "server.py")

# Windows CI 默认 stdout 编码为 cp1252，中文断言说明会直接抛 UnicodeEncodeError
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass


class Client:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, SERVER], cwd=REPO_ROOT,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self._id = 0

    def rpc(self, method, params=None):
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        self.p.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def call(self, name, args):
        return self.rpc("tools/call", {"name": name, "arguments": args})

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def payload_of(resp):
    return json.loads(resp["result"]["content"][0]["text"])


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="swordholder_mcp_test_")
    checks = []

    def check(name, cond, extra=""):
        checks.append((name, bool(cond), extra))
        print(("  PASS " if cond else "  FAIL ") + name + (f"  {extra}" if extra else ""))

    c = Client()
    try:
        init = c.rpc("initialize", {"protocolVersion": "2024-11-05",
                                    "clientInfo": {"name": "selftest", "version": "0"}})
        check("initialize 返回 serverInfo", init["result"]["serverInfo"]["name"] == "swordholder-mcp")

        lst = c.rpc("tools/list")
        names = [t["name"] for t in lst["result"]["tools"]]
        check("tools/list 暴露 5 个工具", len(names) == 5, str(names))

        kg = payload_of(c.call("keygen", {"out_dir": tmp}))
        check("keygen 生成私钥与公钥", kg.get("ok") and len(kg.get("public_key_hex", "")) == 64)

        record = {"alert_id": "ALRT-2026-1023-001", "asset": "build-runner-07",
                  "signal": "unexpected outbound TLS to new ASN",
                  "verdict": "true_positive", "severity": "high",
                  "actions": ["isolate host", "rotate CI token"], "confidence": 0.86}
        rec_path = os.path.join(tmp, "triage.json")
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)

        sealed = payload_of(c.call("seal_record", {
            "record_path": rec_path,
            "private_key_path": kg["private_key_path"],
            "issuer": "selftest/triage",
            "subject": record["alert_id"],
            "out_path": os.path.join(tmp, "triage.seal.json")}))
        check("seal_record 落盘", sealed.get("ok") and os.path.exists(sealed.get("seal_path", "")))
        seal_path = sealed["seal_path"]

        good = payload_of(c.call("verify_seal", {"seal_path": seal_path}))
        check("verify_seal 正常凭证 VALID_UNTRUSTED_KEY", good.get("verdict") == "VALID_UNTRUSTED_KEY", good.get("reason"))

        # 篡改 payload
        tampered = os.path.join(tmp, "tampered.seal.json")
        data = json.load(open(seal_path, encoding="utf-8"))
        data["payload"]["verdict"] = "false_positive"
        json.dump(data, open(tampered, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        bad = payload_of(c.call("verify_seal", {"seal_path": tampered}))
        check("篡改 payload 被判 E_PAYLOAD_TAMPERED", bad.get("reason") == "E_PAYLOAD_TAMPERED", bad.get("reason"))

        # 篡改 header
        tampered2 = os.path.join(tmp, "tampered2.seal.json")
        data = json.load(open(seal_path, encoding="utf-8"))
        data["seal_header"]["issuer"] = "someone-else"
        json.dump(data, open(tampered2, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        bad2 = payload_of(c.call("verify_seal", {"seal_path": tampered2}))
        check("篡改 header 被判 E_BAD_SIGNATURE", bad2.get("reason") == "E_BAD_SIGNATURE", bad2.get("reason"))

        proofs_dir = os.path.join(REPO_ROOT, "proofs")
        if not os.path.isdir(proofs_dir):
            # pip 安装后的 site-packages 不含仓库根的 proofs/：给出可执行的提示，而不是抛 FileNotFoundError
            print(f"  SKIP verify_proof：未找到 {proofs_dir}")
            print("       该断言需在源码仓库根目录运行（pip 安装后的包内不含 proofs/）")
            proofs = []
        else:
            proofs = sorted(f for f in os.listdir(proofs_dir) if f.endswith(".yaml"))
        ok_n = 0
        for f in proofs:
            r = payload_of(c.call("verify_proof", {"proof_path": os.path.join("proofs", f)}))
            if str(r.get("verdict", "")).startswith("VALID"):
                ok_n += 1
        if proofs:
            check(f"verify_proof 通过 {ok_n}/{len(proofs)} 份真实凭证", ok_n == len(proofs) == 4, f"{ok_n}/{len(proofs)}")

        if os.path.isfile(os.path.join(REPO_ROOT, "trusted_keys.json")):
            keys = payload_of(c.call("list_trusted_keys", {}))
            check("list_trusted_keys 可列出信任锚", keys.get("ok") and keys.get("count", 0) >= 1, str(keys.get("count")))
        else:
            print("  SKIP list_trusted_keys：仓库根的 trusted_keys.json 不存在（安装包内不含信任锚）")

        unk = c.call("unknown_tool", {})
        check("未知工具返回 -32601", unk.get("error", {}).get("code") == -32601)
    finally:
        c.close()
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"\n结果：{passed}/{len(checks)} 通过")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
