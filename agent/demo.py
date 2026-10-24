"""端到端演示：告警 → 分诊 → 盖章 → 验签 → 篡改 → 检出。

用法：
    python agent/demo.py                 # 规则引擎（默认，离线可跑）
    python agent/demo.py --llm           # 规则 + 本地 Ollama 增强（可选）
    python agent/demo.py --out D:\\tmp    # 指定输出目录
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for p in (REPO_ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import triage as triage_mod          # noqa: E402  agent/triage.py
from mcp_server import server as mcp  # noqa: E402  mcp_server/server.py

SAMPLES = [
    "alert_01_egress.json",
    "alert_02_token.json",
    "alert_03_supplychain.json",
]


def ensure_key(keys_dir: str) -> dict:
    key_path = os.path.join(keys_dir, "swordholder_ed25519_private.pem")
    if os.path.exists(key_path):
        return {"ok": True, "private_key_path": key_path, "reused": True}
    res = mcp.tool_keygen({"out_dir": keys_dir})
    if not res.get("ok"):
        raise SystemExit("生成密钥失败：" + res.get("error", ""))
    res["reused"] = False
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="启用本地 Ollama 增强")
    ap.add_argument("--out", default=os.path.join(HERE, ".demo_out"))
    args = ap.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    keys_dir = os.path.join(REPO_ROOT, "keys")
    key = ensure_key(keys_dir)

    rows = []
    tamper_ok = False
    for name in SAMPLES:
        alert_path = os.path.join(HERE, "samples", name)
        alert = triage_mod.load_alert(alert_path)

        result = triage_mod.triage(alert, use_llm=args.llm)
        record_path = os.path.join(out_dir, os.path.splitext(name)[0] + ".triage.json")
        with open(record_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        sealed = mcp.tool_seal_record({
            "record_path": record_path,
            "private_key_path": key["private_key_path"],
            "issuer": "swordholder-triage/0.1.0",
            "subject": result.get("alert_id"),
            "out_path": record_path.replace(".triage.json", ".seal.json"),
        })
        if not sealed.get("ok"):
            raise SystemExit("盖章失败：" + sealed.get("error", ""))

        verdict = mcp.tool_verify_seal({"seal_path": sealed["seal_path"]})
        rows.append({
            "alert_id": result.get("alert_id"),
            "asset": result.get("asset"),
            "verdict": result.get("verdict"),
            "severity": result.get("severity"),
            "confidence": result.get("confidence"),
            "engine": result.get("engine"),
            "seal_ok": verdict.get("verdict") == "VALID_UNTRUSTED_KEY",
            "seal_path": sealed["seal_path"],
            "payload_sha256": sealed["payload_sha256"][:16] + "…",
        })

    # 篡改演示：把第一条结论从 true_positive 改成 false_positive
    src = rows[0]["seal_path"]
    tampered_path = os.path.join(out_dir, "tampered.seal.json")
    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
    original_verdict = data["payload"].get("verdict")
    data["payload"]["verdict"] = "false_positive"
    data["payload"]["actions"] = []
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tampered = mcp.tool_verify_seal({"seal_path": tampered_path})
    tamper_ok = tampered.get("reason") == "E_PAYLOAD_TAMPERED"

    # 报告
    report_path = os.path.join(out_dir, "demo_report.md")
    lines = [
        "# Swordholder — Evidence-Sealed Triage 演示报告",
        "",
        f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　引擎：{'rules+llm' if args.llm else 'rules-v1'}",
        f"签发公钥：`{key.get('public_key_hex', '(已存在，未回显)')}`",
        "",
        "| 告警 | 资产 | 结论 | 严重度 | 置信度 | 盖章验签 | 记录摘要 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['alert_id']} | {r['asset']} | {r['verdict']} | {r['severity']} | "
            f"{r['confidence']} | {'VALID' if r['seal_ok'] else 'FAIL'} | `{r['payload_sha256']}` |")
    lines += [
        "",
        "## 篡改演示",
        "",
        f"取第 1 条凭证，把 `verdict` 由 `{original_verdict}` 改为 `false_positive`、清空 `actions`，"
        f"不重新签名，再次验签结果：",
        "",
        f"- 判决：`{tampered.get('verdict')}`　原因码：`{tampered.get('reason')}`",
        f"- 期望摘要：`{tampered.get('expected')}`",
        f"- 实际摘要：`{tampered.get('actual')}`",
        "",
        "结论：记录被改动后，验签方无需信任签发方、也无需源码，即可判定该记录不可采信。",
        "",
        f"## 产物\n\n- 分诊记录与凭证：`{out_dir}`\n- 篡改样本：`{tampered_path}`",
    ]
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(json.dumps({
        "rows": rows,
        "tamper": {"verdict": tampered.get("verdict"), "reason": tampered.get("reason"),
                   "expected": tamper_ok},
        "report": report_path,
        "out_dir": out_dir,
    }, ensure_ascii=False, indent=2))

    all_sealed = all(r["seal_ok"] for r in rows)
    if not (all_sealed and tamper_ok):
        print("演示失败：盖章或篡改检出未达预期", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
