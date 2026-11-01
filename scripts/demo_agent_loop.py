"""Swordholder agent-loop 端到端演示：跑真实模型，产出可验签凭证与完整 trace。

用法（本仓库根目录）：
    python scripts/demo_agent_loop.py                 # 默认本机 Ollama qwen3:8b
    SWORDHOLDER_MODEL=qwen3:30b python scripts/demo_agent_loop.py
    SWORDHOLDER_LLM_PROVIDER=anthropic ANTHROPIC_API_KEY=... python scripts/demo_agent_loop.py

产物：evidence/agent_lab/runs/<alert_id>.trace.json 与 <alert_id>.agent.seal.json
"""

from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from swordholder import agent_loop, core, rules  # noqa: E402
from swordholder.alert import normalize_file  # noqa: E402

CASES = [
    ("供应链投毒（postinstall 下载并执行）", os.path.join(ROOT, "swordholder", "samples", "alert_03_supplychain.json")),
    ("构建机外联未知 ASN（持 CI token）", os.path.join(ROOT, "swordholder", "samples", "alert_01_egress.json")),
    ("告警文本内嵌指令注入", os.path.join(ROOT, "evidence", "agent_lab", "alert_injection.json")),
]

KEY = os.path.join(ROOT, "keys", "swordholder_ed25519_private.pem")
RUN_DIR = os.path.join(ROOT, "evidence", "agent_lab", "runs")
SEAL_DIR = os.path.join(RUN_DIR, "seals")


def main() -> int:
    os.makedirs(RUN_DIR, exist_ok=True)
    cfg = agent_loop.provider_config()
    print(f"provider={cfg['provider']} model={cfg['model']} key={'yes' if os.path.exists(KEY) else 'no'}")
    rows = []

    for title, path in CASES:
        alert = normalize_file(path)
        t0 = time.time()
        trace = agent_loop.run_agent(alert, key_path=KEY if os.path.exists(KEY) else None,
                                     seal_out_dir=SEAL_DIR)
        dt = round(time.time() - t0, 1)
        out = os.path.join(RUN_DIR, f"{alert.get('alert_id')}.trace.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(trace, f, ensure_ascii=False, indent=2)

        seal_check = ""
        if trace.get("seal", {}).get("seal_path") and os.path.exists(trace["seal"]["seal_path"]):
            # 用仓库根信任锚验证：VALID 表示签名完整且签发方已登记为可信
            res = core.verify(trace["seal"]["seal_path"])
            seal_check = res.get("verdict", "")

        rows.append({
            "case": title,
            "alert_id": alert.get("alert_id"),
            "rule": rules.rule_triage(alert)["verdict"],
            "agent": trace.get("verdict"),
            "engine": trace.get("engine"),
            "confidence": (trace.get("guardrail") or {}).get("confidence"),
            "steps": len(trace.get("steps", [])),
            "rejected": len((trace.get("guardrail") or {}).get("rejected", [])),
            "sealed": seal_check,
            "seconds": dt,
            "trace": os.path.relpath(out, ROOT),
        })

    width = max(len(r["case"]) for r in rows) + 2
    print(f"{'case'.ljust(width)}rule -> agent          engine                       steps rej seal   t(s)")
    for r in rows:
        print(f"{r['case'].ljust(width)}{r['rule']:<18}-> {(r['agent'] or ''):<14} "
              f"{r['engine'][:26]:<26} {r['steps']:>4} {r['rejected']:>3}  "
              f"{r['sealed']:<8} {r['seconds']}")

    with open(os.path.join(RUN_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"provider": cfg, "rows": rows}, f, ensure_ascii=False, indent=2)
    print(f"\nsummary -> {os.path.relpath(os.path.join(RUN_DIR, 'summary.json'), ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
