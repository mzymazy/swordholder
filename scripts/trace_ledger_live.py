"""动作账本接线的可复现实跑：脚本化 LLM 驱动 run_agent，产出真实账本与签章。

为什么用脚本化 LLM 而不是真模型：这里要证明的是"接线"——
每一步动作到底有没有进链、链能不能被独立复核、签章能不能被判 VALID。
模型换成谁不影响这三件事；换成本机 Ollama 反而把"有没有模型可用"混进了结论。
真模型路径由 scripts/demo_agent_loop.py 覆盖（那边看的是判定质量）。

用法（仓库根目录）：
    .venv\\Scripts\\python.exe scripts\\trace_ledger_live.py

产物：
    evidence/epistemics/ledger_live/<alert_id>.ledger.json      链式账本（可离线 verify_chain）
    evidence/epistemics/ledger_live/<alert_id>.ledger.seal.json 账本凭证（可 verify_sealed_trace）
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from swordholder import agent_loop, core, trace_ledger  # noqa: E402
from swordholder.alert import normalize  # noqa: E402

OUT_DIR = os.path.join(ROOT, "evidence", "epistemics", "ledger_live")
KEY = os.path.join(ROOT, "keys", "swordholder_ed25519_private.pem")
ANCHOR = os.path.join(ROOT, "trusted_keys.json")

# 三次真实工具调用 + 一次提交：每一步都该在链里留下一条可核对的条目。
SCRIPT = [
    {"thought": "先看资产画像", "action": "get_asset_profile", "args": {"asset": "build-runner-07"}},
    {"thought": "再看主机外联", "action": "get_process_tree", "args": {"host": "build-runner-07"}},
    {"thought": "再看历史告警", "action": "search_prior_alerts", "args": {"entity": "build-runner-07"}},
    {
        "thought": "三次取证相互印证，提交判定",
        "action": "submit_verdict",
        "args": {
            "verdict": "true_positive",
            "severity": "high",
            "confidence": 0.88,
            "hypothesis": "构建机向基线外 ASN 发起 TLS，且 CI token 在异地被调用，疑似凭据外泄后的外联。",
            "actions": ["阻断目标 ASN 出站", "吊销并轮换 CI token", "回溯 7 天该 token 调用记录"],
            "evidence_refs": ["step.1", "step.2", "step.3"],
        },
    },
]


def _alert() -> dict:
    return normalize({
        "alert_id": "ALRT-LEDGER-LIVE-0001",
        "title": "Build runner made outbound TLS to unknown ASN",
        "asset": "build-runner-07",
        "severity": "high",
        "signal": "unexpected outbound TLS to unknown ASN 215199",
        "tags": ["egress", "ci"],
        "description": "构建机向未登记 ASN 建立长连接。",
        "observed": {"first_seen": "2026-11-02T03:14:00Z", "connections": 6},
    })


def main() -> int:
    if not os.path.exists(KEY):
        print(f"[skip] 缺少私钥 {KEY}，无法演示签章")
        return 1
    os.makedirs(OUT_DIR, exist_ok=True)

    seq = list(SCRIPT)

    def fake_call_llm(system, prompt, cfg=None, timeout=90):
        return json.dumps(seq.pop(0), ensure_ascii=False) if seq else "{}"

    agent_loop.call_llm = fake_call_llm

    alert = _alert()
    ledger_out = os.path.join(OUT_DIR, f"{alert['alert_id']}.ledger.json")
    seal_out = os.path.join(OUT_DIR, f"{alert['alert_id']}.ledger.seal.json")
    trace = agent_loop.run_agent(
        alert,
        cfg={"provider": "scripted", "model": "scripted-1", "base": "", "api_key": ""},
        key_path=KEY,
        seal_out_dir=os.path.join(OUT_DIR, "seals"),
        ledger_out=ledger_out,
        ledger_seal_out=seal_out,
    )

    led = trace["ledger"]
    with open(ledger_out, encoding="utf-8") as f:
        body = json.load(f)
    chain = trace_ledger.verify_chain(body)
    sealed = trace_ledger.verify_sealed_trace(body, seal_out, keys_path=ANCHOR) \
        if os.path.exists(seal_out) else {"verdict": "MISSING", "reason": ""}

    print(f"verdict={trace.get('verdict')} engine={trace.get('engine')}")
    print(f"ledger={ledger_out}")
    print(f"step_count={led['step_count']} head={led['head'][:16]}...")
    print(f"chain_ok={chain['ok']} first_break={chain['first_break']}")
    print(f"seal_verdict={sealed['verdict']} {sealed.get('reason', '')}")
    print("entries:")
    for e in body["entries"]:
        print(f"  {e['n']:>2} {e['action']:<20} hash={e['hash'][:12]}... "
              f"obs_ok={e['observation'].get('ok') if isinstance(e['observation'], dict) else '-'}")

    ok = chain["ok"] and sealed["verdict"] == "VALID" and led["step_count"] == len(trace["steps"]) + 3
    print("RESULT:", "PASS" if ok else "FAIL")

    # 把落盘账本改一格再复核：同一份文件、同一个验证器，只多了一次手改。
    # 这一步是为了让"改了会被发现"在现场可演示，而不是只写在文档里。
    tampered = json.loads(json.dumps(body))
    victim = 3 if len(tampered["entries"]) > 3 else 0
    tampered["entries"][victim]["observation"]["ok"] = False
    tampered_path = ledger_out.replace(".ledger.json", ".ledger.tampered.json")
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(tampered, f, ensure_ascii=False, indent=2)
    t_chain = trace_ledger.verify_chain(tampered)
    t_sealed = trace_ledger.verify_sealed_trace(tampered, seal_out, keys_path=ANCHOR) \
        if os.path.exists(seal_out) else {"verdict": "MISSING", "reason": ""}
    print(f"tampered={tampered_path}")
    print(f"tampered_chain_ok={t_chain['ok']} first_break={t_chain['first_break']} "
          f"reason={t_chain['reason']}")
    print(f"tampered_seal_verdict={t_sealed['verdict']} reason={t_sealed.get('reason', '')}")

    ok = ok and t_chain["ok"] is False and t_chain["first_break"] == victim \
        and t_sealed["verdict"] == "INVALID"
    print("FINAL:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
