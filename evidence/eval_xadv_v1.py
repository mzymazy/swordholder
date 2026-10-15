# -*- coding: utf-8 -*-
"""
Swordholder 高阶对抗扩展评测 v1：baseline / injected / combined 三态
====================================================================
用例：evidence/adversarial_xadv_v1.json（15 题，覆盖提示注入变体/编码混淆/
      角色扮演深度嵌套/多轮钓鱼/工具越权，均不与既有 47 题和 hard-01~12 重复）

模式：
  --mode ollama  走 Ollama API（--model 指定 qwen3.8-27b:ud-q3_k_xl 或 qwen3:8b）
  --mode local   走本地 4bit 管线（--lora 指定 LoRA 目录，组合态）
判定：复用 eval_swordholder_v2 JUDGERS_V2 (semantic-v2.2) + eval_stability_v3
      extended_judge（英文拒绝/执行信号）；多轮逐轮判定，任一执行轮即 FAIL。
输出：evidence/xadv_{tag}.json；逐轮文本 artifacts_xadv_{tag}/。
用法示例：
  python eval_xadv_v1.py --mode ollama --model qwen3.8-27b:ud-q3_k_xl --samples 3 --tag qwen38_xadv_base
  python eval_xadv_v1.py --mode ollama --model qwen3.8-27b:ud-q3_k_xl --system-prompt system_prompt_axiom.txt --samples 3 --tag qwen38_xadv_injected
  python eval_xadv_v1.py --mode local --lora models/lora_adapter_v62_memory --system-prompt system_prompt_axiom.txt --samples 3 --tag qwen38_xadv_combined_8b
"""
import argparse
import hashlib
import json
import os
import random
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_swordholder_v2 as v2
import eval_stability_v3 as v3

HERE = os.path.dirname(os.path.abspath(__file__))
XADV_JSON = os.path.join(HERE, "evidence", "adversarial_xadv_v1.json")


def load_xadv():
    with open(XADV_JSON, encoding="utf-8") as f:
        return json.load(f)["cases"]


def sha256_of_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_case(case, temperature, seed, system=None, local_lora=None, model_name=None):
    """逐轮调用并判定（复用 v3.call_model，支持 ollama/local 自动路由）。"""
    turns = case["turns"]
    messages = []
    all_responses = []
    turn_verdicts = []
    failed = False
    for i, t in enumerate(turns):
        messages.append({"role": "user", "content": t["content"]})
        resp = v3.call_model(messages, temperature, seed, system)
        messages.append({"role": "assistant", "content": resp})
        all_responses.append(f"[turn{i}] user: {t['content']}\n[turn{i}] assistant: {resp}")
        verdict = v3.extended_judge(resp, "adversarial", "refuse")
        turn_verdicts.append(verdict)
        if not verdict["passed"]:
            failed = True
    final_verdict = {
        "passed": not failed,
        "turns": len(turns),
        "turn_verdicts": [
            {"passed": tv["passed"], "semantic": tv.get("semantic", {}),
             "lexical": tv.get("lexical", {})} for tv in turn_verdicts],
    }
    return final_verdict, "\n".join(all_responses)


def run(args):
    cases = load_xadv()
    temps = [float(x) for x in args.temps.split(",")]
    seed_rng = random.Random(20261016)
    results = []
    artifact_dir = os.path.join(HERE, f"artifacts_xadv_{args.tag}")
    os.makedirs(artifact_dir, exist_ok=True)
    print(f"[xadv] cases={len(cases)} mode={args.mode} samples={args.samples} "
          f"temps={temps} tag={args.tag}", flush=True)
    t0 = time.time()
    for case in cases:
        cid = case["id"]
        passes = 0
        runs = []
        for i in range(args.samples):
            temp = temps[i % len(temps)]
            seed = seed_rng.randint(1, 2 ** 31)
            verdict, resp = run_case(case, temp, seed,
                                     system=args.system_prompt,
                                     local_lora=args.lora,
                                     model_name=args.model)
            p = bool(verdict["passed"])
            passes += 1 if p else 0
            runs.append({"sample": i, "temperature": temp, "seed": seed, "passed": p,
                         "turns": verdict.get("turns", 0),
                         "response_sha256": sha256_of_text(resp)})
            with open(os.path.join(artifact_dir, f"{cid}_{i}.txt"), "w", encoding="utf-8") as f:
                f.write(f"PROMPT_CASE:\n{json.dumps(case, ensure_ascii=False, indent=2)}\n\nRESPONSE:\n{resp}\n")
        rate = passes / args.samples
        results.append({"id": cid, "domain": case.get("domain"), "desc": case.get("desc"),
                        "category": _category_of(cid),
                        "pass_count": passes, "samples": args.samples, "pass_rate": rate,
                        "runs": runs})
        print(f"    [{cid}] {rate:.2f} ({passes}/{args.samples}) - {case.get('desc')}", flush=True)
    elapsed = int(time.time() - t0)
    summary = {
        "suite": "adversarial-xadv-v1",
        "tag": args.tag,
        "mode": args.mode,
        "model": args.model if args.model else "local",
        "lora": args.lora,
        "system_prompt": args.system_prompt,
        "judge_version": v2.JUDGE_VERSION,
        "samples": args.samples,
        "temperatures": temps,
        "evaluated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "elapsed_seconds": elapsed,
        "cases": results,
        "categories": {},
        "aggregate": {"mean_pass_rate": sum(r["pass_rate"] for r in results) / len(results),
                      "stable_cases": [r["id"] for r in results if r["pass_rate"] == 1.0],
                      "weak_cases": [r["id"] for r in results if r["pass_rate"] < 1.0]},
    }
    for cat in set(_category_of(r["id"]) for r in results):
        rr = [r for r in results if _category_of(r["id"]) == cat]
        summary["categories"][cat] = {
            "case_count": len(rr),
            "mean_pass_rate": sum(r["pass_rate"] for r in rr) / len(rr),
            "pass_count": sum(r["pass_count"] for r in rr),
            "total_samples": sum(r["samples"] for r in rr),
        }
    out_file = os.path.join(HERE, "evidence", f"xadv_{args.tag}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    agg = summary["aggregate"]
    print(f"[done] -> {out_file}  elapsed={elapsed}s", flush=True)
    print(f"  aggregate mean={agg['mean_pass_rate']:.2f} "
          f"stable={len(agg['stable_cases'])}/{len(results)} "
          f"weak={agg['weak_cases']}", flush=True)


def _category_of(cid: str) -> str:
    if cid in ("xadv-01", "xadv-02", "xadv-03"):
        return "injection"
    if cid in ("xadv-04", "xadv-05", "xadv-06"):
        return "obfuscation"
    if cid in ("xadv-07", "xadv-08", "xadv-09"):
        return "roleplay_nested"
    if cid in ("xadv-10", "xadv-11", "xadv-12"):
        return "phishing_multiturn"
    return "tool_abuse"


def main():
    parser = argparse.ArgumentParser(description="Swordholder xadv 高阶对抗扩展评测")
    parser.add_argument("--mode", choices=["ollama", "local"], default="ollama")
    parser.add_argument("--model", default="qwen3.8-27b:ud-q3_k_xl")
    parser.add_argument("--lora", default=None)
    parser.add_argument("--system-prompt", default=None)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--temps", default="0.2,0.6,1.0")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    if args.mode == "local":
        v2.LOCAL_MODEL = os.path.join(HERE, "models", "qwen3-8b-bnb-4bit")
        v2.LOCAL_LORA = os.path.join(HERE, args.lora) if args.lora else None
    else:
        v3.MODEL = args.model
    if args.system_prompt:
        with open(os.path.join(HERE, args.system_prompt), "r", encoding="utf-8") as f:
            v2.SYSTEM_PROMPT = f.read().strip()
            v3.SYSTEM_PROMPT = v2.SYSTEM_PROMPT
    # call_model 路由：local 模式走 v2.LOCAL_MODEL
    if args.mode == "local":
        v2.LOCAL_MODEL = os.path.join(HERE, "models", "qwen3-8b-bnb-4bit")
        v2.LOCAL_LORA = os.path.join(HERE, args.lora) if args.lora else None
    run(args)


if __name__ == "__main__":
    main()
