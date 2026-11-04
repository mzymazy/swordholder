"""Pitch Day 离线演示：回放已存证的 agent trace，并对真实 seal 文件跑真实验签。

为什么需要它：
    现场演示 agent 自主分诊需要本机模型服务在线（Ollama / API）。会场网络、
    笔记本负载、模型未起，任一环节出问题都会让演示中断。本脚本把"模型推理"
    这一段换成回放已落盘的 trace（真实跑出来的记录），而"盖章 / 验签"仍然是
    当前机器上真算的——评委可以当场自己拿 seal 文件验。

用法（仓库根目录，无需模型、无需联网）：
    python scripts/demo_pitch_replay.py                  # 默认存证布局，三案全放
    python scripts/demo_pitch_replay.py --list           # 列出可用存证布局与案卷
    python scripts/demo_pitch_replay.py --model qwen3_8b # 指定 runs/ 下的子目录布局
    python scripts/demo_pitch_replay.py --case ALRT-2026-1104-0003
    python scripts/demo_pitch_replay.py --fast           # 不逐字停顿
    python scripts/demo_pitch_replay.py --verify-all     # 只批量验签所有 seal

退出码：全部 seal 验签通过返回 0，否则返回 1（便于现场判断演示是否可上）。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

RUNS = os.path.join(ROOT, "evidence", "agent_lab", "runs")
FLAT = ""  # 空串表示 runs/ 根目录（扁平存证布局）

VERDICT_ZH = {
    "true_positive": "真阳（需处置）",
    "false_positive": "误报（可关闭）",
    "suspicious": "可疑（需人工复核）",
    "benign": "无害",
}


# ---------------------------------------------------------------- 终端着色（无依赖）
def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        k.SetConsoleMode(h, mode.value | 0x0004)
        return True
    except Exception:
        return False


ANSI = _enable_ansi()


def c(text: str, code: str) -> str:
    if not ANSI:
        return text
    return f"\033[{code}m{text}\033[0m"


DIM, BOLD = "2", "1"
GREEN, RED, YELLOW, CYAN, MAG = "32", "31", "33", "36", "35"


def hr(ch: str = "─", n: int = 78) -> str:
    return c(ch * n, DIM)


# ---------------------------------------------------------------- 数据发现
def list_models() -> list[str]:
    if not os.path.isdir(RUNS):
        return []
    out = []
    # 扁平布局：trace 直接放在 runs/ 下
    if any(f.endswith(".trace.json") for f in os.listdir(RUNS)):
        out.append(FLAT)
    # 分层布局：runs/<model>/*.trace.json
    for d in sorted(os.listdir(RUNS)):
        p = os.path.join(RUNS, d)
        if os.path.isdir(p) and d != "seals" and any(
            f.endswith(".trace.json") for f in os.listdir(p)
        ):
            out.append(d)
    return out


def trace_files(model: str) -> list[tuple[str, str]]:
    """返回 [(alert_id, trace 路径)]，兼容 runs/ 扁平与 runs/<model>/ 分层两种存证布局。"""
    d = RUNS if model == FLAT else os.path.join(RUNS, model)
    if not os.path.isdir(d):
        return []
    return sorted(
        (f[: -len(".trace.json")], os.path.join(d, f))
        for f in os.listdir(d)
        if f.endswith(".trace.json")
    )


def traces_of(model: str) -> list[str]:
    return [aid for aid, _ in trace_files(model)]


def trace_path(model: str, aid: str) -> str | None:
    for a, p in trace_files(model):
        if a == aid:
            return p
    return None


def model_label(model: str) -> str:
    if model != FLAT:
        return model
    return "evidence/agent_lab/runs（扁平存证）"


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def resolve_seal(trace: dict, model: str) -> str | None:
    """trace 里记的绝对路径可能来自别的机器/别的输出目录，按约定位置回退查找。"""
    cand = []
    sp = (trace.get("seal") or {}).get("seal_path")
    if sp:
        cand.append(sp)
        cand.append(os.path.join(os.path.dirname(sp), os.path.basename(sp)))
    aid = trace.get("alert_id", "")
    d = os.path.join(RUNS, model)
    for base in (d, RUNS):
        cand += [
            os.path.join(base, "seals", f"{aid}.agent.seal.json"),
            os.path.join(base, f"{aid}.agent.seal.json"),
        ]
    # trace 里记的模型名（qwen3:8b）与存证目录名（qwen3_8b）不同，先按归一化目录找
    tm = (trace.get("model") or "").replace(":", "_")
    if tm and tm != model:
        tb = os.path.join(RUNS, tm)
        cand += [
            os.path.join(tb, "seals", f"{aid}.agent.seal.json"),
            os.path.join(tb, f"{aid}.agent.seal.json"),
        ]
    # 兜底：扁平布局下 trace 与 seal 可能分居不同子目录，按 alert_id 全树找一遍
    cand += sorted(glob.glob(os.path.join(RUNS, "*", "seals", f"{aid}.agent.seal.json")))
    cand += sorted(glob.glob(os.path.join(RUNS, "*", f"{aid}.agent.seal.json")))
    for p in cand:
        if p and os.path.exists(p):
            return p
    return None


# ---------------------------------------------------------------- 回放渲染
def render_step(st: dict, pause: float) -> None:
    n = st.get("step")
    act = st.get("action", "?")
    args = st.get("args") or {}
    thought = (st.get("thought") or "").strip()

    if act == "submit_verdict":
        print(c(f"  [{n}] submit_verdict", BOLD + ";" + MAG), c("← 交结论（受护栏约束）", DIM))
    else:
        argtxt = ", ".join(f"{k}={v}" for k, v in args.items() if not isinstance(v, (dict, list)))
        print(c(f"  [{n}] {act}", BOLD + ";" + CYAN), c(f"({argtxt})", DIM))

    if thought:
        print(c(f"       思考：{thought}", DIM))

    # 结果摘要：只挑现场看得懂的字段
    res = st.get("result")
    if isinstance(res, dict):
        bits = []
        if res.get("found") is False:
            bits.append(c("无记录", YELLOW))
            if res.get("note"):
                bits.append(res["note"])
        else:
            for key in ("reputation", "author", "weekly_downloads", "note", "indicator"):
                if key in res:
                    v = res[key]
                    if key == "reputation" and v == "malicious":
                        bits.append(c(f"信誉={v}", RED))
                    else:
                        bits.append(f"{key}={v}")
            for sub in ("package", "ioc", "ticket"):
                if isinstance(res.get(sub), dict):
                    for key in ("name", "version", "author", "reputation", "note", "window"):
                        if key in res[sub]:
                            v = res[sub][key]
                            bits.append(c(f"{key}={v}", RED) if key == "reputation" and v == "malicious"
                                        else f"{key}={v}")
        if bits:
            print("       " + c("结果：", DIM) + " | ".join(str(b) for b in bits))

    if "guardrail_ok" in st:
        ok = st["guardrail_ok"]
        reason = st.get("guardrail_reason", "")
        if ok:
            print("       " + c(f"护栏：放行（{reason}）", GREEN))
        else:
            print("       " + c(f"护栏：拒绝（{reason}）", RED))

    if pause:
        time.sleep(pause)


def replay_one(model: str, aid: str, pause: float) -> bool:
    path = trace_path(model, aid)
    if not path:
        print(c(f"未找到 trace：{aid}", RED))
        return False
    tr = load_json(path)

    print()
    print(hr("═"))
    print(c(f"告警 {aid}", BOLD), c(f"| 资产 {tr.get('asset','-')}", DIM))
    print(c(f"      模型 {tr.get('model')}  引擎 {tr.get('engine')}", DIM))
    print(hr())

    for st in tr.get("steps", []):
        render_step(st, pause)

    g = tr.get("guardrail") or {}
    verdict = tr.get("verdict") or g.get("verdict") or "-"
    print()
    print("  " + c("最终结论：", BOLD) + c(f"{verdict}", BOLD + ";" + GREEN)
          + c(f"（{VERDICT_ZH.get(verdict, '')}）  置信度 {g.get('confidence')}", DIM))
    if g.get("hypothesis"):
        print("  " + c("判定依据：", DIM) + g["hypothesis"])
    if g.get("actions"):
        print("  " + c("建议动作：", DIM) + "；".join(g["actions"]))
    inj = tr.get("injection_suspected") or []
    print("  " + c("提示词注入：", DIM)
          + (c(f"检出 {inj}", RED) if inj else c("未检出", GREEN)))
    steps_n = len(tr.get("steps", []))
    rej = len(g.get("rejected", []) or [])
    print("  " + c("过程统计：", DIM) + f"工具调用 {steps_n} 步，护栏拒绝 {rej} 次")

    # 真实验签：这一步不依赖模型，是当场在跑的真东西
    seal = resolve_seal(tr, model)
    if not seal:
        print("  " + c("验签：未找到 seal 文件", RED))
        return False

    print()
    print("  " + c("独立验签（现在真算，不经任何服务端）", BOLD))
    print("  " + c("文件：", DIM) + os.path.relpath(seal, ROOT))
    try:
        from swordholder import core

        res = core.verify(seal)
        v = res.get("verdict", "")
        payload = res.get("payload_sha256") or (tr.get("seal") or {}).get("payload_sha256", "")
        if v == "VALID":
            print("  " + c("结果：VALID", BOLD + ";" + GREEN)
                  + c("  签名完整、载荷未改、签发方在信任锚内", DIM))
            if payload:
                print("  " + c("载荷摘要：", DIM) + payload)
            return True
        print("  " + c(f"结果：{v}", BOLD + ";" + RED) + c(f"  {res.get('reason','')}", DIM))
        return False
    except Exception as e:  # noqa: BLE001
        print("  " + c(f"验签异常：{e}", RED))
        return False


def verify_all(model: str) -> int:
    print()
    print(c(f"批量验签：{model_label(model)}", BOLD))
    print(hr())
    ok_all = True
    for aid, tpath in trace_files(model):
        tr = load_json(tpath)
        seal = resolve_seal(tr, model)
        if not seal:
            print(f"  {aid:<24} {c('无 seal 文件', RED)}")
            ok_all = False
            continue
        try:
            from swordholder import core

            res = core.verify(seal)
            v = res.get("verdict", "")
        except Exception as e:  # noqa: BLE001
            v = f"异常:{e}"
        mark = c("VALID", GREEN) if v == "VALID" else c(v, RED)
        print(f"  {aid:<24} {mark}")
        ok_all = ok_all and v == "VALID"
    print()
    print(c("全部通过" if ok_all else "存在失败项，先修再上会", GREEN if ok_all else RED))
    return 0 if ok_all else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Pitch Day 离线演示回放（不需要模型）")
    ap.add_argument("--model", default=None,
                    help="存证布局名（runs/ 下的子目录名）；默认自动选择可回放的那一份")
    ap.add_argument("--case", default=None, help="只回放指定 alert_id")
    ap.add_argument("--list", action="store_true", help="列出可用模型与案卷")
    ap.add_argument("--fast", action="store_true", help="不逐步骤停顿")
    ap.add_argument("--verify-all", action="store_true", help="只批量验签")
    ap.add_argument("--pause", type=float, default=0.45, help="每步停顿秒数，默认 0.45")
    a = ap.parse_args()

    models = list_models()
    if a.list:
        print(c("可用模型与案卷：", BOLD))
        for m in models:
            aids = traces_of(m)
            print(f"  {model_label(m):<20} {len(aids)} 案")
            for aid in aids:
                print(f"      - {aid}")
        return 0

    if not models:
        print(c(f"未找到任何 trace：{RUNS}", RED))
        return 1
    if a.model is None:
        a.model = FLAT if FLAT in models else models[0]
    if a.model not in models:
        shown = ", ".join(model_label(m) for m in models)
        print(c(f"存证布局不存在：{a.model}；可用：{shown}", RED))
        return 1

    if a.verify_all:
        return verify_all(a.model)

    aids = [a.case] if a.case else traces_of(a.model)
    if not aids:
        print(c("没有可回放的案卷", RED))
        return 1

    print(c("SWORDHOLDER · 自主分诊回放（离线 · 不需模型 · 印章当场真验）", BOLD + ";" + CYAN))
    print(c(f"数据源 {model_label(a.model)}　"
            f"说明：模型推理部分是已落盘的真实记录，盖章与验签是当前机器实时计算", DIM))

    ok = True
    for aid in aids:
        ok = replay_one(a.model, aid, 0 if a.fast else a.pause) and ok

    print()
    print(hr("═"))
    if ok:
        print(c("全部 seal 验签通过：演示可上会。", BOLD + ";" + GREEN))
    else:
        print(c("存在未通过的 seal，先排查再上会。", BOLD + ";" + RED))
    print(c("现场加分动作：把任何一个 .seal.json 拷到评委自己的机器上，"
            "swordholder verify 一样出 VALID——不需要信任我们。", DIM))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
