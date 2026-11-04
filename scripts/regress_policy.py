#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""策略变更门禁（M0 第三步）。

用途：判定规则已经从代码挪进了 YAML，改 YAML 就等于改系统行为。所以任何策略改动
都必须先过这里——用一批人工确认过的案例，把"该放行的放行、该拒收的拒收"钉死。

三件事：
1. 完整性：cases/ 下每个案例的 sha256 与 cases/manifest.json 对不上，直接红灯；
2. 行为：拿当前生效策略（或 --policy 指定的）跑一遍所有案例，逐条比对期望；
3. 可追：输出每条案例实际命中的拒收理由，方便回看策略改动的实际影响。

退出码：0 全部通过；1 有案例不符合期望；2 案例库被改动或用法错误。
用法：
    python scripts/regress_policy.py
    python scripts/regress_policy.py --policy swordholder/policy/email-outbound-approval.yaml
    python scripts/regress_policy.py --update-manifest   # 人工复核后再执行
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from swordholder import agent_loop as al  # noqa: E402
from swordholder import policy_loader  # noqa: E402

CASES_DIR = os.path.join(ROOT, "cases")
MANIFEST = os.path.join(CASES_DIR, "manifest.json")


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cases() -> list[dict]:
    if not os.path.isdir(CASES_DIR):
        raise SystemExit(f"案例目录不存在：{CASES_DIR}")
    out = []
    for name in sorted(os.listdir(CASES_DIR)):
        if not name.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(CASES_DIR, name)
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        doc["_file"] = name
        doc["_sha256"] = sha256_of(path)
        out.append(doc)
    return out


def check_integrity(cases: list[dict]) -> list[str]:
    problems = []
    if not os.path.exists(MANIFEST):
        return ["缺少 cases/manifest.json，案例库未冻结（先人工复核再 --update-manifest）"]
    with open(MANIFEST, encoding="utf-8") as f:
        man = json.load(f)
    known = man.get("cases", {})
    for c in cases:
        want = known.get(c["_file"])
        if want is None:
            problems.append(f"{c['_file']}：未登记进 manifest")
        elif want != c["_sha256"]:
            problems.append(f"{c['_file']}：内容被改动（期望 {want[:12]}… 实际 {c['_sha256'][:12]}…）")
    for name in known:
        if not os.path.exists(os.path.join(CASES_DIR, name)):
            problems.append(f"{name}：manifest 里有，磁盘上没有了")
    return problems


def update_manifest(cases: list[dict]) -> None:
    man = {
        "note": "案例库是策略变更的判据基线。任何 digest 变化都必须人工复核后再提交。",
        "cases": {c["_file"]: c["_sha256"] for c in cases},
    }
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as f:
        json.dump(man, f, ensure_ascii=False, indent=2)
    print(f"已更新 {os.path.relpath(MANIFEST, ROOT)}（{len(cases)} 条）")


def _executed(n: int) -> dict:
    return {i: {"step": i, "action": "get_asset_profile", "args": {},
                "ok": True, "result": {"tool": "get_asset_profile", "ok": True}}
            for i in range(1, n + 1)}


def run_case(case: dict, policy: dict | None) -> tuple[bool, str]:
    """返回 (是否符合期望, 说明)。"""
    inp = case.get("input") or {}
    decision = inp.get("decision") or {}
    executed = _executed(int(inp.get("executed_steps") or 0))
    facts = inp.get("facts") or {}
    alert_ts = inp.get("alert_ts")
    ok, reason, _ = al.guardrail(dict(decision), executed, facts=facts,
                                 alert_ts=alert_ts, injection_detected=False, policy=policy)
    exp = case.get("expect") or {}
    want_ok = bool(exp.get("ok"))
    needle = exp.get("reason_contains")

    if ok != want_ok:
        return False, f"期望 {'放行' if want_ok else '拒收'}，实际 {'放行' if ok else '拒收'}（{reason}）"
    if needle and needle not in (reason or ""):
        return False, f"拒收理由里应含「{needle}」，实际是「{reason}」"
    return True, ("放行" if ok else f"拒收：{reason}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="regress_policy", description="策略变更门禁：案例库回归")
    ap.add_argument("--policy", default=None,
                    help="待测策略 YAML；默认用当前生效策略（$SWORDHOLDER_POLICY 或内置默认）")
    ap.add_argument("--update-manifest", action="store_true", help="重新固化案例 digest（需人工复核）")
    ap.add_argument("--skip-integrity", action="store_true", help="跳过案例库完整性校验（不建议）")
    a = ap.parse_args(argv)

    cases = load_cases()
    if not cases:
        print("案例目录为空，没有任何基线，拒绝通过。")
        return 2

    if a.update_manifest:
        update_manifest(cases)
        return 0

    if not a.skip_integrity:
        problems = check_integrity(cases)
        if problems:
            print("案例库完整性校验未通过——基线被动过，先确认是不是有意为之：")
            for p in problems:
                print(f"  - {p}")
            return 2

    try:
        pol = policy_loader.load(a.policy)
    except policy_loader.PolicyError as e:
        print(f"策略不可用，视为门禁不通过：{e}")
        return 1

    used = os.path.relpath(policy_loader.resolve_path(a.policy), ROOT)
    print(f"待测策略：{pol['id']} v{pol.get('version')}  ({used})")
    print(f"案例数：{len(cases)}\n")
    print(f"{'case':<8}{'结果':<8}{'说明':<64}标题")
    print("-" * 118)

    failed = 0
    for c in cases:
        good, note = run_case(c, pol)
        if not good:
            failed += 1
        print(f"{c.get('id','?'):<8}{'PASS' if good else 'FAIL':<8}{note[:62]:<64}{c.get('title','')}")

    print("-" * 118)
    if failed:
        print(f"未通过：{failed}/{len(cases)}。这份策略不能合入。")
        return 1
    print(f"全部通过（{len(cases)}/{len(cases)}）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
