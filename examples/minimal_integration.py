"""最小接入示例：把一条分诊结论封成可离线独立验签的凭证，并逐条验收。

用途
----
1. 给第一次接入的人一条能直接跑通的最短路径（只用公开 API：``swordholder.core`` /
   ``swordholder.trust``），不依赖仓库内的脚本、样例或私有模块。
2. 给评审方一个**可复算**的验收清单：脚本输出机器可读 JSON，外部人员在自己的机器上
   重跑，逐项比对 ``checks[].passed`` 即可，不需要相信本项目的任何文字描述。

运行
----
    pip install dist/swordholder-0.7.1-py3-none-any.whl
    python examples/minimal_integration.py --out minimal_check.json

退出码：全部通过 0；任一项失败 1；环境问题 2。

注意
----
本示例刻意只演示"存证层"能力（签发 / 独立验签 / 篡改检出 / 会话绑定 / 确定性）。
分诊结论本身是否正确不在本示例的验证范围内——仓库里 stage2 的负结果已说明规则
分诊层在公开遥测上真阳性率为 0，接入方不应把本示例当作分诊质量的背书。
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
from typing import Any, Callable

# ---- 只允许从「公开 API」取用，不 import 仓库脚本或 mcp_server 内部实现细节 ----
try:
    import swordholder
    from swordholder import core, trust
except Exception as exc:  # pragma: no cover - 环境缺失时给出可读结论
    print(json.dumps({"ok": False, "stage": "import",
                      "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
    raise SystemExit(2)


ISSUER = "soc-triage@example.internal"
RECORD: dict[str, Any] = {
    "alert_id": "ALRT-DEMO-0001",
    "asset": "build-runner-07",
    "verdict": "true_positive",
    "severity": "high",
    "confidence": 0.91,
    "hypothesis": "构建机向未登记 ASN 建立长连接，疑似凭证外泄后的中继通道",
    "engine": "rules-v1",
}


class Checker:
    """收集验收项，单项失败不中断后续项。"""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def run(self, cid: str, name: str, expect: str, fn: Callable[[], str]) -> None:
        started = time.perf_counter()
        error = None
        try:
            actual = fn()
        except Exception as exc:  # noqa: BLE001 - 示例要如实汇报异常而非崩溃
            actual, error = f"EXC:{type(exc).__name__}", str(exc)[:400]
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        self.items.append({
            "id": cid,
            "name": name,
            "expect": expect,
            "actual": actual,
            "passed": actual == expect,
            "elapsed_ms": elapsed,
            **({"error": error} if error else {}),
        })

    @property
    def ok(self) -> bool:
        return all(i["passed"] for i in self.items)


def _write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="swordholder 最小接入示例（存证层验收）")
    ap.add_argument("--workdir", default=None, help="工作目录，默认创建临时目录并在结束时保留路径")
    ap.add_argument("--out", default=None, help="把验收结果写入该 JSON 路径；默认只打印")
    ap.add_argument("--bench-iterations", type=int, default=30, help="性能复算的迭代次数")
    args = ap.parse_args(argv)

    workdir = args.workdir or tempfile.mkdtemp(prefix="swordholder-minimal-")
    if os.path.isdir(workdir) and os.listdir(workdir):
        # 复用非空目录会让"生成密钥""登记信任锚"这类一次性步骤因文件已存在而失败。
        # 这里不删除任何东西，只在下面开一个带时间戳的子run目录。
        workdir = os.path.join(workdir, time.strftime("run_%Y%m%d_%H%M%S"))
    os.makedirs(workdir, exist_ok=True)
    keys_dir = os.path.join(workdir, "keys")
    trust_path = os.path.join(workdir, "trusted_keys.json")
    seal_path = os.path.join(workdir, "demo.seal.json")
    challenge = "session-7f3c2a91"

    ck = Checker()
    state: dict[str, Any] = {}

    def step_keygen() -> str:
        res = core.keygen(keys_dir)
        state["key"] = res
        state["pub_hex"] = res["public_key_hex"]
        return "KEYPAIR_CREATED"

    def step_seal() -> str:
        res = core.seal(RECORD, state["key"]["private_key_path"], ISSUER,
                        out_path=seal_path, challenge=challenge)
        state["seal"] = res
        return "SEALED" if os.path.exists(res["seal_path"]) else "MISSING"

    def step_anchor() -> str:
        trust.add_key(trust_path, state["pub_hex"], key_id="demo-key")
        return "ANCHOR_ADDED" if os.path.exists(trust_path) else "MISSING"

    def step_verify_trusted() -> str:
        res = core.verify(seal_path, trust_path, expected_challenge=challenge)
        state["verify_trusted"] = res
        return res.get("verdict", "NO_VERDICT")

    def step_verify_untrusted() -> str:
        res = core.verify(seal_path, None)
        return res.get("verdict", "NO_VERDICT")

    def step_tamper_payload() -> str:
        seal = json.load(open(seal_path, encoding="utf-8"))
        seal["payload"]["verdict"] = "false_positive"
        tampered = os.path.join(workdir, "tampered_payload.seal.json")
        _write_json(tampered, seal)
        return core.verify(tampered, trust_path).get("verdict", "NO_VERDICT")

    def step_tamper_signature() -> str:
        seal = json.load(open(seal_path, encoding="utf-8"))
        sig = seal["signature"]["value"]
        seal["signature"]["value"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        tampered = os.path.join(workdir, "tampered_sig.seal.json")
        _write_json(tampered, seal)
        return core.verify(tampered, trust_path).get("verdict", "NO_VERDICT")

    def step_type_confusion() -> str:
        # 把签名块换成非字符串（整数）：若实现里直接 .get 后 base64 解码，会抛
        # AttributeError/TypeError —— 崩溃不算"检出"。期望得到结构化拒绝码。
        seal = json.load(open(seal_path, encoding="utf-8"))
        seal["signature"]["value"] = 123
        bad = os.path.join(workdir, "typed_wrong.seal.json")
        _write_json(bad, seal)
        res = core.verify(bad, trust_path)
        return res.get("reason", "NO_REASON") if res.get("verdict") == "INVALID" else res.get("verdict", "?")

    def step_bad_base64() -> str:
        seal = json.load(open(seal_path, encoding="utf-8"))
        seal["signature"]["value"] = "not base64!!"
        bad = os.path.join(workdir, "bad_b64.seal.json")
        _write_json(bad, seal)
        res = core.verify(bad, trust_path)
        return res.get("reason", "NO_REASON") if res.get("verdict") == "INVALID" else res.get("verdict", "?")

    def step_replay_other_session() -> str:
        res = core.verify(seal_path, trust_path, expected_challenge="session-other")
        return res.get("reason", "NO_REASON")

    def step_replay_without_challenge() -> str:
        res = core.verify(seal_path, trust_path)
        return res.get("reason", "NO_REASON")

    def step_determinism() -> str:
        again = core.seal(RECORD, state["key"]["private_key_path"], ISSUER,
                          out_path=os.path.join(workdir, "demo2.seal.json"), challenge=challenge)
        same_payload = again["payload_sha256"] == state["seal"]["payload_sha256"]
        same_local = core.payload_sha256(RECORD) == state["seal"]["payload_sha256"]
        return "SAME" if (same_payload and same_local) else "DIFF"

    def step_bench() -> str:
        n = max(1, args.bench_iterations)
        seal_ms: list[float] = []
        verify_ms: list[float] = []
        for i in range(n):
            p = os.path.join(workdir, f"bench_{i}.seal.json")
            t0 = time.perf_counter()
            core.seal(RECORD, state["key"]["private_key_path"], ISSUER, out_path=p, challenge=challenge)
            t1 = time.perf_counter()
            core.verify(p, trust_path, expected_challenge=challenge)
            t2 = time.perf_counter()
            seal_ms.append((t1 - t0) * 1000)
            verify_ms.append((t2 - t1) * 1000)
        state["bench"] = {
            "iterations": n,
            "seal_ms_median": round(statistics.median(seal_ms), 3),
            "seal_ms_p95": round(sorted(seal_ms)[max(0, int(0.95 * n) - 1)], 3),
            "verify_ms_median": round(statistics.median(verify_ms), 3),
            "verify_ms_p95": round(sorted(verify_ms)[max(0, int(0.95 * n) - 1)], 3),
        }
        return "BENCHED"

    ck.run("A1", "生成 ed25519 密钥对", "KEYPAIR_CREATED", step_keygen)
    ck.run("A2", "对分诊结论盖章并落盘", "SEALED", step_seal)
    ck.run("A3", "把公钥登记为信任锚", "ANCHOR_ADDED", step_anchor)
    ck.run("A4", "带信任锚验签 -> VALID", "VALID", step_verify_trusted)
    ck.run("A5", "无信任锚验签 -> 不得返回 VALID", "VALID_UNTRUSTED_KEY", step_verify_untrusted)
    ck.run("A6", "改 payload 字段 -> 拒绝", "INVALID", step_tamper_payload)
    ck.run("A7", "改 signature 字节 -> 拒绝", "INVALID", step_tamper_signature)
    ck.run("A8", "signature 类型混淆 -> E_MALFORMED_SEAL", "E_MALFORMED_SEAL", step_type_confusion)
    ck.run("A8b", "signature 非 base64 字符串 -> E_SCHEMA_INVALID", "E_SCHEMA_INVALID", step_bad_base64)
    ck.run("A9", "跨会话重放 -> E_CHALLENGE_MISMATCH", "E_CHALLENGE_MISMATCH", step_replay_other_session)
    ck.run("A10", "不比对挑战值时可验但无重放防护", "OK", step_replay_without_challenge)
    ck.run("A11", "同一 payload 两次盖章摘要一致", "SAME", step_determinism)
    ck.run("A12", "签发/验签耗时复算", "BENCHED", step_bench)

    report = {
        "ok": ck.ok,
        "tool": "swordholder.minimal_integration",
        "package_version": getattr(swordholder, "__version__", "unknown"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "workdir": workdir,
        "issuer": ISSUER,
        "issue_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload_sha256": state.get("seal", {}).get("payload_sha256"),
        "timing": state.get("bench", {}),
        "checks": ck.items,
        "summary": {
            "total": len(ck.items),
            "passed": sum(1 for i in ck.items if i["passed"]),
            "failed": [i["id"] for i in ck.items if not i["passed"]],
        },
    }

    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"[minimal_integration] {report['summary']['passed']}/{report['summary']['total']} "
              f"checks passed -> {args.out}")
        if not ck.ok:
            print(f"[minimal_integration] FAILED: {report['summary']['failed']}", file=sys.stderr)
    else:
        print(text)

    if not args.workdir:
        # 临时目录保留，便于人工复核产物；路径已写入报告 workdir 字段
        pass
    return 0 if ck.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
