# -*- coding: utf-8 -*-
"""S7: in-toto layout 级 verify 的离线探针（干净重跑，socket 全封）。

之前那版用 `in_toto_verify.main(sys.argv[1:])` 直接调 Python 函数，签名不匹配导致 TypeError，
虽然 net_hits=0 但 rc=1，结论不干净。此版改为：写一个 sitecustomize.py，把 socket.connect /
create_connection / getaddrinfo 全部拦下并记账，再通过 PYTHONPATH 注入，正常调用
in-toto-verify.exe 子进程 —— 于是「rc=0 且 net_hits=0」才是真结论。
"""
from __future__ import annotations

import json
import os
import shutil
import sys

TMP = os.environ["TEMP"]
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import s7_intoto_layout as L  # noqa: E402

GUARD_SRC = '''\
import os, socket
_log = os.environ.get("S7_NETLOG")

def _rec(kind, addr):
    if not _log:
        return
    try:
        with open(_log, "a", encoding="utf-8") as fh:
            fh.write("%s %r\\n" % (kind, addr))
    except Exception:
        pass

def _connect(self, address, *a, **k):
    _rec("connect", address)
    raise OSError("S7 offline probe: outbound network blocked")

def _create_connection(address, *a, **k):
    _rec("create_connection", address)
    raise OSError("S7 offline probe: outbound network blocked")

def _getaddrinfo(host, port, *a, **k):
    _rec("getaddrinfo", (host, port))
    raise socket.gaierror("S7 offline probe: DNS blocked")

socket.socket.connect = _connect
socket.create_connection = _create_connection
socket.getaddrinfo = _getaddrinfo
'''


def main() -> int:
    root = os.path.join(TMP, "s7_bench", "intoto", "offline3")
    guard = os.path.join(TMP, "s7_bench", "guard")
    os.makedirs(guard, exist_ok=True)
    with open(os.path.join(guard, "sitecustomize.py"), "w", encoding="utf-8") as fh:
        fh.write(GUARD_SRC)
    log = os.path.join(TMP, "s7_bench", "offline_netlog.txt")
    if os.path.exists(log):
        os.remove(log)

    # 重建干净的 3 步 layout 级流水线（in-toto-run 真实执行 + owner 签 layout + verify rc=0）
    base = L.run_pipeline(root, 3, verify_reps=1)
    base_ok = base.get("verify_rc") == 0 and base.get("step_rc_all_zero") is not False
    base_ok = base.get("verify_rc") == 0 and all(s["rc"] == 0 for s in base["step_runs"])

    env = dict(os.environ)
    env["PYTHONPATH"] = guard + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["S7_NETLOG"] = log
    v = L.sh([L.VERIFY_EXE, "--layout", "root.layout",
              "--verification-keys", os.path.join(L.KEYS, "owner.pub"),
              "--link-dir", "links"], cwd=root, env=env)

    hits = []
    if os.path.exists(log):
        hits = [ln.strip() for ln in open(log, encoding="utf-8") if ln.strip()]
    rep = {
        "baseline_pipeline": {
            "steps": 3, "verify_rc": base.get("verify_rc"),
            "step_rcs": [s["rc"] for s in base.get("step_runs", [])],
            "baseline_ok": base_ok,
            "link_count": base.get("link_count"),
            "signed_metadata_bytes": base.get("signed_metadata_bytes")},
        "offline_verify": {
            "rc": v["rc"], "ms": v["ms"], "cmd": v["cmd"],
            "net_hits": len(hits), "net_events": hits[:20],
            "ok": v["rc"] == 0 and len(hits) == 0,
            "out_tail": v["out"][-300:], "err_tail": v["err"][-400:]},
        "guard": {"sitecustomize": os.path.join(guard, "sitecustomize.py"),
                  "blocks": ["socket.socket.connect", "socket.create_connection",
                             "socket.getaddrinfo"]},
    }
    out = os.path.join(HERE, "s7_intoto_offline.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
