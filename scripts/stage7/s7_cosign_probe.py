# -*- coding: utf-8 -*-
"""probe: cosign verify-blob 的 TUF 行为 —— 为什么 warm 缓存下仍耗时 2s / 死代理下必失败。"""
import json
import os
import shutil
import statistics
import subprocess
import time

COSIGN = os.path.join(os.environ["TEMP"], "s7_cosign", "cosign-windows-amd64.exe")
WD = os.path.join(os.environ["TEMP"], "s7_bench", "cosign")
PAYLOAD = os.path.join(os.environ["TEMP"], "s7_bench", "ours_c", "payloads", "trace_1.json")
HOME = os.path.join(os.path.expanduser("~"), ".sigstore")
DEAD = {"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
        "https_proxy": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
        "NO_PROXY": "", "no_proxy": ""}


def go(extra_env=None, reps=4, blank_tuf=False):
    if blank_tuf and os.path.isdir(HOME):
        shutil.move(HOME, HOME + ".probe_bak")
    env = dict(os.environ)
    env["COSIGN_PASSWORD"] = "s7-bench-pass"
    if extra_env:
        env.update(extra_env)
    out = []
    for _ in range(reps):
        t0 = time.perf_counter()
        p = subprocess.run([COSIGN, "verify-blob", "--key", "cosign.pub", "--signature", "t1.sig",
                            "--insecure-ignore-tlog=true", PAYLOAD],
                           cwd=WD, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env, timeout=300)
        out.append({"rc": p.returncode, "ms": round((time.perf_counter() - t0) * 1000.0, 1),
                    "err": (p.stderr or "")[-160:].replace("\n", " ")})
    return out


print("== A. 正常环境，TUF 缓存已在 ==")
a = go()
print(json.dumps(a, ensure_ascii=False, indent=1))
print("median_ms=", statistics.median([x["ms"] for x in a]))

print("== B. 正常环境，TUF 缓存删除（冷启动）==")
b = go(blank_tuf=True)
print(json.dumps(b, ensure_ascii=False, indent=1))

print("== C. 正常环境，再跑一次（缓存已由 B 重建）==")
c = go(reps=2)
print(json.dumps(c, ensure_ascii=False, indent=1))

print("== D. 死代理 + 缓存已在 ==")
d = go(extra_env=DEAD, reps=2)
print(json.dumps(d, ensure_ascii=False, indent=1))

print("== E. 死代理 + 缓存删除 ==")
e = go(extra_env=DEAD, reps=1, blank_tuf=True)
print(json.dumps(e, ensure_ascii=False, indent=1))
print("cache_exists_after=", os.path.isdir(HOME))
