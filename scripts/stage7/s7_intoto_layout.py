# -*- coding: utf-8 -*-
"""S7: in-toto 3.1.0 layout 级全流程实测（CLI：in-toto-run / in-toto-sign / in-toto-verify）。

测什么
------
1. 真实 N 步供应链（N=1/5/20/50）：每步一个 link（in-toto-run 实际执行命令并签名），
   再由 owner 密钥签 layout，最后跑 in-toto-verify 做 layout 级全流程验证。
2. 体积：layout + N 个 link + 公钥 的总字节。
3. 耗时：逐步 in-toto-run 墙钟、layout 签名耗时、layout 级 verify 耗时（多次取中位数）。
4. 篡改定位：对 N=3 的成品做 7 类篡改，看 verify 是否失败、错误信息是否点名具体步骤。
5. 离线：审计钩子封死 socket 后跑 layout 级 verify，统计网络调用次数。
6. 外部依赖：全程是否需要 Rekor / Fulcio / TSA / OIDC。

用法： python s7_intoto_layout.py <workdir> <out.json>
"""
from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import time

VENV_SCRIPTS = os.path.join(os.environ["TEMP"], "s7_intoto_venv", "Scripts")
RUN_EXE = os.path.join(VENV_SCRIPTS, "in-toto-run.exe")
SIGN_EXE = os.path.join(VENV_SCRIPTS, "in-toto-sign.exe")
VERIFY_EXE = os.path.join(VENV_SCRIPTS, "in-toto-verify.exe")
PY = os.path.join(VENV_SCRIPTS, "python.exe")

KEYS = os.path.join(os.environ["TEMP"], "s7_bench", "keys")

STEP_SCRIPT = """\
import sys
src, dst = sys.argv[1], sys.argv[2]
open(dst, 'w', encoding='utf-8').write(open(src, encoding='utf-8').read() + '|processed')
"""

INSPECT_SCRIPT = """\
import glob, sys
bad = []
for p in glob.glob('artifacts/*.txt'):
    if not open(p, encoding='utf-8').read().endswith('|processed'):
        bad.append(p)
sys.exit(1 if bad else 0)
"""


def sh(args, cwd, timeout=180, env=None):
    t0 = time.perf_counter()
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout, env=env)
    dt = (time.perf_counter() - t0) * 1000.0
    return {"rc": p.returncode, "out": (p.stdout or "").strip(), "err": (p.stderr or "").strip(),
            "ms": round(dt, 2), "cmd": " ".join(args)}


def startup_ms(exe: str, reps: int = 5) -> float:
    """CLI 空载启动基线：`<exe> --version` 的墙钟中位数（毫秒）。

    in-toto 的 CLI 是独立进程，每次调用都要付出 Python 解释器启动 + 依赖导入的固定开销
    （实测 ~150-250ms）。我方数字是**进程内纯函数耗时**，若直接拿 CLI 墙钟与之相比，
    差异会被启动开销完全主导。故所有 CLI 耗时同时给出「净耗时 = 墙钟 - 启动基线」。
    """
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        subprocess.run([exe, "--version"], capture_output=True, timeout=120)
        xs.append((time.perf_counter() - t0) * 1000.0)
    return round(statistics.median(xs), 2)


def keyid_of(priv_path: str) -> tuple[str, dict]:
    """用 securesystemslib 载入私钥，返回 keyid 与公钥字典（布局里要用）。"""
    code = (
        "import json,sys\n"
        "from cryptography.hazmat.primitives import serialization\n"
        "from securesystemslib.signer import CryptoSigner\n"
        "priv=serialization.load_pem_private_key(open(sys.argv[1],'rb').read(), password=None)\n"
        "s=CryptoSigner(priv)\n"
        "pk=s.public_key\n"
        "d=pk.to_dict(); d['keyid']=pk.keyid\n"
        "print(json.dumps(d))\n"
    )
    p = subprocess.run([PY, "-c", code, priv_path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError("key load failed: " + (p.stderr or "")[-600:])
    d = json.loads(p.stdout.strip().splitlines()[-1])
    return d["keyid"], d


def init_workspace(root: str, n: int) -> None:
    if os.path.isdir(root):
        shutil.rmtree(root)
    for sub in ("artifacts", "links", "scripts"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    with open(os.path.join(root, "scripts", "step.py"), "w", encoding="utf-8") as fh:
        fh.write(STEP_SCRIPT)
    with open(os.path.join(root, "scripts", "inspect.py"), "w", encoding="utf-8") as fh:
        fh.write(INSPECT_SCRIPT)
    with open(os.path.join(root, "seed0.txt"), "w", encoding="utf-8") as fh:
        fh.write("S7 seed payload")


def build_layout(n: int, alice_keyid: str, alice_pub: dict) -> dict:
    steps = []
    for i in range(n):
        name = "step%02d" % i
        src = "seed0.txt" if i == 0 else "artifacts/s%02d.txt" % (i - 1)
        dst = "artifacts/s%02d.txt" % i
        # 两条规则写法上的坑（都是 H1/H2 案例反证出来的，已修正）：
        # 1) 链式归属必须写在 expected_materials 上：step_i 收到的 s(i-1).txt 要和
        #    step(i-1) 登记为该产物的哈希一致；写在 expected_products 里规则空转。
        # 2) in-toto 的 MATCH 是"消费式"规则：哈希对不上时它只是**不消费**，并不抛错，
        #    必须再跟一条 DISALLOW * 才能把"没匹配上"变成验证失败。
        if i == 0:
            mat_rules = [["ALLOW", "seed0.txt"], ["DISALLOW", "*"]]
        else:
            mat_rules = [["MATCH", "artifacts/s%02d.txt" % (i - 1),
                          "WITH", "PRODUCTS",
                          "FROM", "step%02d" % (i - 1)],
                         ["DISALLOW", "*"]]
        steps.append({
            "_type": "step",
            "name": name,
            "expected_materials": mat_rules,
            "expected_products": [["CREATE", dst], ["DISALLOW", "*"]],
            "pubkeys": [alice_keyid],
            "expected_command": ["python", "scripts/step.py", src, dst],
            "threshold": 1,
        })
    last = "artifacts/s%02d.txt" % (n - 1)
    return {
        "_type": "layout",
        "expires": "2030-12-31T00:00:00Z",
        "readme": "S7 in-toto layout-level benchmark (single functionary, %d steps)" % n,
        "keys": {alice_keyid: alice_pub},
        "steps": steps,
        "inspect": [{
            "_type": "inspection",
            "name": "check_artifacts",
            "expected_materials": [["MATCH", last, "WITH", "PRODUCTS",
                                    "FROM", "step%02d" % (n - 1)]],
            "expected_products": [],
            "run": ["python", "scripts/inspect.py"],
        }],
    }


def run_pipeline(root: str, n: int, verify_reps: int = 5) -> dict:
    init_workspace(root, n)
    alice_keyid, alice_pub = keyid_of(os.path.join(KEYS, "alice.key"))
    layout_path = os.path.join(root, "layout.json")
    # in-toto 的 layout 文件是 Metablock 结构：{"signed": {...layout...}, "signatures": []}
    meta = {"signatures": [], "signed": build_layout(n, alice_keyid, alice_pub)}
    with open(layout_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=1)

    step_runs = []
    total_step_ms = 0.0
    for i in range(n):
        src = "seed0.txt" if i == 0 else "artifacts/s%02d.txt" % (i - 1)
        dst = "artifacts/s%02d.txt" % i
        r = sh([RUN_EXE, "-n", "step%02d" % i, "-m", src, "-p", dst,
                "--signing-key", os.path.join(KEYS, "alice.key"),
                "-d", "links", "--", "python", "scripts/step.py", src, dst], cwd=root)
        total_step_ms += r["ms"]
        step_runs.append({"step": "step%02d" % i, "rc": r["rc"], "ms": r["ms"],
                          "err_tail": r["err"][-300:] if r["rc"] != 0 else ""})

    sign = sh([SIGN_EXE, "-f", "layout.json", "-k", os.path.join(KEYS, "owner.key"),
               "-o", "root.layout"], cwd=root)
    if sign["rc"] != 0 or not os.path.exists(os.path.join(root, "root.layout")):
        return {"steps": n, "error": "in-toto-sign failed", "sign_layout_rc": sign["rc"],
                "sign_layout_err": sign["err"][-800:], "sign_layout_out": sign["out"][-400:],
                "step_runs": step_runs}

    verify_times = []
    first_verify = None
    for k in range(verify_reps):
        v = sh([VERIFY_EXE, "--layout", "root.layout",
                "--verification-keys", os.path.join(KEYS, "owner.pub"),
                "--link-dir", "links"], cwd=root)
        verify_times.append(v["ms"])
        if k == 0:
            first_verify = v
    verify_times_sorted = sorted(verify_times)

    links = {}
    ldir = os.path.join(root, "links")
    for fn in sorted(os.listdir(ldir)):
        links[fn] = os.path.getsize(os.path.join(ldir, fn))
    layout_bytes = os.path.getsize(os.path.join(root, "root.layout"))
    pub_bytes = os.path.getsize(os.path.join(KEYS, "alice.pub")) + \
        os.path.getsize(os.path.join(KEYS, "owner.pub"))
    artifacts_bytes = sum(os.path.getsize(os.path.join(root, "artifacts", f))
                          for f in os.listdir(os.path.join(root, "artifacts")))
    return {
        "steps": n,
        "step_runs": step_runs,
        "step_ms_total": round(total_step_ms, 2),
        "step_ms_median": round(statistics.median([s["ms"] for s in step_runs]), 2) if n else 0,
        "sign_layout_ms": sign["ms"],
        "sign_layout_rc": sign["rc"],
        "sign_layout_err": sign["err"][-300:],
        "verify_rc": first_verify["rc"],
        "verify_out_tail": first_verify["out"][-600:],
        "verify_err_tail": first_verify["err"][-600:],
        "verify_ms_median": round(statistics.median(verify_times), 2),
        "verify_ms_min": round(verify_times_sorted[0], 2),
        "verify_ms_samples": verify_times,
        "link_count": len(links),
        "link_bytes_total": sum(links.values()),
        "link_bytes_each": links,
        "link_bytes_per_step": round(sum(links.values()) / n, 2) if n else 0,
        "layout_bytes": layout_bytes,
        "pubkey_bytes": pub_bytes,
        "artifacts_bytes": artifacts_bytes,
        "signed_metadata_bytes": layout_bytes + sum(links.values()) + pub_bytes,
        "signature_count": n + 1,
    }


# ------------------------------------------------------------ 篡改定位
def _mutate(root_src: str, root_dst: str, kind: str) -> str:
    """把基准工作目录复制一份，按 kind 篡改，返回被篡改对象的说明。"""
    if os.path.isdir(root_dst):
        shutil.rmtree(root_dst)
    shutil.copytree(root_src, root_dst)  # 注意：基准目录是 verification=OK 的成品
    links_dir = os.path.join(root_dst, "links")
    link_files = sorted(os.listdir(links_dir))

    def _load(p):
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)

    def _dump(p, d):
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(d, fh, ensure_ascii=False)

    if kind == "product_file_modified":          # 记录后改了磁盘上的成品
        p = os.path.join(root_dst, "artifacts", "s01.txt")
        with open(p, "a", encoding="utf-8") as fh:
            fh.write("|EVIL")
        return "artifacts/s01.txt 内容被改（link 未动）"

    if kind == "link_product_hash_modified":     # 改 link 内登记的哈希，签名不动
        p = os.path.join(links_dir, link_files[1])
        d = _load(p)
        key = list(d["signed"]["products"].keys())[0]
        d["signed"]["products"][key]["sha256"] = "0" * 64
        _dump(p, d)
        return "%s 内 products 哈希改为 64 个 0（签名未重算）" % link_files[1]

    if kind == "link_signature_corrupted":       # 破坏签名值
        p = os.path.join(links_dir, link_files[1])
        d = _load(p)
        d["signatures"][0]["sig"] = "0" * len(d["signatures"][0]["sig"])
        _dump(p, d)
        return "%s 的签名值置零（载荷未动）" % link_files[1]

    if kind == "link_deleted":                   # 删掉中间步骤的 link
        os.remove(os.path.join(links_dir, link_files[1]))
        return "删除 %s" % link_files[1]

    if kind == "link_command_changed":           # 改记录的 command（签名失效）
        p = os.path.join(links_dir, link_files[2])
        d = _load(p)
        d["signed"]["command"] = ["python", "evil.py"]
        _dump(p, d)
        return "%s 的 command 改为 evil.py" % link_files[2]

    if kind == "link_renamed_keyid":             # 换成别的 keyid 前缀（冒充他人）
        p = os.path.join(links_dir, link_files[0])
        new = os.path.join(links_dir, "step00.deadbeef.link")
        shutil.move(p, new)
        return "step00 的 link 改名为 step00.deadbeef.link"

    if kind == "layout_unsigned":                # 去掉 layout 的签名
        p = os.path.join(root_dst, "root.layout")
        d = _load(p)
        d["signatures"] = []
        _dump(p, d)
        return "root.layout 的签名列表清空"

    raise ValueError(kind)


def tamper_suite(base_root: str, work_parent: str) -> dict:
    kinds = ["product_file_modified", "link_product_hash_modified", "link_signature_corrupted",
             "link_deleted", "link_command_changed", "link_renamed_keyid", "layout_unsigned"]
    rows = []
    for kind in kinds:
        dst = os.path.join(work_parent, "tamper_" + kind)
        note = _mutate(base_root, dst, kind)
        v = sh([VERIFY_EXE, "--layout", "root.layout",
                "--verification-keys", os.path.join(KEYS, "owner.pub"),
                "--link-dir", "links"], cwd=dst)
        text = (v["err"] + " " + v["out"])
        named = [s for s in ("step00", "step01", "step02", "check_artifacts") if s in text]
        rows.append({
            "case": kind,
            "mutation": note,
            "rc": v["rc"],
            "detected": v["rc"] != 0,
            "named_steps_in_error": named,
            "error_excerpt": (v["err"] or v["out"])[-500:],
        })
    return {
        "cases": rows,
        "cases_total": len(rows),
        "detected": sum(1 for r in rows if r["detected"]),
        "detected_rate": round(sum(1 for r in rows if r["detected"]) / len(rows), 4),
        "localized_to_step": sum(1 for r in rows if r["detected"] and r["named_steps_in_error"]),
    }


# ------------------------------------------------------------------ 离线
OFFLINE_WRAPPER = r'''
import json, sys
NET = ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.bind",
       "socket.sendto", "urllib.Request")
hits = {"n": 0, "events": []}
def hook(event, args):
    if event in NET:
        hits["n"] += 1
        hits["events"].append(event)
        raise RuntimeError("network blocked by probe: " + event)
sys.addaudithook(hook)
from in_toto import in_toto_verify
rc = 0
try:
    rc = in_toto_verify.main(sys.argv[1:]) or 0
except SystemExit as e:
    rc = e.code or 0
finally:
    print("__PROBE__" + json.dumps({"net_hits": hits["n"], "events": hits["events"][:10], "rc": rc}))
'''


def offline_verify(root: str) -> dict:
    wrapper = os.path.join(root, "_offline_wrapper.py")
    with open(wrapper, "w", encoding="utf-8") as fh:
        fh.write(OFFLINE_WRAPPER)
    p = subprocess.run([PY, wrapper, "--layout", "root.layout",
                        "--verification-keys", os.path.join(KEYS, "owner.pub"),
                        "--link-dir", "links"], cwd=root, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=180)
    probe = None
    for line in (p.stdout or "").splitlines():
        if line.startswith("__PROBE__"):
            probe = json.loads(line[len("__PROBE__"):])
    return {
        "rc": p.returncode,
        "probe": probe,
        "stdout_tail": (p.stdout or "")[-400:],
        "stderr_tail": (p.stderr or "")[-400:],
        "ok": bool(probe and probe.get("rc") == 0 and probe.get("net_hits") == 0),
    }


INPROC_COST = r'''
import json, statistics, sys, time
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from securesystemslib.signer import CryptoSigner

signer = CryptoSigner.generate_ed25519()
pk = signer.public_key
pub = dict(pk.to_dict()); pub["keyid"] = pk.keyid

def sign_all(n):
    out = []
    for i in range(n):
        link = Link(name="step%02d" % i, materials={},
                    products={"artifacts/s%02d.txt" % i: {"sha256": "a" * 64}},
                    byproducts={"return-value": 0},
                    command=["python", "scripts/step.py"])
        mb = Metablock(signed=link, signatures=[])
        mb.create_signature(signer)
        out.append(mb)
    return out

def timed(fn, reps, warmup=3):
    for _ in range(warmup): fn()
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter(); fn(); xs.append((time.perf_counter() - t0) * 1000.0)
    xs.sort()
    return round(statistics.median(xs), 4), round(xs[0], 4)

rows = []
for n in (1, 5, 20, 50):
    mbs = sign_all(n)
    raw = [json.dumps(mb.to_dict(), sort_keys=True) for mb in mbs]
    b = sum(len(x.encode("utf-8")) for x in raw)
    s_med, s_min = timed(lambda n=n: sign_all(n), 9)
    def ver(mbs=[Metablock.from_dict(json.loads(raw[i])) for i in range(n)]):
        return sum(1 for mb in mbs if mb.verify_signature(pub) is None)
    v_med, v_min = timed(ver, 9)
    rows.append({"steps": n, "signature_count": n, "bytes_total": b,
                 "bytes_per_step": round(b / n, 2),
                 "sign_ms_total": s_med, "sign_min_ms": s_min,
                 "verify_ms_total": v_med, "verify_min_ms": v_min})
print("__INPROC__" + json.dumps(rows))
'''


def inproc_link_cost(workdir: str) -> list[dict]:
    """进程内 link 级成本（与我方 0.x ms 数字同口径，不含进程启动）。"""
    p = os.path.join(workdir, "_inproc_cost.py")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(INPROC_COST)
    r = subprocess.run([PY, p], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=600)
    for line in (r.stdout or "").splitlines():
        if line.startswith("__INPROC__"):
            return json.loads(line[len("__INPROC__"):])
    return [{"error": (r.stderr or "")[-500:]}]


def main() -> int:
    workdir = sys.argv[1]
    out = sys.argv[2]
    os.makedirs(workdir, exist_ok=True)

    rep = {
        "tool": "in-toto",
        "version": subprocess.run([RUN_EXE, "--version"], capture_output=True, text=True,
                                  encoding="utf-8", errors="replace").stdout.strip(),
        "python": sys.version.split()[0],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pip_freeze": subprocess.run([PY, "-m", "pip", "freeze"], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace").stdout.split("\n"),
        "layout_level": {},
        "tamper": {},
        "offline": {},
    }
    env_versions = {line.split("==")[0]: line.split("==")[1]
                    for line in rep["pip_freeze"] if "==" in line}
    rep["deps"] = {k: env_versions.get(k) for k in
                   ("in-toto", "securesystemslib", "cryptography", "attrs", "iso8601", "pathspec")}

    # CLI 空载启动基线（用于把「进程启动开销」从 CLI 墙钟里剥掉）
    base = {"verify": startup_ms(VERIFY_EXE), "run": startup_ms(RUN_EXE),
            "sign": startup_ms(SIGN_EXE)}
    rep["cli_startup_baseline_ms"] = base

    # 1) 真实流水线：N=3（用于篡改），N=1/5/20/50（用于规模对照）
    base_root = os.path.join(workdir, "pipe3")
    rep["layout_level"]["pipeline_build"] = run_pipeline(base_root, 3, verify_reps=5)
    rep["tamper"] = tamper_suite(base_root, workdir)
    rep["offline"] = offline_verify(base_root)

    scaling = []
    for n in (1, 5, 20, 50):
        r = run_pipeline(os.path.join(workdir, "pipe%d" % n), n, verify_reps=3 if n >= 20 else 5)
        scaling.append({
            "steps": n,
            "signature_count": r["signature_count"],
            "step_ms_total": r["step_ms_total"],
            "step_net_ms_total": round(r["step_ms_total"] - n * base["run"], 2),
            "sign_layout_ms": r["sign_layout_ms"],
            "sign_layout_net_ms": round(r["sign_layout_ms"] - base["sign"], 2),
            "verify_ms_median": r["verify_ms_median"],
            "verify_net_ms_median": round(r["verify_ms_median"] - base["verify"], 2),
            "link_bytes_total": r["link_bytes_total"],
            "link_bytes_per_step": r["link_bytes_per_step"],
            "layout_bytes": r["layout_bytes"],
            "pubkey_bytes": r["pubkey_bytes"],
            "signed_metadata_bytes": r["signed_metadata_bytes"],
            "verify_rc": r["verify_rc"],
            "step_rc_all_zero": all(s["rc"] == 0 for s in r["step_runs"]),
        })
    rep["scaling"] = scaling
    rep["inproc_link_cost"] = inproc_link_cost(workdir)

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)

    print(json.dumps({
        "version": rep["version"],
        "pipeline3_verify_rc": rep["layout_level"]["pipeline_build"]["verify_rc"],
        "pipeline3_verify_ms": rep["layout_level"]["pipeline_build"]["verify_ms_median"],
        "tamper_detected": "%d/%d" % (rep["tamper"]["detected"], rep["tamper"]["cases_total"]),
        "tamper_localized": rep["tamper"]["localized_to_step"],
        "offline_net_hits": (rep["offline"]["probe"] or {}).get("net_hits"),
        "offline_ok": rep["offline"]["ok"],
        "scaling": scaling,
        "out": out,
    }, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
