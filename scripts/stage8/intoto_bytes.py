"""S8: 量 in-toto 侧同任务凭据体积（pretty / compact）。只做体积对照，不做定位对照。"""
import base64, glob, json, os, shutil, subprocess

VENV = os.path.join(os.environ["TEMP"], "s7_intoto_venv")
PY = os.path.join(VENV, "Scripts", "python.exe")
RUN = os.path.join(VENV, "Scripts", "in-toto-run.exe")
SIGN = os.path.join(VENV, "Scripts", "in-toto-sign.exe")
KEYS = os.path.join(os.environ["TEMP"], "s7_bench", "keys")
OUT = os.path.join(os.environ["TEMP"], "s8_intoto")


def sh(cmd, cwd=None):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=cwd)
    if r.returncode != 0:
        print("FAIL", os.path.basename(cmd[0]), r.stdout.strip()[:200], r.stderr.strip()[:400])
        raise SystemExit(1)


def dumps(o):
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)


res = {}
for n in (1, 5, 20, 50):
    work = os.path.join(OUT, "n%02d" % n)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    open(os.path.join(work, "seed0.txt"), "w").write("seed\n")
    art = os.path.join(work, "artifact.bin")
    open(art, "wb").write(b"payload" * 64)

    for i in range(n):
        sh([RUN, "-n", "step%02d" % i, "--signing-key", os.path.join(KEYS, "alice.key"),
            "--use-dsse", "-m", art, "-p", art, "-x"], cwd=work)

    links = sorted(glob.glob(os.path.join(work, "step*.link")))
    first = json.load(open(links[0], encoding="utf-8"))
    keyid = first["signatures"][0]["keyid"]
    pem = open(os.path.join(KEYS, "alice.pub"), encoding="utf-8").read()
    der = base64.b64decode("".join(l for l in pem.splitlines() if l and not l.startswith("-----")))
    keys_block = {keyid: {"keyid": keyid, "keytype": "ed25519", "scheme": "ed25519",
                          "keyval": {"public": der[-32:].hex()}}}

    steps = []
    for i in range(n):
        steps.append({
            "_type": "step",
            "name": "step%02d" % i,
            "expected_materials": ([["MATCH", "artifact.bin", "WITH", "PRODUCTS", "FROM", "step%02d" % (i - 1)],
                                    ["DISALLOW", "*"]] if i else [["ALLOW", "*"]]),
            "expected_products": [["ALLOW", "*"]],
            "pubkeys": [keyid],
            "expected_command": [],
            "threshold": 1,
        })
    layout = {
        "_type": "layout",
        "expires": "2027-11-08T00:00:00Z",
        "readme": "",
        "keys": keys_block,
        "steps": steps,
        "inspect": [],
    }
    lp = os.path.join(work, "root.layout")
    json.dump({"_type": "metablock", "signatures": [], "signed": layout},
              open(lp, "w", encoding="utf-8"), ensure_ascii=False)
    sh([SIGN, "-f", lp, "-k", os.path.join(KEYS, "owner.key")], cwd=work)

    files = [lp] + links
    pretty = sum(os.path.getsize(f) for f in files)
    compact = sum(len(dumps(json.load(open(f, encoding="utf-8"))).encode()) for f in files)
    all_files = sorted(os.listdir(work))
    res["N=%d" % n] = {
        "files": len(files),
        "pretty_bytes": pretty,
        "compact_bytes": compact,
        "note": "root.layout(owner 签名) + %d 个 link(每步 alice 签名)，不含签名者公钥文件与产物本体" % n,
        "dir_listing": all_files[:4],
    }
    print("N=%d files=%d pretty=%d compact=%d" % (n, len(files), pretty, compact))

json.dump(res, open(os.path.join(OUT, "intoto_bytes.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("OK")
