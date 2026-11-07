"""下载 splunk/attack_data 指定 MITRE 技术目录下的 Windows 遥测日志（只读公开数据）。

- 通过 GitHub Contents API 枚举目录；
- LFS 文件走 media.githubusercontent.com，普通文件走 raw.githubusercontent.com；
- 单文件上限 4MB、总量上限 90MB，避免把仓库撑爆；
- 记录每次下载的 URL、字节数、sha256，供报告复算。
"""
import hashlib
import json
import os
import sys
import urllib.request

API = "https://api.github.com/repos/splunk/attack_data/contents/"
MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
RAW = "https://raw.githubusercontent.com/splunk/attack_data/master/"
UA = {"User-Agent": "swordholder-audit"}
BASE = os.environ.get("S2_BASE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "corpus", "raw")
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 90 * 1024 * 1024
TECHS = ["T1003.001", "T1003.003", "T1059.001", "T1059.003", "T1059.005", "T1105",
         "T1547.001", "T1218.011", "T1569.002", "T1112", "T1071.001", "T1047",
         "T1055", "T1136.001", "T1021.001"]
KEEP = (".log", ".yml", ".json")


def ls(path):
    req = urllib.request.Request(API + path, headers=UA)
    return json.load(urllib.request.urlopen(req, timeout=40))


def fetch(path, limit):
    for base in (MEDIA, RAW):
        try:
            req = urllib.request.Request(base + path, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read(limit + 1)
            if len(data) > limit:
                return None, "too_big"
            if data[:8] == b"version " and b"git-lfs" in data[:120]:
                continue
            return data, "ok"
        except Exception:  # noqa: BLE001
            continue
    return None, "fetch_failed"


def main():
    manifest = []
    total = 0
    for tech in TECHS:
        try:
            subs = [x for x in ls("datasets/attack_techniques/" + tech) if x.get("type") == "dir"]
        except Exception as e:  # noqa: BLE001
            print(tech, "list_failed", type(e).__name__, flush=True)
            continue
        for sub in subs[:3]:
            pdir = f"datasets/attack_techniques/{tech}/{sub['name']}"
            try:
                files = ls(pdir)
            except Exception:  # noqa: BLE001
                continue
            for f in files:
                name = f["name"]
                if not name.endswith(KEEP):
                    continue
                rel = f"{pdir}/{name}"
                local = os.path.join(OUT, tech, sub["name"], name)
                if os.path.exists(local):
                    data = open(local, "rb").read()
                    why = "ok"
                else:
                    data, why = fetch(rel, MAX_FILE)
                rec = {"path": rel, "bytes": None, "sha256": None, "status": why}
                if data is not None:
                    if total + len(data) > MAX_TOTAL:
                        rec["status"] = "total_cap"
                        manifest.append(rec)
                        continue
                    local = os.path.join(OUT, tech, sub["name"], name)
                    os.makedirs(os.path.dirname(local), exist_ok=True)
                    with open(local, "wb") as fh:
                        fh.write(data)
                    total += len(data)
                    rec["bytes"] = len(data)
                    rec["sha256"] = hashlib.sha256(data).hexdigest()
                    rec["local"] = local
                manifest.append(rec)
        print(tech, "done", total // 1024, "KB", flush=True)
    with open(os.path.join(os.path.dirname(OUT), "download_manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"total_bytes": total, "files": manifest}, fh, ensure_ascii=False, indent=1)
    ok = [m for m in manifest if m["status"] == "ok"]
    print("files_ok", len(ok), "bytes", total)


if __name__ == "__main__":
    main()
