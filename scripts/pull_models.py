"""后台批量拉取异家族模型（Ollama HTTP API 流式），用于跨模型横向榜单。"""

import json
import sys
import time
import urllib.request

TARGETS = sys.argv[1:] or ["llama3.1:8b", "gemma3:12b", "deepseek-r1:8b"]


def pull(name: str) -> bool:
    payload = json.dumps({"name": name, "stream": True}).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/pull", data=payload,
                                 headers={"Content-Type": "application/json"})
    last = 0.0
    try:
        with urllib.request.urlopen(req, timeout=7200) as r:
            for raw in r:
                if not raw.strip():
                    continue
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if msg.get("error"):
                    print(f"[FAIL] {name}: {msg['error']}", flush=True)
                    return False
                st = msg.get("status", "")
                total = msg.get("total") or 0
                done = msg.get("completed") or 0
                if total and time.time() - last > 20:
                    last = time.time()
                    print(f"[{name}] {st} {done*100.0/total:.1f}%", flush=True)
        print(f"[OK] {name}", flush=True)
        return True
    except Exception as e:
        print(f"[FAIL] {name}: {e}", flush=True)
        return False


for t in TARGETS:
    ok = pull(t)
    print(f"===== {t} -> {'OK' if ok else 'FAIL'} =====", flush=True)
