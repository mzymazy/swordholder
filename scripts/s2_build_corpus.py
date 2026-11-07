"""把 splunk/attack_data 的公开 Windows 遥测解析成事件，并转成 swordholder 内部告警。

解析：整文件读入 → HTML 反转义（Splunk 常把 XML 转义成 &lt;Event&gt;）→ 抽取
`<Event ...>...</Event>` 块逐块解析；无 XML 包裹的纯文本行（如 PowerShell 脚本块）作为文本事件。

标注：锚点来自 MITRE ATT&CK 技术语义，与 rules-v1 关键词集合互不重叠，避免同义反复。
抽样：先对全量事件打锚点，再取全部正样本 + 确定性哈希抽样背景，避免攻击事件被稀释。
"""
import hashlib
import html
import json
import os
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
RAW = os.path.join(BASE, "corpus", "raw")
OUT = os.path.join(BASE, "corpus")
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

ANCHORS = {
    "T1003.001": ["lsass", "procdump", "comsvcs", "minidump", "sekurlsa", "dumpert", "nanodump"],
    "T1003.003": ["ntds.dit", "ntdsutil", "vssadmin", "wbadmin", "esentutl", "shadowcopy"],
    "T1059.001": ["-encodedcommand", "-enc ", "invoke-expression", "iex ", "downloadstring",
                  "frombase64string", "invoke-webrequest", "net.webclient"],
    "T1059.003": ["cmd.exe /c", "cmd /c", "for /l", "set /a", "& whoami", "dir /s"],
    "T1059.005": ["wscript", "cscript", "vbscript", "chrw(", "createobject("],
    "T1105": ["bitsadmin", "certutil -urlcache", "urlcache", "-transfer", "invoke-webrequest",
              "start-bitstransfer", "tftp", "ftp.exe"],
    "T1547.001": ["currentversion\\run", "runonce", "startup", "schtasks", "reg add"],
    "T1218.011": ["rundll32", "javascript:", "url.dll", "shell32.dll"],
    "T1569.002": ["psexec", "sc.exe create", "sc create", "new-service", "smbexec"],
    "T1112": ["reg add", "reg delete", "set-itemproperty", "hklm", "new-itemproperty"],
    "T1071.001": ["http://", "https://", "user-agent", "beacon", "dns"],
    "T1047": ["wmic", "invoke-wmimethod", "win32_process", "wmiprvse", "scrcons"],
    "T1055": ["createremotethread", "virtualalloc", "writeprocessmemory", "spawnto", "inject"],
    "T1136.001": ["net user", "new-localuser", "net localgroup", "add-localgroupmember"],
    "T1021.001": ["mstsc", "rdp", "termsrv", "3389"],
}
MAX_TEXT = 1500
MAX_BLOCK = 60000           # 单个 <Event> 块上限，防止异常长块
MAX_TEXT_EVENTS_PER_FILE = 1500
BG_CAP = 20000


def extract_event_blocks(txt):
    blocks, i = [], 0
    while True:
        s = txt.find("<Event", i)
        if s < 0:
            break
        e = txt.find("</Event>", s)
        if e < 0:
            break
        e += len("</Event>")
        if e - s <= MAX_BLOCK:
            blocks.append(txt[s:e])
        i = e
    return blocks


def parse_block(block):
    try:
        root = ET.fromstring(block)
    except Exception:  # noqa: BLE001
        return None
    sys_el = root.find(NS + "System")
    if sys_el is None:
        return None
    def g(tag):
        el = sys_el.find(NS + tag)
        return (el.text or "").strip() if el is not None else ""
    tc = sys_el.find(NS + "TimeCreated")
    fields = {}
    for d in root.iter(NS + "Data"):
        n = d.get("Name")
        if n and n not in fields:
            fields[n] = (d.text or "").strip()
    return {"channel": g("Channel"), "event_id": g("EventID"), "computer": g("Computer"),
            "time": tc.get("SystemTime") if tc is not None else "", "fields": fields}


def event_text(ev):
    f = ev["fields"]
    keys = ["CommandLine", "Image", "ParentImage", "TargetImage", "ScriptBlockText",
            "TargetObject", "Details", "ServiceName", "ServiceFileName", "DestinationIp",
            "DestinationHostname", "QueryName", "GrantedAccess", "NewProcessName",
            "TargetUserName", "SubjectUserName", "Url", "Payload"]
    parts = [f.get(k, "") for k in keys if f.get(k)]
    if not parts:
        parts = [f"{k}={v}" for k, v in list(f.items())[:8]]
    return " | ".join(parts)[:MAX_TEXT]


def main():
    stats = {"files": 0, "events": 0, "by_format": {}, "by_channel": {}, "by_technique": {},
             "by_eid": {}, "text_only_events": 0}
    events = []
    for dp, _dn, fns in os.walk(RAW):
        for fn in sorted(fns):
            if fn.endswith(".yml"):
                continue
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, RAW).replace("\\", "/")
            tech = rel.split("/")[0]
            stats["files"] += 1
            raw_txt = open(p, "r", encoding="utf-8", errors="replace").read()
            txt = html.unescape(raw_txt)
            blocks = extract_event_blocks(txt)
            for b in blocks:
                ev = parse_block(b)
                if ev is None:
                    continue
                ev.update({"fmt": "xml-wineventlog", "tech": tech, "file": rel})
                ev["text"] = event_text(ev)
                events.append(ev)
            if blocks:
                # 去掉已解析的 XML 块，剩余长文本行作为纯文本事件
                rest = txt
                for b in blocks:
                    rest = rest.replace(b, "\n", 1)
            else:
                rest = txt
            n_txt = 0
            for line in rest.splitlines():
                s = line.strip()
                if len(s) < 25 or n_txt >= MAX_TEXT_EVENTS_PER_FILE:
                    continue
                if s.startswith("<?xml") or s.startswith("</") or s.startswith("<Data"):
                    continue
                events.append({"channel": fn.replace(".log", ""), "event_id": "", "computer": "",
                               "time": "", "fields": {"line": s[:MAX_TEXT]}, "fmt": "plain-text",
                               "tech": tech, "file": rel, "text": s[:MAX_TEXT]})
                n_txt += 1
            stats["text_only_events"] += n_txt
            stats["by_technique"][tech] = stats["by_technique"].get(tech, 0) + len(blocks) + n_txt
    stats["events"] = len(events)

    for i, ev in enumerate(events):
        ev["h"] = hashlib.sha256(f"{ev['file']}#{i}".encode()).hexdigest()
        ev["fmt"] = ev["fmt"]
        stats["by_format"][ev["fmt"]] = stats["by_format"].get(ev["fmt"], 0) + 1
        stats["by_channel"][ev["channel"]] = stats["by_channel"].get(ev["channel"], 0) + 1
        eid = ev["event_id"] or "-"
        stats["by_eid"][eid] = stats["by_eid"].get(eid, 0) + 1
        t = (ev["text"] or "").lower()
        ev["hit"] = [a for a in ANCHORS.get(ev["tech"], []) if a in t]
        ev["label"] = "attack" if ev["hit"] else "background"

    pos = [e for e in events if e["label"] == "attack"]
    bg = [e for e in events if e["label"] == "background"]
    bg.sort(key=lambda e: e["h"])
    sample = pos + bg[:BG_CAP]
    sample.sort(key=lambda e: e["h"])

    alerts = []
    lab = {"pos": len(pos), "neg_in_sample": min(len(bg), BG_CAP),
           "neg_total": len(bg), "by_tech_pos": {}}
    for ev in pos:
        lab["by_tech_pos"][ev["tech"]] = lab["by_tech_pos"].get(ev["tech"], 0) + 1
    for ev in sample:
        aid = f"{ev['tech']}-{ev['h'][:12]}"
        sev = "high" if ev["event_id"] in ("10", "1", "4104") else "medium"
        m1 = {"alert_id": aid,
              "title": f"Windows event {ev['event_id'] or 'n/a'} on {ev['channel'] or 'unknown'}",
              "severity": sev, "signal": ev["channel"] or ev["fmt"],
              "description": ev["text"], "asset": ev["computer"] or None,
              "tags": [ev["tech"]], "observed_at": ev["time"] or None}
        m2 = dict(m1)
        m2["title"] = (f"{ev['tech']} suspicious activity reported by upstream detector "
                       f"({ev['file'].split('/')[-1]})")
        m2["signal"] = f"{ev['tech']} detection"
        alerts.append({"meta": {"label": ev["label"], "anchors": ev["hit"], "tech": ev["tech"],
                                "fmt": ev["fmt"], "file": ev["file"], "event_id": ev["event_id"],
                                "channel": ev["channel"]},
                       "m1": m1, "m2": m2})
    stats["labels"] = lab
    stats["sample_total"] = len(alerts)
    json.dump(stats, open(os.path.join(OUT, "events_stats.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    with open(os.path.join(OUT, "alerts_corpus.jsonl"), "w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a, ensure_ascii=False) + "\n")
    print(json.dumps({k: stats[k] for k in ("files", "events", "sample_total", "text_only_events",
                                            "by_format", "by_eid", "labels")},
                     ensure_ascii=False, indent=1)[:2600])


if __name__ == "__main__":
    main()
