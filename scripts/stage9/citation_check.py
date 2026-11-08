# -*- coding: utf-8 -*-
"""S9 引用核验：把报告里引用的每一个链接跑一遍，记录 HTTP 状态、字节数、内容指纹，
并把要引用的原句从已下载的权威 PDF 里逐字抽出来（不做任何改写）。

为何单独一个脚本：第九阶段的立论方式从"我们自证"改成"外部可核引"。可核引的最低要求是
①链接今天能打开 ②条文编号对得上 ③引号里的话能在这份文件里逐字找到。
这三件事都必须留下可复跑的记录，而不是写在报告里靠读者相信。

用法::

    python scripts/stage9/citation_check.py --out evidence/stage9/s9_citations.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
CACHE = ROOT / "evidence" / "stage9" / "src"

URLS = [
    ("eu_ai_act_full", "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
     "EU AI Act 全文（Regulation (EU) 2024/1689），Article 12 / 19 / 26 / 73 与 Recital 71 的权威出处"),
    ("eu_art12_mirror", "https://www.artificialintelligenceact.eu/article/12/",
     "Article 12 Record-keeping 可读镜像（与 OJ 原文对照用）"),
    ("eu_art19_mirror", "https://www.artificialintelligenceact.eu/article/19/",
     "Article 19 Automatically generated logs 可读镜像"),
    ("eu_art26_mirror", "https://www.artificialintelligenceact.eu/article/26/",
     "Article 26 Obligations of deployers 可读镜像"),
    ("eu_art73_mirror", "https://www.artificialintelligenceact.eu/article/73/",
     "Article 73 Reporting of serious incidents 可读镜像"),
    ("eu_recital71_mirror", "https://www.artificialintelligenceact.eu/recital/71/",
     "Recital 71 可读镜像"),
    ("nist_ai_rmf_100_1", "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
     "NIST AI RMF 1.0（AI 100-1）"),
    ("nist_ai_600_1", "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
     "NIST AI 600-1 Generative AI Profile"),
    ("sr_11_7", "https://www.federalreserve.gov/boarddocs/srletters/2011/sr1107a1.pdf",
     "SR 11-7 Guidance on Model Risk Management"),
    ("iso_42001_official", "https://www.iso.org/standard/81230.html",
     "ISO/IEC 42001:2023 官方页面（标准正文为付费内容）"),
    ("iso_42001_catalog", "https://www.iso.org/standard/42001",
     "ISO/IEC 42001 目录跳转"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) swordholder-s9-citation-check"


def fetch(url: str, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return {"url": url, "status": r.status, "bytes": len(raw),
                    "content_type": r.headers.get("Content-Type", ""),
                    "sha256": hashlib.sha256(raw).hexdigest(), "body": raw,
                    "final_url": r.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "bytes": 0, "body": b"", "error": "HTTPError"}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "status": None, "bytes": 0, "body": b"", "error": type(e).__name__}


def _pdf_text(path: pathlib.Path) -> str:
    from pypdf import PdfReader
    reader = PdfReader(str(path))
    out = []
    for p in reader.pages:
        out.append(p.extract_text() or "")
    return "\n".join(out)


def _norm(text: str) -> str:
    """把空白压平；同时消掉 "12 (1)" 与 "12(1)" 这类排版差异（镜像页会在括号前加空格）。

    这一步只是为了做逐字对比，不改变任何字词；报告里引用的句子仍然照抄原文。
    """
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"(?<=\d)\s+\(", "(", text)
    return text.strip()


def _html_text(raw: bytes) -> str:
    doc = raw.decode("utf-8", "ignore")
    doc = re.sub(r"(?is)<(script|style).*?</\1>", " ", doc)
    doc = re.sub(r"(?s)<[^>]+>", " ", doc)
    doc = (doc.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
              .replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " "))
    return _norm(doc)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "evidence/stage9/s9_citations.json"))
    ap.add_argument("--offline", action="store_true", help="只用本地缓存，不联网")
    args = ap.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    records = []
    for key, url, purpose in URLS:
        cache_path = CACHE / f"{key}.bin"
        if args.offline and cache_path.exists():
            raw = cache_path.read_bytes()
            rec = {"key": key, "url": url, "purpose": purpose, "status": 200,
                   "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                   "source": "cache", "error": None}
            body = raw
        else:
            got = fetch(url)
            body = got.pop("body")
            rec = {"key": key, "purpose": purpose, "source": "network", **got}
            if got.get("status") == 200 and body:
                cache_path.write_bytes(body)
            else:
                if cache_path.exists():  # 网络失败时回落到缓存，并显式标注
                    body = cache_path.read_bytes()
                    rec["fallback_to_cache"] = True
                    rec["bytes"] = len(body)
        records.append(rec)
        print(f"{key:24s} status={rec.get('status')} bytes={rec.get('bytes')} {rec.get('error') or ''}")

    # ---- 逐字抽句：从本地 PDF 里按 Action ID / 段落定位，抽取原文，供报告引用
    quotes: dict[str, dict] = {}

    def grab(pdf_key: str, key: str, pattern: str, label: str, width: int = 700):
        path = CACHE / f"{pdf_key}.bin"
        if not path.exists():
            quotes[label] = {"found": False, "reason": f"缺 {pdf_key} 本地副本"}
            return
        txt = _norm(_pdf_text(path))
        m = re.search(pattern, txt)
        if not m:
            quotes[label] = {"found": False, "reason": "未命中 pattern", "pattern": pattern,
                             "key": key}
            return
        start = m.start()
        snippet = txt[start:start + width].strip()
        quotes[label] = {"found": True, "key": key, "quote": snippet}

    grab("nist_ai_rmf_100_1", "MEASURE 2.7",
         r"MEASURE 2\.7",
         "rmf_measure_2_7")
    grab("nist_ai_rmf_100_1", "MEASURE 3.1",
         r"MEASURE 3\.1",
         "rmf_measure_3_1")
    grab("nist_ai_rmf_100_1", "MEASURE 2.8",
         r"MEASURE 2\.8",
         "rmf_measure_2_8")
    grab("nist_ai_600_1", "MS-2.8-003",
         r"MS-2\.8-003",
         "gai_ms_2_8_003")
    grab("nist_ai_600_1", "MS-1.1-002",
         r"MS-1\.1-002",
         "gai_ms_1_1_002")
    grab("nist_ai_600_1", "MS-2.7-005",
         r"MS-2\.7-005",
         "gai_ms_2_7_005")
    grab("nist_ai_600_1", "GV-1.6-003",
         r"GV-1\.6-003",
         "gai_gv_1_6_003")
    grab("sr_11_7", "documentation",
         r"Documentation of model development and validation should be sufficiently detailed",
         "sr_doc_detailed", width=600)
    grab("sr_11_7", "tracking",
         r"Documentation and tracking of activities surrounding model development",
         "sr_tracking", width=600)

    # ---- 双源交叉核对：同一句条文，必须在「OJ 原文副本」与「镜像页」里都能逐字找到
    # 注意：镜像页在专有名词后插入了定义气泡（如 "AI system means a machine-based system..."），
    # 因此不能拿整句做精确子串匹配，只能拿“不含专有名词的探针片段”比对。这是方法限制，写进报告。
    cross: dict[str, dict] = {}
    oj = CACHE / "eu_ai_act_full.bin"
    mirror_map = {
        "art12": "eu_art12_mirror", "art19": "eu_art19_mirror",
        "art26": "eu_art26_mirror", "art73": "eu_art73_mirror",
        "rec71": "eu_recital71_mirror",
    }
    probes = {
        "art12_1": ["High-risk AI systems shall technically allow for the automatic recording "
                    "of events (logs) over the lifetime of the system"],
        "art12_2": ["logging capabilities shall enable the recording of events relevant for"],
        "art19_1": ["keep the logs referred to in Article 12(1), automatically generated by their",
                    "of at least six months, unless provided otherwise"],
        "art26_6": ["keep the logs automatically generated by that",
                    "to the extent such logs are under their control",
                    "of at least six months, unless provided otherwise"],
        "art73_6": ["shall not perform any investigation which involves altering the",
                    "in a way which may affect any subsequent evaluation of the causes of the "
                    "incident, prior to informing the competent authorities"],
        "rec71": ["high-risk AI systems should technically allow for the automatic recording of "
                  "events, by means of logs, over the duration of the lifetime of the system"],
    }
    oj_text = _html_text(oj.read_bytes()) if oj.exists() else ""
    for label, frags in probes.items():
        mir_key = mirror_map.get(label.split("_")[0])
        mir = CACHE / f"{mir_key}.bin" if mir_key else None
        mir_text = _html_text(mir.read_bytes()) if (mir and mir.exists()) else ""
        frags_n = [_norm(f) for f in frags]
        oj_hits = sum(1 for f in frags_n if f in oj_text)
        mir_hits = sum(1 for f in frags_n if f in mir_text) if mir_text else 0
        cross[label] = {
            "probes": frags,
            "oj_hits": oj_hits,
            "mirror_hits": mir_hits if mir_text else None,
            "mirror": mir_key,
            "both": oj_hits == len(frags) and bool(mir_text) and mir_hits == len(frags),
        }

    out = {"checked_at_unix": __import__("time").time(), "records": records, "quotes": quotes,
           "eu_cross_check": cross,
           "eu_cross_check_both": sum(1 for v in cross.values() if v.get("both")),
           "eu_cross_check_total": len(cross)}
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    for label, v in cross.items():
        print(f"  cross {label:9s} oj={v['oj_hits']}/{len(v['probes'])} "
              f"mirror={v['mirror_hits']}/{len(v['probes'])} both={v['both']}")
    print("\nquotes:")
    for k, v in quotes.items():
        print(f"  {k:22s} found={v.get('found')} {'' if v.get('found') else v.get('reason')}")
    print("written:", args.out)


if __name__ == "__main__":
    main()
