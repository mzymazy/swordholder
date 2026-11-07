"""消融实验：把"判定到底由什么驱动"量化出来。

A1 结构化技术标签：给告警补 ATT&CK 技术标签与检测语义名（仍不含 rules 关键词）
A2 头部注入外联语义：模拟上游检测命名为 "Outbound C2 beacon ..."
A3 证据注入供应链关键词：测上限与判别力（正/负样本是否同样被判 TP）
"""
import json
import os
import sys

BASE = os.environ.get("S2_BASE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.environ.get("SWORDHOLDER_REPO") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from swordholder import rules  # noqa: E402
from swordholder.alert import normalize  # noqa: E402


def load():
    out = []
    for line in open(os.path.join(BASE, "corpus", "alerts_corpus.jsonl"), encoding="utf-8"):
        out.append(json.loads(line))
    return out


def run(alerts, mutate, name):
    agg = {"name": name,
           "attack": {"n": 0, "verdict": {}},
           "background": {"n": 0, "verdict": {}}}
    for a in alerts:
        raw = mutate(dict(a["m1"]))
        norm = normalize(raw, fmt="generic")
        r = rules.rule_triage(norm)
        lab = a["meta"]["label"]
        agg[lab]["n"] += 1
        agg[lab]["verdict"][r["verdict"]] = agg[lab]["verdict"].get(r["verdict"], 0) + 1
    for lab in ("attack", "background"):
        s = agg[lab]
        s["tp_rate"] = round(s["verdict"].get("true_positive", 0) / max(s["n"], 1), 4)
        s["fp_rate"] = round(s["verdict"].get("false_positive", 0) / max(s["n"], 1), 4)
    return agg


def m_identity(x):
    return x


def m_attack_tag(x):
    x["tags"] = list(x.get("tags") or []) + ["attack.t1059.001", "lsass", "credential-dump"]
    x["title"] = x["title"] + " [ATT&CK T1059.001]"
    return x


def m_egress_name(x):
    x["title"] = "Outbound C2 beacon to unknown ASN - " + x["title"]
    return x


def m_inject_supply(x):
    x["description"] = (x.get("description") or "") + " npm install postinstall payload"
    return x


def main():
    alerts = load()
    res = [run(alerts, m_identity, "baseline"),
           run(alerts, m_attack_tag, "A1_attack_tag"),
           run(alerts, m_egress_name, "A2_egress_name"),
           run(alerts, m_inject_supply, "A3_inject_supply_keywords")]
    json.dump(res, open(os.path.join(BASE, "stage2_ablations.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    for r in res:
        print(r["name"], "attack", r["attack"]["verdict"], "bg", r["background"]["verdict"],
              "| tp_atk", r["attack"]["tp_rate"], "tp_bg", r["background"]["tp_rate"])


if __name__ == "__main__":
    main()
