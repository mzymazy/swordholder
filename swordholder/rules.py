"""分诊规则与可选 LLM 增强。

规则层永远可用（无网络、无模型），LLM 只在 verdict/severity 之外补成因假设与建议。
定性顺序：供应链 → 异常外联 → 凭证重放 → 演练白名单 → 兜底 suspicious。
"""

from __future__ import annotations

import json
import os
import urllib.request

DEFAULT_MODEL = os.environ.get("SWORDHOLDER_MODEL", "qwen3:8b")
DEFAULT_BASE = os.environ.get("SWORDHOLDER_OLLAMA", "http://127.0.0.1:11434")

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def _rule(signal: str, tags: list, alert: dict) -> tuple[str, str, float, list]:
    """返回 (verdict, hypothesis, confidence, actions)。"""
    # 定性只看"告警信号 + 标题"，描述仅作上下文，避免描述里的关键词抢判
    head = " ".join([str(alert.get("title", "")), signal]).lower()
    text = " ".join([head, str(alert.get("description", ""))]).lower()

    if any(t in text for t in ["typosquat", "postinstall", "preinstall",
                               "supply-chain", "supply chain", "npm", "pypi"]):
        return ("true_positive", "依赖包安装期脚本执行外部载荷，疑似供应链投毒",
                0.91, ["冻结该依赖版本并从锁文件移除",
                       "隔离构建机镜像，重建缓存",
                       "全量扫描近 30 天引入该包的产物"])

    if any(t in head for t in ["outbound", "egress", "unknown asn", "dns tunnel", "c2", "beacon"]):
        conf = 0.78 if str(alert.get("severity", "")).lower() in ("high", "critical") else 0.62
        return ("suspicious", "主机向未登记 ASN 发起加密外联，需结合进程树与外联频次定性",
                conf, ["抓取目标 IP 与域名的被动 DNS 记录",
                       "导出该进程树与命令行",
                       "在 EDR 上加该 ASN 的出站告警阈值"])

    if any(t in text for t in ["ci token", "cicd", "pipeline token", "build-runner", "runner"]):
        return ("true_positive", "构建机凭证在非预期上下文被使用，疑似泄露后重放",
                0.86, ["立即吊销该 CI token 并重签",
                       "检查构建机出网目的地白名单",
                       "回溯近 7 天该 token 的调用来源 ASN"])

    if any(t in text for t in ["authorized pentest", "red team", "演练", "白名单扫描"]):
        return ("false_positive", "命中演练或授权测试窗口，非真实攻击",
                0.88, ["核对演练工单编号与时间窗", "将来源加入临时白名单并设到期"])

    return ("suspicious", "信号不足以定性，需补充上下文", 0.5,
            ["补充资产画像与进程树", "人工复核"])


def rule_triage(alert: dict) -> dict:
    verdict, hypothesis, confidence, actions = _rule(
        alert.get("signal", ""), alert.get("tags", []) or [], alert)
    return {
        "alert_id": alert.get("alert_id"),
        "asset": alert.get("asset"),
        "verdict": verdict,
        "severity": alert.get("severity", "medium"),
        "confidence": confidence,
        "hypothesis": hypothesis,
        "actions": actions,
        "engine": "rules-v1",
    }


def llm_available(base: str = DEFAULT_BASE) -> bool:
    try:
        with urllib.request.urlopen(base + "/api/tags", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def llm_enrich(alert: dict, base_triage: dict, model: str = DEFAULT_MODEL,
               base: str = DEFAULT_BASE, timeout: int = 90) -> dict:
    """LLM 只允许补 hypothesis/actions，不允许改 verdict/severity。失败原样返回。"""
    prompt = (
        "你是 SOC 分诊助手。基于以下告警与规则初判，用中文给出更具体的成因假设与处置建议。\n"
        "硬约束：不得改变 verdict 与 severity，只输出 JSON："
        '{"hypothesis":"...","actions":["...","..."],"notes":"..."}\n'
        f"告警：{json.dumps(alert, ensure_ascii=False)}\n"
        f"规则初判：{json.dumps(base_triage, ensure_ascii=False)}"
    )
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json",
                       "options": {"temperature": 0.2, "num_predict": 400}}).encode("utf-8")
    req = urllib.request.Request(base + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(json.loads(r.read().decode("utf-8")).get("response", "{}"))
    except Exception as e:
        merged = dict(base_triage)
        merged["engine"] = "rules-v1 (llm-unavailable)"
        merged["llm_note"] = type(e).__name__
        return merged

    merged = dict(base_triage)
    if out.get("hypothesis"):
        merged["hypothesis_llm"] = out["hypothesis"]
    if isinstance(out.get("actions"), list) and out["actions"]:
        merged["actions_llm"] = out["actions"]
    merged["engine"] = f"rules-v1+{model}"
    return merged


def triage(alert: dict, use_llm: bool = False, model: str = DEFAULT_MODEL) -> dict:
    base_triage = rule_triage(alert)
    if use_llm and llm_available():
        return llm_enrich(alert, base_triage, model=model)
    if use_llm:
        base_triage["engine"] = "rules-v1 (llm-not-running)"
    return base_triage


def load_alert(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sample_alerts() -> list[str]:
    if not os.path.isdir(SAMPLE_DIR):
        return []
    skip = (".seal.json", ".triage.json")
    return sorted(os.path.join(SAMPLE_DIR, n) for n in os.listdir(SAMPLE_DIR)
                  if n.endswith(".json") and not n.endswith(skip))
