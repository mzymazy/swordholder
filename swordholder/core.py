"""高层封装：把 MCP Server 里的底层实现收敛成四个函数。

保持单一路径原则 —— CLI、MCP、测试都调这里，不各自复制一份逻辑。
"""

from __future__ import annotations

import json
import os
from typing import Any, Union

from mcp_server import server as _srv
from . import alert as _alert
from . import rules


class SealError(RuntimeError):
    """盖章失败（密钥缺失、写入失败等）。"""


def keygen(out_dir: str = "keys") -> dict:
    """生成密钥对，返回 {'private_key_path', 'public_key_path', 'public_key_hex'}。"""
    res = _srv.tool_keygen({"out_dir": out_dir})
    if not res.get("ok"):
        raise SealError(res.get("error") or "keygen failed")
    return res


def seal(record: Union[dict, str], private_key_path: str, issuer: str,
         subject: str | None = None, out_path: str | None = None) -> dict:
    """给一条结论盖章。

    record 可以是 dict，也可以是 JSON 文件路径。
    subject 默认取 record 里的 alert_id / subject / id 之一。
    """
    payload = None
    if isinstance(record, dict):
        payload = record
    elif isinstance(record, str):
        if not os.path.exists(record):
            raise SealError(f"record 不存在：{record}")
        with open(record, "r", encoding="utf-8") as f:
            payload = json.load(f)
    else:
        raise SealError("record 必须是 dict 或 JSON 路径")

    if subject is None:
        for k in ("alert_id", "subject", "id", "record_id"):
            if isinstance(payload, dict) and payload.get(k):
                subject = str(payload[k])
                break

    args: dict[str, Any] = {"payload": payload, "private_key_path": private_key_path,
                            "issuer": issuer}
    if subject:
        args["subject"] = subject
    if out_path:
        args["out_path"] = out_path

    res = _srv.tool_seal_record(args)
    if not res.get("ok"):
        raise SealError(res.get("error") or "seal failed")
    return res


def verify(seal_path: str, keys_path: str | None = None) -> dict:
    """验签。返回 {'verdict': VALID|VALID_UNTRUSTED_KEY|INVALID, 'reason': ...}。

    注意：没有提供信任锚时不会返回裸 VALID，而是 VALID_UNTRUSTED_KEY —— 签名有效
    但签发方未被登记，调用方不得据此声称“已获得信任背书”。
    """
    args: dict[str, Any] = {"seal_path": seal_path}
    if keys_path:
        args["keys_path"] = keys_path
    return _srv.tool_verify_seal(args)


def verify_or_raise(seal_path: str, keys_path: str | None = None,
                    require_trusted: bool = False) -> dict:
    res = verify(seal_path, keys_path)
    verdict = res.get("verdict")
    if verdict == "INVALID":
        raise SealError(f"{res.get('reason')}: {res.get('expected')} != {res.get('actual')}")
    if require_trusted and verdict != "VALID":
        raise SealError(f"签发方未通过信任校验：{res.get('reason')}")
    return res


def triage(alert: Union[dict, str], use_llm: bool = False, model: str | None = None) -> dict:
    """分诊一条告警。use_llm=True 且本机 Ollama 可用时才叠加 LLM 增强。"""
    if isinstance(alert, str):
        alert = rules.load_alert(alert)
    return rules.triage(alert, use_llm=use_llm, model=model or rules.DEFAULT_MODEL)


KEEP_FIELDS = ("alert_id", "title", "severity", "signal", "asset", "tags",
               "observed_at", "source")


def payload_sha256(record: dict) -> str:
    """与盖章时写入 header 的 payload_sha256 完全同一算法（json-c14n-v1）。"""
    return _srv.sha256_hex(_srv.c14n(record))



def triage_event(raw: Union[dict, str], fmt: str = "auto", use_llm: bool = False,
                 model: str | None = None) -> dict:
    """归一化任意来源告警后分诊。

    与 :func:`triage` 的区别：先过适配层做字段归一与校验（非法输入抛
    alert.AlertError），并在结论里附 ``input`` 区块——只保留归一后的身份字段与
    原始载荷 sha256，作为凭证可审计的输入凭据（不把原始日志塞进凭证）。
    """
    if isinstance(raw, str):
        import pathlib
        raw = json.loads(pathlib.Path(raw).read_text(encoding="utf-8"))
    normalized = _alert.normalize(raw, fmt=fmt)
    res = rules.triage(normalized, use_llm=use_llm, model=model or rules.DEFAULT_MODEL)
    res["input"] = {k: normalized.get(k) for k in KEEP_FIELDS}
    res["schema_version"] = normalized.get("schema_version")
    return res

