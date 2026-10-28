"""Swordholder：给 AI 的判断盖章，让任何人能独立验签。

公开 API：
    keygen()       生成 ed25519 签名密钥对
    seal()         把任意 JSON 结论封装成可验签凭证
    verify()       独立验签（不需要源码、不需要信任签发方）
    triage()       对安全告警做分诊，产出结论
    triage_event() 先把任意来源告警归一，再分诊（Splunk/Sentinel/Wazuh/自定义）
    normalize()    只做告警归一与校验（契约见 alert.schema.json）
    Store          凭证索引（sqlite），供按结论/主体/时间检索
    ServerConfig / build_server   HTTP 服务（serve.py）

命令行入口：``swordholder``（见 cli.py）。
"""

from .core import SealError, keygen, seal, triage, triage_event, verify, verify_or_raise
from .alert import AlertError, detect_format, normalize
from .rules import load_alert, rule_triage
from .store import Store

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "keygen",
    "seal",
    "verify",
    "verify_or_raise",
    "triage",
    "triage_event",
    "normalize",
    "detect_format",
    "rule_triage",
    "load_alert",
    "Store",
    "SealError",
    "AlertError",
]

