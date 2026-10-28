"""Swordholder：给 AI 的判断盖章，让任何人能独立验签。

公开 API 只有四件事：
    keygen()  生成 ed25519 签名密钥对
    seal()    把任意 JSON 结论封装成可验签凭证
    verify()  独立验签（不需要源码、不需要信任签发方）
    triage()  对安全告警做分诊，产出结论

命令行入口：``swordholder``（见 cli.py）。
"""

from .core import SealError, keygen, seal, triage, verify, verify_or_raise
from .rules import load_alert, rule_triage

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "keygen",
    "seal",
    "verify",
    "verify_or_raise",
    "triage",
    "rule_triage",
    "load_alert",
    "SealError",
]
