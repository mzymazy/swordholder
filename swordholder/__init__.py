"""Swordholder锛氱粰 AI 鐨勫垽鏂洊绔狅紝璁╀换浣曚汉閮借兘鐙珛楠岀銆?

鍏紑 API锛?
    keygen()       鐢熸垚 ed25519 绛惧悕瀵嗛挜瀵?
    seal()         鎶婁换鎰?JSON 缁撹灏佽鎴愬彲楠岀鍑瘉
    verify()       鐙珛楠岀锛堜笉闇€瑕佹簮鐮併€佷笉闇€瑕佷俊浠荤鍙戞柟锛?
    triage()       瀵瑰畨鍏ㄥ憡璀﹀仛鍒嗚瘖锛屼骇鍑虹粨璁?
    triage_event() 鍏堟妸浠绘剰鏉ユ簮鍛婅褰掍竴锛屽啀鍒嗚瘖锛圫plunk/Sentinel/Wazuh/鑷畾涔夛級
    normalize()    鍙仛鍛婅褰掍竴涓庢牎楠岋紙濂戠害瑙?alert.schema.json锛?
    Store          鍑瘉绱㈠紩锛坰qlite锛夛紝渚涙寜缁撹/涓讳綋/鏃堕棿妫€绱?
    trust          淇′换閿氭不鐞嗭細杞崲绐楀彛銆佸瘑閽?鍑瘉鍚婇攢銆佽疆鎹綋妫€
    ServerConfig / build_server   HTTP 鏈嶅姟锛坰erve.py锛?

鍛戒护琛屽叆鍙ｏ細``swordholder``锛堣 cli.py锛夈€?
"""

from .core import SealError, keygen, seal, triage, triage_event, verify, verify_or_raise
from .alert import AlertError, detect_format, normalize
from .rules import load_alert, rule_triage
from .store import Store
from . import trust
from .retention import MIN_RETENTION_DAYS, RetentionError, RetentionPolicy
from . import seal_schema
from .trust import (TrustError, add_key, retire_key, revoke_key, revoke_seal,
                    restore_seal, summary, check_rotation, evaluate)

__version__ = "0.8.0"

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
    "trust",
    "seal_schema",
    "TrustError",
    "add_key",
    "retire_key",
    "revoke_key",
    "revoke_seal",
    "restore_seal",
    "summary",
    "check_rotation",
    "evaluate",
    "RetentionPolicy",
    "RetentionError",
    "MIN_RETENTION_DAYS",
]

