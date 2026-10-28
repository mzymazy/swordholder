"""兼容层：规则实现已迁到 `swordholder.rules`，此处只保留旧入口不破坏既有脚本。

新代码请直接 `from swordholder.rules import triage` 或 `from swordholder import triage`。
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from swordholder.rules import (  # noqa: E402,F401
    DEFAULT_BASE,
    DEFAULT_MODEL,
    llm_available,
    llm_enrich,
    load_alert,
    rule_triage,
    sample_alerts,
    triage,
)

__all__ = ["DEFAULT_BASE", "DEFAULT_MODEL", "llm_available", "llm_enrich",
           "load_alert", "rule_triage", "sample_alerts", "triage"]
