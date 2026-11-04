"""策略包加载器：把"什么算合规判定"从内核代码里搬进可替换的 YAML。

为什么要这一层（见 docs/DESIGN-policy-layer.md）：
    之前的 guardrail 把"告警分诊"这一个场景的领域知识写死在 if 里——
    换场景（AI 改配置、AI 对外发信）就得改内核，加一个场景等于加一次回归风险。
    现在内核只做一件事：按策略文件执行校验。领域知识住在这里，代码只是容器。

加载顺序：
    1. 显式传入的 path
    2. 环境变量 SWORDHOLDER_POLICY
    3. 内置默认包 default-soc-triage.yaml

失败姿势：**fail-closed**。策略文件缺失、解析失败、字段不全，一律抛 PolicyError，
由调用方决定停机还是降级——绝不"读不到就放行"。
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

try:
    import yaml
except ImportError as e:  # pragma: no cover
    raise ImportError("策略层依赖 pyyaml，请先 pip install pyyaml") from e

SCHEMA = "swordholder/policy/v1"
ENV_VAR = "SWORDHOLDER_POLICY"
POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy")
DEFAULT_POLICY = os.path.join(POLICY_DIR, "default-soc-triage.yaml")

_REQUIRED = ("schema", "id", "verdicts", "severities", "limits", "invariants")
_REQUIRED_LIMITS = ("min_ok_steps", "max_hypothesis_len", "actions_min", "actions_max",
                    "action_max_len", "action_min_len")
REQUIRE_TYPES = ("tool_verified_ref", "window_covers_alert")


class PolicyError(RuntimeError):
    """策略包不合法。调用方应当 fail-closed（回落到规则层或停机），不得放行。"""


def _fail(msg: str) -> None:
    raise PolicyError(msg)


def validate(p: Any, origin: str = "<memory>") -> dict:
    """结构性校验。只查"内核能不能执行"，不查业务是否合理。"""
    if not isinstance(p, dict):
        _fail(f"{origin}: 策略包必须是映射（dict），实际 {type(p).__name__}")

    miss = [k for k in _REQUIRED if k not in p]
    if miss:
        _fail(f"{origin}: 缺少必需字段 {miss}")

    if p["schema"] != SCHEMA:
        _fail(f"{origin}: schema 不匹配，期望 {SCHEMA}，实际 {p['schema']!r}")

    for key in ("verdicts", "severities"):
        v = p[key]
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
            _fail(f"{origin}: {key} 必须是非空字符串列表")

    limits = p["limits"]
    if not isinstance(limits, dict):
        _fail(f"{origin}: limits 必须是映射")
    miss_l = [k for k in _REQUIRED_LIMITS if k not in limits]
    if miss_l:
        _fail(f"{origin}: limits 缺少 {miss_l}")
    for k in _REQUIRED_LIMITS:
        if not isinstance(limits[k], int) or limits[k] < 0:
            _fail(f"{origin}: limits.{k} 必须是非负整数")

    cmap = p.get("confidence_text_map") or {}
    if not isinstance(cmap, dict):
        _fail(f"{origin}: confidence_text_map 必须是映射")
    for k, v in cmap.items():
        if not isinstance(v, (int, float)) or not 0.0 <= float(v) <= 1.0:
            _fail(f"{origin}: confidence_text_map.{k} 必须在 [0,1]")

    invs = p["invariants"]
    if not isinstance(invs, list):
        _fail(f"{origin}: invariants 必须是列表")
    seen = set()
    for i, inv in enumerate(invs):
        if not isinstance(inv, dict):
            _fail(f"{origin}: invariants[{i}] 必须是映射")
        for k in ("id", "when", "require", "field"):
            if k not in inv:
                _fail(f"{origin}: invariants[{i}] 缺少 {k}")
        if inv["id"] in seen:
            _fail(f"{origin}: invariants id 重复：{inv['id']}")
        seen.add(inv["id"])
        if inv["require"] not in REQUIRE_TYPES:
            _fail(f"{origin}: invariants[{i}].require={inv['require']!r} 不支持，"
                  f"可用 {list(REQUIRE_TYPES)}")
        when = inv["when"]
        if not isinstance(when, dict) or "verdict" not in when:
            _fail(f"{origin}: invariants[{i}].when 必须含 verdict")
        if when["verdict"] not in p["verdicts"]:
            _fail(f"{origin}: invariants[{i}].when.verdict={when['verdict']!r} 不在 verdicts 内")
        msgs = inv.get("messages") or {}
        if not isinstance(msgs, dict) or not msgs:
            _fail(f"{origin}: invariants[{i}] 必须给出 messages")
    return p


@lru_cache(maxsize=8)
def _load_cached(path: str, mtime: float) -> dict:  # noqa: ARG001  (mtime 只用于让缓存失效)
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return validate(raw, origin=path)


def resolve_path(path: str | None = None) -> str:
    return path or os.environ.get(ENV_VAR) or DEFAULT_POLICY


def load(path: str | None = None) -> dict:
    """加载并校验策略包。任何异常都转成 PolicyError，调用方据此 fail-closed。"""
    p = resolve_path(path)
    if not os.path.exists(p):
        raise PolicyError(f"策略包不存在：{p}")
    try:
        return _load_cached(os.path.abspath(p), os.path.getmtime(p))
    except PolicyError:
        raise
    except Exception as e:  # noqa: BLE001
        raise PolicyError(f"策略包解析失败：{p}：{e}") from e


def list_builtin() -> list[tuple[str, str, str]]:
    """列出内置策略包：(文件名, id, title)。供 CLI 展示。"""
    out = []
    if not os.path.isdir(POLICY_DIR):
        return out
    for name in sorted(os.listdir(POLICY_DIR)):
        if not name.endswith((".yaml", ".yml")):
            continue
        try:
            p = load(os.path.join(POLICY_DIR, name))
            out.append((name, p.get("id", "?"), p.get("title", "")))
        except PolicyError as e:
            out.append((name, "<invalid>", str(e)))
    return out


__all__ = ["PolicyError", "SCHEMA", "ENV_VAR", "DEFAULT_POLICY", "POLICY_DIR",
           "validate", "load", "resolve_path", "list_builtin", "REQUIRE_TYPES"]
