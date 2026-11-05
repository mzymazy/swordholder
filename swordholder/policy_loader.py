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
import re
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

# 会话级不变量白名单（P0-2）。拼错一个 id 就等于静默关掉一条防线，所以在加载期就拦。
SESSION_SCHEMA = "swordholder/session/v1"
SESSION_RULES = ("S1_claim_must_be_verified", "S2_precedent_must_be_verified",
                 "S3_axiom_never_authorizes", "S4_turn_budget",
                 "S5_no_relax_without_new_evidence", "S6_relax_limit")


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

    validate_session(p.get("session"), origin=origin)
    return p


def validate_session(seg: Any, origin: str = "<memory>") -> None:
    """校验可选的会话级策略段（P0-2）。缺省合法——单轮场景不必声明。

    一旦声明就必须能被执行：正则必须编译得过、不变量 id 必须在白名单内。
    否则"策略写了但内核没认"就是一条静默失效的防线。
    """
    if seg is None:
        return
    if not isinstance(seg, dict):
        _fail(f"{origin}: session 段必须是映射")

    sch = seg.get("schema", SESSION_SCHEMA)
    if sch != SESSION_SCHEMA:
        _fail(f"{origin}: session.schema 不匹配，期望 {SESSION_SCHEMA}，实际 {sch!r}")

    tb = seg.get("turn_budget")
    if tb is not None and (not isinstance(tb, int) or tb < 0):
        _fail(f"{origin}: session.turn_budget 必须是非负整数")

    relax = seg.get("relax")
    if relax is not None:
        if not isinstance(relax, dict):
            _fail(f"{origin}: session.relax 必须是映射")
        cap = relax.get("max_relaxations")
        if cap is not None and (not isinstance(cap, int) or cap < 0):
            _fail(f"{origin}: session.relax.max_relaxations 必须是非负整数")
        rne = relax.get("require_new_evidence")
        if rne is not None and not isinstance(rne, bool):
            _fail(f"{origin}: session.relax.require_new_evidence 必须是布尔值")

    rules = seg.get("rules")
    if rules is not None:
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            _fail(f"{origin}: session.rules 必须是字符串列表")
        unknown = [r for r in rules if r not in SESSION_RULES]
        if unknown:
            _fail(f"{origin}: session.rules 含未知不变量 {unknown}，可用 {list(SESSION_RULES)}")

    claims = seg.get("claims")
    if claims is not None:
        if not isinstance(claims, list):
            _fail(f"{origin}: session.claims 必须是列表")
        seen: set[str] = set()
        for i, c in enumerate(claims):
            if not isinstance(c, dict):
                _fail(f"{origin}: session.claims[{i}] 必须是映射")
            cid = c.get("id")
            if not cid or not isinstance(cid, str):
                _fail(f"{origin}: session.claims[{i}] 缺少 id")
            if cid in seen:
                _fail(f"{origin}: session.claims id 重复：{cid}")
            seen.add(cid)
            pats = c.get("patterns")
            if not isinstance(pats, list) or not pats or not all(isinstance(x, str) for x in pats):
                _fail(f"{origin}: session.claims[{cid}].patterns 必须是非空字符串列表")
            for pat in pats:
                try:
                    re.compile(pat)
                except re.error as e:
                    _fail(f"{origin}: session.claims[{cid}] 正则非法 {pat!r}：{e}")
            kw = c.get("keywords")
            if kw is not None and (not isinstance(kw, list)
                                   or not all(isinstance(x, str) for x in kw)):
                _fail(f"{origin}: session.claims[{cid}].keywords 必须是字符串列表")
            vt = c.get("verify_tool")
            if vt is not None and not isinstance(vt, str):
                _fail(f"{origin}: session.claims[{cid}].verify_tool 必须是字符串或 null")


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
           "SESSION_SCHEMA", "SESSION_RULES", "validate", "validate_session", "load",
           "resolve_path", "list_builtin", "REQUIRE_TYPES"]
