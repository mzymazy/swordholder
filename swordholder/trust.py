"""信任锚与吊销策略：让密钥轮换可验证、让错签可撤回。

设计约束（比"能跑"更重要的三条）：

1. **向后兼容**：0.1–0.3 的 ``trusted_keys.json``（只有 key_id / public_key_hex）
   原样可读，缺省 ``status`` 视为 ``active``、无有效期窗口。老仓库不用改文件。
2. **按签发时刻判有效期，不按验签时刻**：密钥轮换后旧凭证必须还能验通，
   否则一次轮换就把历史证据全变成"不可信"。所以窗口拿 ``seal_header.created_at``
   去比，不拿 ``now()`` 去比。
3. **fail-closed**：锚文件缺失/损坏 → ``unknown``（不宣称可信）；
   锚被吊销 → INVALID；旧锚签发窗口之后的新凭证 → INVALID。
   签名有效 ≠ 签发方可信，这条在 0.1 就定了，这里只做加严不做放松。

判定结果用 ``(trust, reason, key_id, key_status)`` 四元组表达，verdict 由调用方映射：

    trust=trusted    → VALID
    trust=untrusted  → VALID_UNTRUSTED_KEY / E_UNTRUSTED_KEY
    trust=unknown    → VALID_UNTRUSTED_KEY / E_NO_TRUST_ANCHOR
    trust=revoked    → INVALID / E_SEAL_REVOKED | E_KEY_REVOKED
    trust=expired    → INVALID / E_KEY_EXPIRED
    trust=not_yet    → INVALID / E_KEY_NOT_YET_VALID
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any


class TrustError(RuntimeError):
    """信任锚读写或参数错误。"""


# ---------------------------------------------------------------- 时间处理

def parse_ts(value: Any) -> datetime | None:
    """宽松解析 ISO 时间，统一成 UTC aware；无法解析返回 None。"""
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- 读取

def _empty(path: str | None) -> dict:
    return {"schema": "swordholder-trust/1.0", "trust_root": None, "keys": [],
            "revoked_seals": [], "path": path, "loaded": False}


def load(path: str | None) -> dict:
    """读信任锚文件；不存在或损坏都返回 ``loaded=False``，不抛异常（fail-closed）。"""
    doc = _empty(path)
    if not path:
        return doc
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return doc

    if isinstance(raw, list):
        keys, revoked, root = raw, [], None
    elif isinstance(raw, dict):
        keys = raw.get("keys") or []
        revoked = raw.get("revoked_seals") or []
        root = raw.get("trust_root")
    else:
        return doc

    out_keys = []
    for item in keys:
        if not isinstance(item, dict):
            continue
        pub = str(item.get("public_key_hex") or item.get("public_key") or "").strip().lower()
        if not pub:
            continue
        out_keys.append({
            "key_id": item.get("key_id") or item.get("id") or pub[:16],
            "algorithm": item.get("algorithm") or "ed25519",
            "public_key_hex": pub,
            "status": (item.get("status") or "active").strip().lower(),
            "not_before": item.get("not_before"),
            "not_after": item.get("not_after"),
            "replaced_by": item.get("replaced_by"),
            "note": item.get("note"),
            "retired_at": item.get("retired_at"),
            "revoked_at": item.get("revoked_at"),
            "revoked_reason": item.get("revoked_reason"),
        })

    out_revoked = []
    for item in revoked:
        if isinstance(item, str):
            out_revoked.append({"seal_id": item, "reason": None, "revoked_at": None})
        elif isinstance(item, dict) and item.get("seal_id"):
            out_revoked.append({"seal_id": str(item["seal_id"]),
                                "reason": item.get("reason"),
                                "revoked_at": item.get("revoked_at")})

    doc.update({"schema": raw.get("schema") if isinstance(raw, dict) else None,
                "trust_root": root, "keys": out_keys,
                "revoked_seals": out_revoked, "loaded": True})
    return doc


# ---------------------------------------------------------------- 判定

def find_key(trust: dict, public_key_hex: str) -> dict | None:
    pub = (public_key_hex or "").strip().lower()
    for key in trust.get("keys") or []:
        if key.get("public_key_hex") == pub:
            return key
    return None


def is_seal_revoked(trust: dict, seal_id: str | None) -> dict | None:
    if not seal_id:
        return None
    for item in trust.get("revoked_seals") or []:
        if item.get("seal_id") == str(seal_id):
            return item
    return None


def evaluate(header: dict, keys_path: str | None) -> dict:
    """按信任锚 + 吊销策略判定一个已通过签名校验的 seal 头。

    返回 ``{'trust','reason','key_id','key_status'}``；不做 verdict 映射。
    """
    trust = load(keys_path)
    seal_id = header.get("seal_id")
    pub_hex = header.get("public_key_hex") or ""

    hit = is_seal_revoked(trust, seal_id)
    if hit:
        return {"trust": "revoked", "reason": "E_SEAL_REVOKED", "key_id": None,
                "key_status": None, "revoked_at": hit.get("revoked_at"),
                "revoked_reason": hit.get("reason")}

    if not trust["loaded"]:
        return {"trust": "unknown", "reason": "E_NO_TRUST_ANCHOR",
                "key_id": None, "key_status": None}

    key = find_key(trust, pub_hex)
    if key is None:
        return {"trust": "untrusted", "reason": "E_UNTRUSTED_KEY",
                "key_id": None, "key_status": None}

    key_id, status = key["key_id"], key["status"]

    if status == "revoked":
        return {"trust": "revoked", "reason": "E_KEY_REVOKED", "key_id": key_id,
                "key_status": status, "revoked_at": key.get("revoked_at"),
                "revoked_reason": key.get("revoked_reason")}

    created = parse_ts(header.get("created_at"))
    not_before = parse_ts(key.get("not_before"))
    not_after = parse_ts(key.get("not_after"))

    if created is None:
        # 没有签发时间就无法把它放进任何有效窗口里，只有"无窗口 active 锚"能放行
        if not_before is None and not_after is None and status != "retired":
            return {"trust": "trusted", "reason": "OK", "key_id": key_id,
                    "key_status": status}
        return {"trust": "expired", "reason": "E_SEAL_NO_TIMESTAMP",
                "key_id": key_id, "key_status": status}

    if not_before is not None and created < not_before:
        return {"trust": "not_yet", "reason": "E_KEY_NOT_YET_VALID",
                "key_id": key_id, "key_status": status}
    if not_after is not None and created > not_after:
        return {"trust": "expired", "reason": "E_KEY_EXPIRED",
                "key_id": key_id, "key_status": status}

    return {"trust": "trusted", "reason": "OK", "key_id": key_id, "key_status": status}


# ---------------------------------------------------------------- 写入

def _validate_pubkey(pub_hex: str) -> str:
    pub = (pub_hex or "").strip().lower()
    if len(pub) != 64:
        raise TrustError("ed25519 公钥必须是 64 位十六进制字符")
    try:
        bytes.fromhex(pub)
    except ValueError as e:
        raise TrustError(f"公钥不是合法十六进制：{e}") from e
    return pub


def _read_raw(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            raise TrustError(f"信任锚文件无法解析（拒绝在其上写入）：{e}") from e
        if isinstance(raw, list):
            return {"schema": "swordholder-trust/1.0", "trust_root": None,
                    "keys": raw, "revoked_seals": []}
        if not isinstance(raw, dict):
            raise TrustError("信任锚文件结构不是对象或数组")
        raw.setdefault("keys", [])
        raw.setdefault("revoked_seals", [])
        return raw
    return {"schema": "swordholder-trust/1.0", "trust_root": None,
            "keys": [], "revoked_seals": []}


def _write_raw(path: str, raw: dict) -> None:
    """原子写：先写同目录临时文件再 replace，避免半截文件把整个信任链弄坏。"""
    path = os.path.abspath(path)
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, suffix=".trust.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _entry_pub(entry: dict) -> str:
    return str(entry.get("public_key_hex") or entry.get("public_key") or "").lower()


def add_key(path: str, public_key_hex: str, key_id: str | None = None,
            not_before: str | None = None, not_after: str | None = None,
            note: str | None = None, trust_root: str | None = None) -> dict:
    """登记信任锚。同一公钥重复登记按 key_id 覆盖（幂等）。"""
    pub = _validate_pubkey(public_key_hex)
    for label, value in (("not_before", not_before), ("not_after", not_after)):
        if value and parse_ts(value) is None:
            raise TrustError(f"{label} 不是合法 ISO 时间：{value}")
    if not_before and not_after and parse_ts(not_before) > parse_ts(not_after):
        raise TrustError("not_before 晚于 not_after，窗口是空的")

    raw = _read_raw(path)
    kid = key_id or f"k-{pub[:12]}"
    entry = {"key_id": kid, "algorithm": "ed25519", "public_key_hex": pub,
             "status": "active",
             "fingerprint_sha256": __import__("hashlib").sha256(pub.encode()).hexdigest()}
    if not_before:
        entry["not_before"] = not_before
    if not_after:
        entry["not_after"] = not_after
    if note:
        entry["note"] = note

    keys = [k for k in raw["keys"] if not isinstance(k, dict) or _entry_pub(k) != pub]
    if any(isinstance(k, dict) and (k.get("key_id") or k.get("id")) == kid
           and _entry_pub(k) != pub for k in keys):
        raise TrustError(f"key_id 已被另一把公钥占用：{kid}")
    keys.append(entry)
    raw["keys"] = keys
    if trust_root:
        raw["trust_root"] = trust_root
    _write_raw(path, raw)
    return {"ok": True, "keys_path": os.path.abspath(path), "key": entry,
            "total_keys": len(keys)}


def _mutate_key(path: str, key_id: str, patch: dict) -> dict:
    raw = _read_raw(path)
    hit = None
    for item in raw["keys"]:
        if isinstance(item, dict) and (item.get("key_id") or item.get("id")) == key_id:
            hit = item
            break
    if hit is None:
        raise TrustError(f"信任锚中没有 key_id={key_id}")
    hit.update(patch)
    _write_raw(path, raw)
    return {"ok": True, "keys_path": os.path.abspath(path), "key": hit}


def retire_key(path: str, key_id: str, at: str | None = None,
               replaced_by: str | None = None) -> dict:
    """停用旧锚：保留其在 ``at`` 之前签发凭证的验证能力，之后不再接受。"""
    stamp = at or utc_now()
    if parse_ts(stamp) is None:
        raise TrustError(f"at 不是合法 ISO 时间：{at}")
    patch = {"status": "retired", "not_after": stamp, "retired_at": utc_now()}
    if replaced_by:
        patch["replaced_by"] = replaced_by
    return _mutate_key(path, key_id, patch)


def revoke_key(path: str, key_id: str, reason: str | None = None) -> dict:
    """吊销锚：该锚签发的全部凭证立即不可信（私钥泄露场景）。"""
    patch = {"status": "revoked", "revoked_at": utc_now()}
    if reason:
        patch["revoked_reason"] = reason
    return _mutate_key(path, key_id, patch)


def revoke_seal(path: str, seal_id: str, reason: str | None = None) -> dict:
    """吊销单份凭证（错签/误发/内容需作废），不动密钥。"""
    if not seal_id:
        raise TrustError("seal_id 不能为空")
    raw = _read_raw(path)
    existing = [r for r in raw["revoked_seals"]
                if (r.get("seal_id") if isinstance(r, dict) else r) == seal_id]
    if existing:
        return {"ok": True, "keys_path": os.path.abspath(path), "seal_id": seal_id,
                "already": True, "total_revoked": len(raw["revoked_seals"])}
    raw["revoked_seals"].append({"seal_id": seal_id, "reason": reason,
                                 "revoked_at": utc_now()})
    _write_raw(path, raw)
    return {"ok": True, "keys_path": os.path.abspath(path), "seal_id": seal_id,
            "already": False, "total_revoked": len(raw["revoked_seals"])}


def restore_seal(path: str, seal_id: str) -> dict:
    """撤销吊销记录（误吊销回滚）。"""
    raw = _read_raw(path)
    before = len(raw["revoked_seals"])
    raw["revoked_seals"] = [r for r in raw["revoked_seals"]
                            if (r.get("seal_id") if isinstance(r, dict) else r) != seal_id]
    removed = before - len(raw["revoked_seals"])
    if not removed:
        raise TrustError(f"吊销列表中无此 seal_id：{seal_id}")
    _write_raw(path, raw)
    return {"ok": True, "keys_path": os.path.abspath(path), "seal_id": seal_id,
            "removed": removed}


# ---------------------------------------------------------------- 概览

def summary(path: str | None) -> dict:
    """给 CLI / HTTP 用的信任链概览（不含任何私钥信息）。"""
    trust = load(path)
    keys = trust["keys"]
    by_status: dict[str, int] = {}
    for k in keys:
        by_status[k["status"]] = by_status.get(k["status"], 0) + 1
    now = datetime.now(timezone.utc)
    view = []
    for k in keys:
        nb, na = parse_ts(k.get("not_before")), parse_ts(k.get("not_after"))
        if k["status"] == "revoked":
            state = "revoked"
        elif k["status"] == "retired":
            state = "retired"
        elif nb and now < nb:
            state = "pending"
        elif na and now > na:
            state = "expired"
        else:
            state = "usable"
        view.append({"key_id": k["key_id"], "status": k["status"], "state": state,
                     "fingerprint_sha256_16": __import__("hashlib")
                     .sha256(k["public_key_hex"].encode()).hexdigest()[:16],
                     "not_before": k.get("not_before"), "not_after": k.get("not_after"),
                     "replaced_by": k.get("replaced_by")})
    return {"ok": trust["loaded"], "keys_path": os.path.abspath(path) if path else None,
            "loaded": trust["loaded"], "trust_root": trust.get("trust_root"),
            "keys": view, "counts": {"total": len(keys), "by_status": by_status},
            "revoked_seals": trust["revoked_seals"],
            "revoked_seal_count": len(trust["revoked_seals"])}


def check_rotation(path: str) -> dict:
    """轮换体检：有没有多把 active 锚并存、旧锚是否留了窗口。

    返回 ``warnings`` 列表（不是错误，是给运维看的提醒）。
    """
    trust = load(path)
    warnings: list[str] = []
    active = [k for k in trust["keys"] if k["status"] == "active"]
    retired = [k for k in trust["keys"] if k["status"] == "retired"]
    if not trust["loaded"]:
        warnings.append("信任锚文件缺失或损坏，所有凭证只能判 VALID_UNTRUSTED_KEY")
    if not active:
        warnings.append("没有 active 锚，新凭证将无法建立信任")
    if len(active) > 1:
        warnings.append(f"存在 {len(active)} 把 active 锚并存；轮换期可以接受，"
                        "确认新锚稳定后应把旧锚 retire 收敛到 1 把")
    if len(retired) > 3:
        warnings.append(f"已停用锚累积 {len(retired)} 把，建议归档到单独文件")
    for k in retired:
        if not k.get("not_after"):
            warnings.append(f"停用锚 {k['key_id']} 没有 not_after，"
                            "其签发窗口无限延伸，等于没有真正停用")
        if not k.get("replaced_by"):
            warnings.append(f"停用锚 {k['key_id']} 未记录 replaced_by，轮换链断点")
    return {"ok": True, "loaded": trust["loaded"], "active": len(active),
            "retired": len(retired),
            "revoked": len([k for k in trust["keys"] if k["status"] == "revoked"]),
            "revoked_seals": len(trust["revoked_seals"]), "warnings": warnings}
