"""凭证（seal）契约的机器校验：版本化 + fail-closed。

为什么要有这个模块：``verify()`` 以前只有几个手写 ``if``（缺块就报 ``E_MALFORMED_SEAL``），
"字段都在、但类型不对 / 版本不认识 / 摘要不是 64 位十六进制"这类问题没人裁决。
第三方要独立实现验签，也不能靠读我们的实现代码，得有一份可读的契约文本。

口径：
- schema 文件按版本固定，**已发布版本的文件不再修改**；新增字段走新版本号，旧凭证照旧可验。
- 不认识的 ``seal_version`` 一律拒收（``E_UNSUPPORTED_SEAL_VERSION``），不做"按最接近的
  版本猜着解析"——猜错方向就是把伪造当合法。
- 校验器本身不可用时同样拒收（``E_VALIDATOR_UNAVAILABLE``），不静默放行。
"""

from __future__ import annotations

import json
import os
from typing import Any

SCHEMA_DIR = os.path.dirname(os.path.abspath(__file__))

# 版本 -> schema 文件名。加新版本 = 加一行 + 加一个文件。
SCHEMA_FILES: dict[str, str] = {
    "1.0": "seal.schema.json",
}

SUPPORTED_VERSIONS: tuple[str, ...] = tuple(SCHEMA_FILES)
LATEST_VERSION = "1.0"

_CACHE: dict[str, dict] = {}


class SealSchemaError(ValueError):
    """凭证结构不符合契约。``reason`` 与 verify 的 reason 同名，便于直接透传。"""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def schema_path(version: str = LATEST_VERSION) -> str:
    fn = SCHEMA_FILES.get(version)
    if not fn:
        raise SealSchemaError("E_UNSUPPORTED_SEAL_VERSION",
                              f"不支持的 seal_version {version!r}，已支持：{', '.join(SUPPORTED_VERSIONS)}")
    return os.path.join(SCHEMA_DIR, fn)


def load_schema(version: str = LATEST_VERSION) -> dict:
    """读入某一版本的 schema（进程内缓存）。"""
    if version not in _CACHE:
        with open(schema_path(version), "r", encoding="utf-8") as f:
            _CACHE[version] = json.load(f)
    return _CACHE[version]


def seal_version_of(seal: Any) -> str | None:
    """取出 seal_header.seal_version；取不到返回 None。"""
    if not isinstance(seal, dict):
        return None
    header = seal.get("seal_header")
    if not isinstance(header, dict):
        return None
    v = header.get("seal_version")
    return v if isinstance(v, str) else None


def validate(seal: Any) -> dict:
    """按 seal_header.seal_version 校验整份凭证。

    返回 ``{"ok": bool, "seal_version": str|None, "reason": str, "detail": str}``；
    不抛异常，方便 verify 直接把它翻成 ``verdict=INVALID``。
    """
    version = seal_version_of(seal)
    if not version:
        return {"ok": False, "seal_version": None, "reason": "E_SCHEMA_INVALID",
                "detail": "缺少 seal_header.seal_version（无法确定按哪一版契约解析）"}
    if version not in SCHEMA_FILES:
        return {"ok": False, "seal_version": version, "reason": "E_UNSUPPORTED_SEAL_VERSION",
                "detail": f"未知版本 {version!r}；已支持：{', '.join(SUPPORTED_VERSIONS)}"}

    try:
        import jsonschema  # 局部导入：缺依赖时要能给出明确原因，而不是 ImportError 冒到调用方
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "seal_version": version, "reason": "E_VALIDATOR_UNAVAILABLE",
                "detail": f"jsonschema 不可用（{e}）"}

    try:
        jsonschema.validate(instance=seal, schema=load_schema(version))
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path) or "<root>"
        return {"ok": False, "seal_version": version, "reason": "E_SCHEMA_INVALID",
                "detail": f"{loc}: {e.message}"}
    except jsonschema.SchemaError as e:  # schema 自己写错了，属于仓库缺陷
        return {"ok": False, "seal_version": version, "reason": "E_SCHEMA_INVALID",
                "detail": f"内置 schema 非法：{e.message}"}

    return {"ok": True, "seal_version": version, "reason": "OK", "detail": ""}


def dumps(version: str = LATEST_VERSION) -> str:
    """把某版 schema 原文吐出来（CLI ``swordholder schema --which seal`` 用）。"""
    return json.dumps(load_schema(version), ensure_ascii=False, indent=2)


__all__ = ["SealSchemaError", "SCHEMA_FILES", "SUPPORTED_VERSIONS", "LATEST_VERSION",
           "schema_path", "load_schema", "seal_version_of", "validate", "dumps"]
