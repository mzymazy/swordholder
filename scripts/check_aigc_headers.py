#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""AIGC 隐式标识（文档头）一致性守卫。

用途
----
本仓库的对外 Markdown 在文件头以 YAML front matter 形式携带 AIGC 合规标识
（Label / ContentProducer / ProduceID / ReservedCode / ContentPropagator /
PropagateID / ReservedCode2）。这些字段是**不透明水印数据**，其中
ReservedCode1/2 是 base64 编码的二进制串（解码后 140 字节），不是给人读的文本，
因此**不允许**为了"版面好看"而删除、截断、折行或改用 YAML 锚点/别名简化——
删除即丢失水印，折行会破坏 base64，锚点则会让只做正则会话的解析器读不到值。

本脚本只做只读校验，用于 CI 与本地自检：
  1. 带 AIGC 头的文件数不得低于阈值（防止批量丢失头信息）；
  2. 七个字段必须齐全且非空；
  3. Label 必须为 "1"；
  4. ProduceID / PropagateID 必须匹配 `[0-9a-f]{32}_[0-9a-f]{32}`；
  5. ReservedCode1 / ReservedCode2 必须可 base64 解码，且长度等于 140 字节；
  6. ContentProducer 与 ContentPropagator 必须一致。

用法
----
    python scripts/check_aigc_headers.py            # 校验，失败返回 1
    python scripts/check_aigc_headers.py --json     # 输出 JSON 摘要

仅依赖标准库，跨平台（Windows 控制台已统一 UTF-8 输出）。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import sys

REQUIRED_FIELDS = (
    "Label",
    "ContentProducer",
    "ProduceID",
    "ReservedCode1",
    "ContentPropagator",
    "PropagateID",
    "ReservedCode2",
)
ID_PATTERN = re.compile(r"^[0-9a-f]{32}_[0-9a-f]{32}$")
RESERVED_CODE_BYTES = 140
MIN_TAGGED_FILES = 20

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def list_tracked_markdown() -> list[str]:
    """列出 git 跟踪的 Markdown（相对路径，/ 分隔）。"""
    out = subprocess.run(
        ["git", "-C", REPO_ROOT, "-c", "core.quotepath=false", "ls-files", "-z", "*.md"],
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        raise SystemExit("git ls-files 失败：\n" + out.stderr.decode("utf-8", "replace"))
    return [p for p in out.stdout.decode("utf-8").split("\0") if p.strip()]


def parse_front_matter(text: str) -> dict[str, str]:
    """解析文件头 `---` 之间的 AIGC 段；无 AIGC 段返回空 dict。"""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}
    try:
        end = lines.index("---", 1)
    except ValueError:
        return {}

    block = lines[1:end]
    if not any("AIGC:" in line for line in block):
        return {}

    fields: dict[str, str] = {}
    for line in block:
        match = re.match(r"\s*([A-Za-z0-9_]+):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        fields[key] = value
    return fields


def check_file(rel_path: str) -> list[str]:
    """校验单个文件，返回问题列表（空列表表示通过）。"""
    problems: list[str] = []
    abs_path = os.path.join(REPO_ROOT, rel_path.replace("/", os.sep))
    with open(abs_path, encoding="utf-8") as handle:
        fields = parse_front_matter(handle.read())

    if not fields:
        return problems

    for name in REQUIRED_FIELDS:
        if not fields.get(name):
            problems.append("%s: 缺少字段或值为空 -> %s" % (rel_path, name))

    if fields.get("Label") not in (None, "") and fields.get("Label") != "1":
        problems.append("%s: Label 应为 \"1\"，实际 %r" % (rel_path, fields.get("Label")))

    for name in ("ProduceID", "PropagateID"):
        value = fields.get(name) or ""
        if value and not ID_PATTERN.match(value):
            problems.append("%s: %s 格式非法 -> %r" % (rel_path, name, value))

    for name in ("ReservedCode1", "ReservedCode2"):
        value = fields.get(name) or ""
        if not value:
            continue
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            problems.append("%s: %s 不是合法 base64（是否被折行或截断）" % (rel_path, name))
            continue
        if len(raw) != RESERVED_CODE_BYTES:
            problems.append(
                "%s: %s 解码长度 %d，期望 %d" % (rel_path, name, len(raw), RESERVED_CODE_BYTES)
            )

    producer, propagator = fields.get("ContentProducer"), fields.get("ContentPropagator")
    if producer and propagator and producer != propagator:
        problems.append("%s: ContentProducer 与 ContentPropagator 不一致" % rel_path)

    return problems


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    as_json = "--json" in argv
    tagged: list[str] = []
    problems: list[str] = []

    for rel_path in list_tracked_markdown():
        abs_path = os.path.join(REPO_ROOT, rel_path.replace("/", os.sep))
        try:
            with open(abs_path, encoding="utf-8") as handle:
                head = handle.read(4096)
        except OSError as exc:  # 文件损坏/权限问题也要暴露，不静默跳过
            problems.append("%s: 读取失败 -> %s" % (rel_path, exc))
            continue
        if parse_front_matter(head):
            tagged.append(rel_path)
        problems.extend(check_file(rel_path))

    if len(tagged) < MIN_TAGGED_FILES:
        problems.append(
            "带 AIGC 头的 Markdown 仅 %d 份，低于阈值 %d（疑似批量丢失）"
            % (len(tagged), MIN_TAGGED_FILES)
        )

    summary = {"tagged_files": len(tagged), "problems": problems, "ok": not problems}
    if as_json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("AIGC 头一致性守卫：%d 份文件带头" % len(tagged))
        if problems:
            print("发现 %d 处问题：" % len(problems))
            for item in problems:
                print("  - " + item)
        else:
            print("字段齐全、base64 可解码（%d 字节）、编号格式合法 -> 通过" % RESERVED_CODE_BYTES)

    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
