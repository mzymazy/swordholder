"""版本号只有一个事实来源，别让人在两处手改。

0.5.0 发版时踩过：pyproject.toml 改到 0.5.0，swordholder/__init__.py 还写着 0.4.0，
`swordholder --version` 报旧的。这类漂移不会让任何功能坏掉，只会让"你跑的是哪一版"
变成说不清的事——对一份要靠证据说话的项目来说，这不能留。
"""

import os
import re

import swordholder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")


def _pyproject_version():
    with open(PYPROJECT, encoding="utf-8") as f:
        text = f.read()
    # 只看 [project] 段内的 version，避免误配 [build-system] 或 tool 段
    section = text.split("[project]", 1)[1].split("\n[", 1)[0]
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', section, re.M)
    assert m, "pyproject.toml 的 [project] 段里找不到 version"
    return m.group(1)


def test_version_matches_pyproject():
    assert swordholder.__version__ == _pyproject_version(), (
        f"swordholder.__version__={swordholder.__version__} 与 pyproject="
        f"{_pyproject_version()} 不一致"
    )


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", swordholder.__version__), swordholder.__version__


def test_cli_reports_package_version():
    """`swordholder --version` 必须报包自己的版本，而不是 argparse 的默认串。"""
    import io
    from contextlib import redirect_stdout

    from swordholder.cli import build_parser

    parser = build_parser()
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            parser.parse_args(["--version"])
    except SystemExit:
        pass
    assert swordholder.__version__ in buf.getvalue(), buf.getvalue()
