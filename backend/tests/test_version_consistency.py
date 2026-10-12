"""版本号一致性守卫。

背景：``0.3.0`` 之前版本号散落在四处且互不相同
（``backend`` 0.2.1 / ``sdk`` 0.1.0 / ``frontend`` 0.1.0），
既没有 tag 也没有 CHANGELOG，出问题无法定位"哪个版本引入的"。

这个测试把"四处同步 + CHANGELOG 有条目"固化成 CI 护栏：
任何人只改一处而忘了其余，CI 立刻变红 —— 这是当初能埋下漂移的根因。

⚠️ 这是**跨包**的一致性检查，路径依赖仓库布局；
从 ``backend/`` 作为工作目录运行（CI 与 pytest.ini 均如此）时按 ``__file__`` 定位仓库根。
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

BACKEND_MAIN = REPO_ROOT / "backend" / "main.py"
SDK_PYPROJECT = REPO_ROOT / "sdk" / "python" / "pyproject.toml"
SDK_INIT = REPO_ROOT / "sdk" / "python" / "shadowagent" / "__init__.py"
FRONTEND_PACKAGE = REPO_ROOT / "frontend" / "package.json"
FRONTEND_LOCK = REPO_ROOT / "frontend" / "package-lock.json"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def backend_version() -> str:
    """``app = FastAPI(..., version="x.y.z", ...)`` 里的版本号。"""
    match = re.search(r"FastAPI\((.*?)\)", _read(BACKEND_MAIN), re.S)
    assert match, f"未在 {BACKEND_MAIN} 找到 FastAPI(...) 构造调用"
    version_match = re.search(r'version\s*=\s*"([^"]+)"', match.group(1))
    assert version_match, f"未在 FastAPI(...) 中找到 version=..."
    return version_match.group(1)


def sdk_pyproject_version() -> str:
    return tomllib.loads(_read(SDK_PYPROJECT))["project"]["version"]


def sdk_init_version() -> str:
    match = re.search(r'__version__\s*=\s*"([^"]+)"', _read(SDK_INIT))
    assert match, f"未在 {SDK_INIT} 找到 __version__"
    return match.group(1)


def frontend_version() -> str:
    return json.loads(_read(FRONTEND_PACKAGE))["version"]


def frontend_lock_version() -> str:
    """``package-lock.json`` 顶层版本（``packages[""]`` 亦同源）。

    ⚠️ 必须与 ``package.json`` 同步：``npm ci`` 在两者失配时会拒绝安装，
    而锁文件里**同名依赖**的 ``version`` 字段不在此列（例如 ``yocto-queue`` 也是 0.1.0）。
    """
    lock = json.loads(_read(FRONTEND_LOCK))
    return lock["version"]


def _all_versions() -> dict[str, str]:
    return {
        "backend/main.py (FastAPI version=)": backend_version(),
        "sdk/python/pyproject.toml (project.version)": sdk_pyproject_version(),
        "sdk/python/shadowagent/__init__.py (__version__)": sdk_init_version(),
        "frontend/package.json (version)": frontend_version(),
        "frontend/package-lock.json (version)": frontend_lock_version(),
    }


@pytest.mark.parametrize(
    "path",
    [
        BACKEND_MAIN,
        SDK_PYPROJECT,
        SDK_INIT,
        FRONTEND_PACKAGE,
        FRONTEND_LOCK,
        CHANGELOG,
    ],
)
def test_release_artifacts_exist(path: Path) -> None:
    assert path.exists(), f"发布工件缺失：{path.relative_to(REPO_ROOT)}"


def test_lockfile_root_version_matches_package_json() -> None:
    assert frontend_lock_version() == frontend_version(), (
        "frontend/package-lock.json 顶层 version 与 package.json 不一致 —— "
        "npm ci 会因此拒绝安装（npm 不会自动回写锁文件版本）"
    )


def test_all_version_locations_agree() -> None:
    versions = _all_versions()
    distinct = set(versions.values())
    assert len(distinct) == 1, "版本号漂移（应统一为同一值）：\n" + "\n".join(
        f"  {location} = {value}" for location, value in versions.items()
    )


def test_version_looks_semver() -> None:
    version = backend_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?", version), (
        f"版本号 {version!r} 不是语义化版本（期望 x.y.z）"
    )


def test_changelog_has_entry_for_current_version() -> None:
    version = backend_version()
    changelog = _read(CHANGELOG)
    assert re.search(
        rf"^##\s*\[{re.escape(version)}\]", changelog, re.M
    ), f"CHANGELOG.md 中缺少 [ {version} ] 段 —— 发版时请先补条目再打 tag"


def test_changelog_has_unreleased_section() -> None:
    assert re.search(r"^##\s*\[Unreleased\]", _read(CHANGELOG), re.M), (
        "CHANGELOG.md 缺少 [Unreleased] 段 —— 新变更应先记录在那里"
    )
