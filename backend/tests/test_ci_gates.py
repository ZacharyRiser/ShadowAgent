"""Security gates in CI must survive refactors.

``.github/workflows/ci.yml`` is where the project's claims are actually
enforced, and a deleted step fails silently: the build stays green and nothing
says the dependency scan stopped running. These assertions are cheap and they
turn "someone removed the gate" into a red test.

Only the gates that are easy to drop by accident are pinned here -- the test
matrix, migration check and image builds are visible in every PR anyway.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def workflow() -> str:
    assert CI_WORKFLOW.exists(), "CI workflow missing"
    return CI_WORKFLOW.read_text(encoding="utf-8")


def test_dependency_audit_job_exists(workflow: str) -> None:
    assert "dependency-audit:" in workflow, (
        "依赖漏洞扫描 job 被移除了 —— 它不会让别的测试变红，所以必须显式护栏"
    )


def test_backend_dependencies_are_audited_strictly(workflow: str) -> None:
    assert "pip-audit -r requirements.txt --strict" in workflow, (
        "后端依赖审计丢失或不再 --strict —— 解析失败会静默变成绿灯"
    )


def test_frontend_dependencies_are_audited(workflow: str) -> None:
    assert "npm audit --omit=dev --audit-level=high" in workflow, (
        "前端依赖审计丢失或不再限定运行时树 —— 2026-10-08 起与后端"
        " pip-audit（只审 requirements.txt 运行时依赖）对齐；"
        "braces（GHSA-vfj7-8cjw-p6xm，仅 eslint 工具链可达）上游无修复版本，"
        "放宽回全树审计前必须先有上游修复并单独说明"
    )


def test_frontend_audit_is_blocking(workflow: str) -> None:
    """The frontend audit gates, same as the backend one.

    The tree carried real production advisories until the 2026-09-27 refresh
    cleared them (next 16.2.4 -> 16.3.6 and friends), so the step ran
    report-only with ``continue-on-error: true`` to avoid training people to
    ignore a permanently red gate. With the tree clean there is no reason for
    the exemption: if it ever comes back it should be a visible, justified
    edit -- never a silent one.
    """
    block = workflow.split("Audit frontend dependencies")[1]
    assert "continue-on-error" not in block.split("- name:")[0], (
        "前端审计又变回非阻断了 —— 依赖树自 2026-09-27 刷新后是干净的，"
        "豁免需要单独说明理由"
    )


def test_test_suite_and_frontend_build_are_still_gated(workflow: str) -> None:
    assert "python -m pytest tests -v" in workflow
    assert "npm run build" in workflow


def test_frontend_unit_tests_run_in_ci(workflow: str) -> None:
    assert "npm test" in workflow, (
        "前端单元测试步骤丢失 —— 它守的是构建/类型检查都抓不到的判定逻辑"
        "（邮箱形状、注册文案谎报），删掉等于把回归重新放回人工把关"
    )


def test_perf_gate_is_wired_as_a_manual_job(workflow: str) -> None:
    """The gate exists, and is manual on purpose.

    Its criteria are relative (no 5xx, blocked path not dramatically slower than
    the allowed path, no pool starvation), which is what makes them portable —
    but a shared CI runner is still a noisy place to judge latency ratios, and a
    gate that fails for hardware reasons teaches people to ignore it. So: wired
    in, dispatchable by hand, and *not* attached to push.
    """
    assert "tools/perf_gate.py" in workflow, "性能门禁从 CI 里消失了"
    gate_job = workflow.split("perf-gate:")[1]
    assert "github.event_name == 'workflow_dispatch'" in gate_job.split("- name:")[0], (
        "性能门禁不再是手动触发 —— 若改成每推必跑，需要一个说明「共享 runner 噪声已处理」"
        "的理由，而不是顺手删掉这个条件"
    )
