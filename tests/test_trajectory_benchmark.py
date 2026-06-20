from __future__ import annotations

import json
import subprocess
import sys

from limacharlie_mcp.trajectory_benchmark import TRAJECTORIES, build_report, render_markdown


EXPECTED_TRAJECTORIES = {
    "first_auth_setup",
    "list_sensors",
    "review_org_posture",
    "tune_noisy_detection",
    "case_triage",
    "isolate_rejoin_safe_action",
    "dr_change_safe_action",
    "unsupported_firehose_request",
}


def test_benchmark_covers_planned_trajectories() -> None:
    report = build_report()

    assert {trajectory.id for trajectory in TRAJECTORIES} == EXPECTED_TRAJECTORIES
    assert {trajectory["id"] for trajectory in report["trajectories"]} == EXPECTED_TRAJECTORIES
    assert set(report["scores"]) == {"local_direct_api_mcp", "native_claude_code_plugin", "native_hosted_mcp"}


def test_local_mcp_scores_strong_on_agent_safe_differentiators() -> None:
    report = build_report()
    local_scores = report["scores"]["local_direct_api_mcp"]

    assert report["summary"]["leader"] == "local_direct_api_mcp"
    assert local_scores["review_org_posture"]["rating"] == "strong"
    assert local_scores["isolate_rejoin_safe_action"]["rating"] == "strong"
    assert local_scores["dr_change_safe_action"]["rating"] == "strong"
    assert local_scores["unsupported_firehose_request"]["rating"] == "strong"
    assert report["scores"]["native_hosted_mcp"]["unsupported_firehose_request"]["rating"] == "weak"


def test_benchmark_report_is_json_serializable_and_markdown_renderable() -> None:
    report = build_report()

    encoded = json.dumps(report, sort_keys=True)
    markdown = render_markdown(report)

    assert "local_direct_api_mcp" in encoded
    assert "# LimaCharlie MCP trajectory benchmark" in markdown
    assert "Unsupported firehose request" in markdown


def test_benchmark_cli_outputs_json_and_markdown() -> None:
    json_result = subprocess.run(
        [sys.executable, "-m", "limacharlie_mcp.trajectory_benchmark", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    markdown_result = subprocess.run(
        [sys.executable, "-m", "limacharlie_mcp.trajectory_benchmark", "--format", "markdown"],
        check=True,
        capture_output=True,
        text=True,
    )

    parsed = json.loads(json_result.stdout)
    assert parsed["ok"] is True
    assert parsed["benchmark"] == "limacharlie_native_vs_local_mcp"
    assert markdown_result.stdout.startswith("# LimaCharlie MCP trajectory benchmark")
