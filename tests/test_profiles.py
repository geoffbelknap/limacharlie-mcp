from __future__ import annotations

import json
import subprocess
import sys

from limacharlie_mcp.api import LimaCharlieAPI, OPERATION_CATALOG
from limacharlie_mcp.profiles import available_profiles, tool_names_for_profile


def test_profile_catalog_filters_operations_and_reports_counts(tmp_path) -> None:
    client = LimaCharlieAPI(api_key="secret", audit_path=tmp_path / "audit.jsonl")

    full = client.tool_catalog(profile="full-dev")
    core = client.tool_catalog(profile="core")
    review = client.tool_catalog(profile="review")
    recover = client.tool_catalog(profile="recover")

    assert full["data"]["profile"] == "full-dev"
    assert core["data"]["profile"] == "core"
    assert review["data"]["profile"] == "review"
    assert recover["data"]["profile"] == "recover"
    assert review["data"]["active_profile"]["title"] == "Posture review and tuning"
    assert "org posture review" in review["data"]["active_profile"]["best_for"]
    assert review["data"]["agent_guidance"]["start_with"] == [
        "lc_review_org_posture",
        "lc_review_fleet_health",
        "lc_review_detection_noise",
    ]
    assert "apikey.ctrl" in review["data"]["permission_summary"]["recommended"]
    assert review["data"]["action_summary"] == {"read": review["meta"]["summary"]["operation_count"] - 1, "validate": 1}
    assert full["meta"]["summary"]["operation_count"] == len(OPERATION_CATALOG)
    assert core["meta"]["summary"]["operation_count"] < review["meta"]["summary"]["operation_count"] < full["meta"]["summary"]["operation_count"]
    assert recover["meta"]["summary"]["operation_count"] != review["meta"]["summary"]["operation_count"]
    assert set(full["data"]["profiles"]) == set(available_profiles())
    assert "auth.status" in core["data"]["operations"]
    assert "permission.explain" in core["data"]["operations"]
    assert "sensor.list" not in core["data"]["operations"]
    assert "sensor.list" in review["data"]["operations"]
    assert "sensor.isolate.preview" not in review["data"]["operations"]
    assert "sensor.rejoin.preview" in recover["data"]["operations"]
    assert "api_key.list" in review["data"]["operations"]
    assert "api_key.list" not in recover["data"]["operations"]
    assert "review.org_posture" in review["data"]["operations"]
    assert "review.org_posture" not in recover["data"]["operations"]
    assert review["data"]["operations"]["review.org_posture"]["action"] == "read"
    assert not any(spec["action"] == "preview" for spec in review["data"]["operations"].values())
    assert not any(spec["action"] == "execute" for spec in review["data"]["operations"].values())


def test_profile_tool_sets_are_focused_and_keep_safety_tools() -> None:
    full = tool_names_for_profile(OPERATION_CATALOG, "full-dev")
    core = tool_names_for_profile(OPERATION_CATALOG, "core")
    detect = tool_names_for_profile(OPERATION_CATALOG, "detect")
    contain = tool_names_for_profile(OPERATION_CATALOG, "contain")
    review = tool_names_for_profile(OPERATION_CATALOG, "review")
    recover = tool_names_for_profile(OPERATION_CATALOG, "recover")

    assert len(core) < len(detect) < len(full)
    assert len(contain) < len(full)
    assert len(review) < len(full)
    assert len(recover) < len(review)
    assert review != recover
    for profile in available_profiles():
        names = tool_names_for_profile(OPERATION_CATALOG, profile)
        assert "lc_tool_catalog" in names
        assert "lc_explain_permission" in names
        assert not any("firehose" in name or name.startswith("lc_stream") for name in names)
    assert "lc_confirm_action" in contain
    assert "lc_cancel_action" in contain
    assert "lc_confirm_action" not in review
    assert "lc_confirm_action" in recover
    assert "lc_preview_rejoin_sensor" in recover
    assert "lc_preview_unseal_sensor" in recover
    assert "lc_list_api_keys" in review
    assert "lc_list_api_keys" not in recover
    assert "lc_review_org_posture" in review
    assert "lc_review_detection_noise" in review
    assert "lc_review_org_posture" not in recover
    assert "lc_preview_isolate_sensor" in contain
    assert "lc_preview_isolate_sensor" not in detect


def test_configure_profile_filters_actual_mcp_tools_in_subprocess() -> None:
    code = """
import anyio, json
from limacharlie_mcp import server

server.configure_profile("core")
tools = anyio.run(server.mcp.list_tools)
print(json.dumps(sorted(tool.name for tool in tools)))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    tools = set(json.loads(result.stdout))

    assert "lc_tool_catalog" in tools
    assert "lc_auth_status" in tools
    assert "lc_explain_permission" in tools
    assert "lc_list_sensors" not in tools
    assert "lc_preview_isolate_sensor" not in tools
