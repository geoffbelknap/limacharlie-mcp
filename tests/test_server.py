from __future__ import annotations

import anyio

from limacharlie_mcp import server


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"


def test_mcp_tools_return_ax_input_error_for_invalid_oid() -> None:
    result = server.lc_list_sensors("not-an-oid")

    assert result["ok"] is False
    assert result["operation"] == "sensor.list"
    assert result["error"]["class"] == "input"
    assert result["error"]["code"] == "invalid_input"
    assert result["error"]["same_input_retryable"] is False
    assert result["side_effects"] == []
    assert result["request_id"].startswith("req_")


def test_mcp_tools_return_ax_input_error_for_missing_time_window() -> None:
    result = server.lc_list_artifacts(OID)

    assert result["ok"] is False
    assert result["operation"] == "artifact.list"
    assert result["error"]["class"] == "input"
    assert "start and end" in result["error"]["message"]


def test_mcp_tool_schema_snapshot_for_representative_tools() -> None:
    async def collect_tools() -> dict:
        tools = await server.mcp.list_tools()
        return {tool.name: tool.model_dump() for tool in tools}

    tools = anyio.run(collect_tools)

    assert {
        "lc_auth_status",
        "lc_auth_refresh",
        "lc_list_sensor_events",
        "lc_wait_job",
        "lc_list_audit_logs",
        "lc_list_yara_rules",
        "lc_list_fp_rules",
        "lc_list_schemas",
        "lc_list_online_sensors",
        "lc_get_org_urls",
        "lc_get_runtime_metadata",
        "lc_get_quota_usage",
        "lc_list_groups",
        "lc_get_group",
        "lc_list_group_logs",
        "lc_list_pending_mutations",
        "lc_preview_add_sensor_tag",
        "lc_preview_remove_sensor_tag",
        "lc_confirm_mutation",
        "lc_cancel_mutation",
    } <= set(tools)
    event_schema = tools["lc_list_sensor_events"]["inputSchema"]
    assert set(event_schema["required"]) == {"oid", "sensor_id", "start", "end"}
    assert event_schema["properties"]["limit"]["default"] == 100
    assert event_schema["properties"]["cursor"]["default"] == "-"
    wait_schema = tools["lc_wait_job"]["inputSchema"]
    assert set(wait_schema["required"]) == {"oid", "job_id"}
    assert wait_schema["properties"]["timeout_seconds"]["default"] == 60
    assert wait_schema["properties"]["poll_interval_seconds"]["default"] == 5
    preview_tag_schema = tools["lc_preview_add_sensor_tag"]["inputSchema"]
    assert set(preview_tag_schema["required"]) == {"oid", "sensor_id", "tag"}
    assert preview_tag_schema["properties"]["ttl_seconds"]["default"] == 0
    assert preview_tag_schema["properties"]["token_ttl_seconds"]["default"] == 300
    runtime_schema = tools["lc_get_runtime_metadata"]["inputSchema"]
    assert set(runtime_schema["required"]) == {"oid"}
    assert runtime_schema["properties"]["limit"]["default"] == 100
    group_schema = tools["lc_get_group"]["inputSchema"]
    assert set(group_schema["required"]) == {"group_id"}
    confirm_schema = tools["lc_confirm_mutation"]["inputSchema"]
    assert set(confirm_schema["required"]) == {"confirmation_token"}
