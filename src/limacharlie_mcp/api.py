from __future__ import annotations

import base64
import gzip
import json
import os
import re
import time
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from .local_vault import ensure_managed_vault
from .profiles import filter_operation_catalog, normalize_profile, profile_catalog
from .runtime_config import env_first, load_runtime_config


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json: Any | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        ...


@dataclass(frozen=True)
class ToolResponse:
    ok: bool
    operation: str
    data: Any
    meta: dict[str, Any]
    request_id: str
    resource: dict[str, Any] | None = None
    state: dict[str, Any] | None = None
    side_effects: list[dict[str, Any]] | None = None
    warnings: list[str] | None = None
    observed_at: str | None = None
    error: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "operation": self.operation,
            "request_id": self.request_id,
            "resource": self.resource,
            "state": self.state or {},
            "data": self.data,
            "side_effects": self.side_effects or [],
            "warnings": self.warnings or [],
            "meta": self.meta,
            "observed_at": self.observed_at,
        }
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class Token:
    value: str
    expires_at: float


@dataclass
class PendingMutation:
    token: str
    expires_at: float
    operation: str
    oid: str
    method: str
    path: str
    resource: dict[str, Any]
    base_url: str | None
    params: dict[str, Any] | None
    data: dict[str, Any] | None
    json_body: Any | None
    extra_headers: dict[str, str] | None
    expected_effect: str
    reversibility: str
    side_effects: list[dict[str, Any]]


class ValidationError(ValueError):
    """Invalid MCP tool input."""


def input_error_response(operation: str, message: str) -> dict[str, Any]:
    return ToolResponse(
        ok=False,
        operation=operation,
        request_id=f"req_{uuid.uuid4().hex}",
        resource=None,
        state={},
        data=None,
        side_effects=[],
        warnings=[],
        meta={"summary": {"shape": "empty"}, "truncated": False},
        observed_at=observed_at(),
        error={
            "code": "invalid_input",
            "class": "input",
            "message": message,
            "retryable": False,
            "same_input_retryable": False,
            "suggested_next_actions": [
                "Call lc_tool_catalog to inspect required inputs and bounds.",
                "Retry with corrected input values.",
            ],
        },
    ).as_dict()


UNSUPPORTED_CAPABILITIES: dict[str, dict[str, Any]] = {
    "telemetry.live_stream": {
        "status": "intentionally_unsupported",
        "scope": "live telemetry streaming via spout-style pull loops",
        "reason": "MCP tools must stay bounded and auditable; streaming an unbounded telemetry feed into an LLM is not a safe security workflow.",
        "alternatives": [
            "Use lc_list_sensor_events, lc_list_detections, lc_list_audit_logs, lc_execute_search_query, or lc_replay_dry_run with explicit limits and time windows.",
            "Use LimaCharlie outputs, storage, SIEM pipelines, or purpose-built stream processors for operational telemetry streams.",
        ],
    },
    "telemetry.firehose": {
        "status": "intentionally_unsupported",
        "scope": "push-mode firehose listener registration and ingestion",
        "reason": "Running an MCP server as an operational telemetry sink invites misuse and requires listener lifecycle, TLS, output registration, and cleanup outside the bounded MCP contract.",
        "alternatives": [
            "Use LimaCharlie output integrations or a dedicated firehose receiver outside the MCP.",
            "Use bounded historical search/replay tools when an agent needs specific evidence.",
        ],
    },
}


OPERATION_CATALOG: dict[str, dict[str, Any]] = {
    "tool.catalog": {
        "suite": "platform",
        "tool": "lc_tool_catalog",
        "action": "read",
        "resource_type": "tool_surface",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Describes tools, inputs, bounds, side effects, unsupported capabilities, and intended use cases.",
    },
    "auth.whoami": {
        "suite": "platform",
        "tool": "lc_auth_whoami",
        "action": "read",
        "resource_type": "identity",
        "required_inputs": [],
        "optional_inputs": ["oid", "check_perm"],
        "side_effects": "none",
        "notes": "Use with oid plus check_perm to test a permission in a concrete org context.",
    },
    "auth.status": {
        "suite": "platform",
        "tool": "lc_auth_status",
        "action": "read",
        "resource_type": "auth_session",
        "required_inputs": [],
        "optional_inputs": ["oid"],
        "side_effects": "none",
        "notes": "Shows credential mode and cached JWT freshness without exposing secrets.",
    },
    "auth.refresh": {
        "suite": "platform",
        "tool": "lc_auth_refresh",
        "action": "execute",
        "resource_type": "auth_session",
        "required_inputs": [],
        "optional_inputs": ["oid"],
        "side_effects": "local_jwt_cache_refresh",
        "notes": "Forces a new short-lived LimaCharlie JWT. Users should not paste JWTs manually.",
    },
    "org.list": {
        "suite": "administration",
        "tool": "lc_list_orgs",
        "action": "read",
        "resource_type": "organization_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Uses LimaCharlie's minimal JWT org placeholder for discovery.",
    },
    "download.sensor_targets.list": {
        "suite": "platform",
        "tool": "lc_list_sensor_download_targets",
        "action": "read",
        "resource_type": "download_target_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists supported sensor installer target URLs without downloading binaries.",
    },
    "download.adapter_targets.list": {
        "suite": "platform",
        "tool": "lc_list_adapter_download_targets",
        "action": "read",
        "resource_type": "download_target_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists supported adapter binary target URLs without downloading binaries.",
    },
    "sensor.list": {
        "suite": "investigation",
        "tool": "lc_list_sensors",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["selector", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Use before choosing a sensor for an investigation or response workflow.",
    },
    "sensor.get": {
        "suite": "investigation",
        "tool": "lc_get_sensor",
        "action": "read",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use to verify hostname, platform, IPs, and online state for one sensor.",
    },
    "sensor.isolation_status.get": {
        "suite": "response",
        "tool": "lc_get_sensor_isolation_status",
        "action": "read",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Reads the sensor should_isolate flag for endpoint-policy verification.",
    },
    "sensor.seal_status.get": {
        "suite": "response",
        "tool": "lc_get_sensor_seal_status",
        "action": "read",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Reads the sensor should_seal flag for endpoint-policy verification.",
    },
    "sensor.wait_online": {
        "suite": "investigation",
        "tool": "lc_wait_sensor_online",
        "action": "read",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["timeout_seconds", "poll_interval_seconds"],
        "bounds": {"timeout_min": 1, "timeout_max": 3600, "poll_interval_min": 1, "poll_interval_max": 60},
        "side_effects": "none",
        "notes": "Polls one sensor until the SDK-compatible online marker is observed or timeout expires.",
    },
    "sensor.task.preview": {
        "suite": "response",
        "tool": "lc_preview_sensor_task",
        "action": "preview",
        "resource_type": "sensor_task",
        "required_inputs": ["oid", "sensor_id", "tasks"],
        "optional_inputs": ["investigation_id", "token_ttl_seconds"],
        "bounds": {"tasks_max": 20, "token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews tasking one sensor. Requires lc_confirm_mutation before remote execution.",
    },
    "sensor.isolate.preview": {
        "suite": "response",
        "tool": "lc_preview_isolate_sensor",
        "action": "preview",
        "resource_type": "sensor_isolation",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews network isolation for one sensor.",
    },
    "sensor.rejoin.preview": {
        "suite": "response",
        "tool": "lc_preview_rejoin_sensor",
        "action": "preview",
        "resource_type": "sensor_isolation",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing network isolation from one sensor.",
    },
    "sensor.seal.preview": {
        "suite": "response",
        "tool": "lc_preview_seal_sensor",
        "action": "preview",
        "resource_type": "sensor_seal",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews sealing one sensor against uninstall.",
    },
    "sensor.unseal.preview": {
        "suite": "response",
        "tool": "lc_preview_unseal_sensor",
        "action": "preview",
        "resource_type": "sensor_seal",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews unsealing one sensor.",
    },
    "sensor.delete.preview": {
        "suite": "response",
        "tool": "lc_preview_delete_sensor",
        "action": "preview",
        "resource_type": "sensor",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting one sensor record.",
    },
    "sensor.online.list": {
        "suite": "investigation",
        "tool": "lc_list_online_sensors",
        "action": "read",
        "resource_type": "online_sensor_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Returns currently online sensors/counts from GET /v1/online/{oid}.",
    },
    "detection.list": {
        "suite": "investigation",
        "tool": "lc_list_detections",
        "action": "read",
        "resource_type": "detection_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["limit", "cursor", "category"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded page. Use next_cursor for additional pages.",
    },
    "detection.get": {
        "suite": "investigation",
        "tool": "lc_get_detection",
        "action": "read",
        "resource_type": "detection",
        "required_inputs": ["oid", "detect_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use after listing detections or receiving a detection ID from another system.",
    },
    "case.list": {
        "suite": "investigation",
        "tool": "lc_list_cases",
        "action": "read",
        "resource_type": "case_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [
            "status",
            "severity",
            "classification",
            "assignee",
            "search",
            "sensor_id",
            "tags",
            "sort",
            "order",
            "limit",
            "page_token",
        ],
        "bounds": {"limit_min": 1, "limit_max": 200, "order": ["asc", "desc"]},
        "side_effects": "none",
        "notes": "Lists one Cases API page with optional filters. Use page_token for pagination.",
    },
    "case.get": {
        "suite": "investigation",
        "tool": "lc_get_case",
        "action": "read",
        "resource_type": "case",
        "required_inputs": ["oid", "case_number"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Use for a specific numeric case number.",
    },
    "event.list": {
        "suite": "investigation",
        "tool": "lc_list_sensor_events",
        "action": "read",
        "resource_type": "event_collection",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": ["event_type", "limit", "cursor", "is_forward"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded page for one sensor; follow next_cursor explicitly.",
    },
    "event.overview": {
        "suite": "investigation",
        "tool": "lc_get_sensor_event_overview",
        "action": "read",
        "resource_type": "event_overview",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": [],
        "bounds": {"time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use before pulling full events to identify useful time ranges.",
    },
    "event.get": {
        "suite": "investigation",
        "tool": "lc_get_event",
        "action": "read",
        "resource_type": "event",
        "required_inputs": ["oid", "sensor_id", "atom"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one event by atom on one sensor.",
    },
    "event.children": {
        "suite": "investigation",
        "tool": "lc_list_child_events",
        "action": "read",
        "resource_type": "event_collection",
        "required_inputs": ["oid", "sensor_id", "atom"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Fetches child events for a parent event atom.",
    },
    "event.retention": {
        "suite": "investigation",
        "tool": "lc_get_event_retention",
        "action": "read",
        "resource_type": "event_retention",
        "required_inputs": ["oid", "sensor_id", "start", "end"],
        "optional_inputs": ["is_detailed"],
        "bounds": {"time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use to understand retained event volume before pulling full data.",
    },
    "ioc.search": {
        "suite": "investigation",
        "tool": "lc_search_ioc",
        "action": "read",
        "resource_type": "ioc_search",
        "required_inputs": ["oid", "obj_type", "obj_name"],
        "optional_inputs": ["info", "case_sensitive", "wildcards", "limit", "per_object"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "info": ["summary", "locations"]},
        "side_effects": "none",
        "notes": "Searches Insight object prevalence and locations for one indicator.",
    },
    "ioc.batch_search": {
        "suite": "investigation",
        "tool": "lc_batch_search_iocs",
        "action": "read",
        "resource_type": "ioc_batch_search",
        "required_inputs": ["oid", "objects"],
        "optional_inputs": ["info", "case_sensitive", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "object_types": ["domain", "ip", "file_hash", "file_path", "file_name", "user", "service_name", "package_name"]},
        "side_effects": "none",
        "notes": "Batch Insight prevalence/location lookup for bounded indicator groups.",
    },
    "ioc.object_info": {
        "suite": "investigation",
        "tool": "lc_get_object_information",
        "action": "read",
        "resource_type": "ioc_search",
        "required_inputs": ["oid", "obj_type", "obj_name"],
        "optional_inputs": ["info", "case_sensitive", "wildcards", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 1000, "info": ["summary", "locations"]},
        "side_effects": "none",
        "notes": "Alias for a single-object Insight lookup with enrichment-oriented naming.",
    },
    "insight.status": {
        "suite": "investigation",
        "tool": "lc_get_insight_status",
        "action": "read",
        "resource_type": "insight_status",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Checks whether Insight retention appears enabled for an org.",
    },
    "search.validate": {
        "suite": "investigation",
        "tool": "lc_validate_search_query",
        "action": "read",
        "resource_type": "lcql_validation",
        "required_inputs": ["oid", "query"],
        "optional_inputs": ["start", "end", "stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Validates LCQL through the org's search service. Use before estimate or execute.",
    },
    "search.estimate": {
        "suite": "investigation",
        "tool": "lc_estimate_search_query",
        "action": "read",
        "resource_type": "lcql_estimate",
        "required_inputs": ["oid", "query", "start", "end"],
        "optional_inputs": ["stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Uses LimaCharlie's search validation endpoint with an explicit time window to estimate query cost.",
    },
    "search.execute": {
        "suite": "investigation",
        "tool": "lc_execute_search_query",
        "action": "execute",
        "resource_type": "lcql_search_job",
        "required_inputs": ["oid", "query", "start", "end"],
        "optional_inputs": ["stream"],
        "bounds": {"time_format": "unix_seconds", "stream": ["event", "detect", "audit"]},
        "side_effects": "starts_server_search_query",
        "notes": "Starts a paginated LCQL search and returns a query_id. Poll explicitly for bounded results.",
    },
    "search.poll": {
        "suite": "investigation",
        "tool": "lc_poll_search_query",
        "action": "read",
        "resource_type": "lcql_search_page",
        "required_inputs": ["oid", "query_id"],
        "optional_inputs": ["token", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Polls one bounded search page and returns checkpoint state including next_token when present.",
    },
    "search.cancel": {
        "suite": "investigation",
        "tool": "lc_cancel_search_query",
        "action": "execute",
        "resource_type": "lcql_search_job",
        "required_inputs": ["oid", "query_id"],
        "optional_inputs": [],
        "side_effects": "cancels_server_search_query",
        "notes": "Cancels a server-side LCQL search job to release search resources.",
    },
    "saved_query.list": {
        "suite": "investigation",
        "tool": "lc_list_saved_queries",
        "action": "read",
        "resource_type": "saved_query_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists saved LCQL queries stored in the query hive.",
    },
    "saved_query.get": {
        "suite": "investigation",
        "tool": "lc_get_saved_query",
        "action": "read",
        "resource_type": "saved_query",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one saved LCQL query from the query hive.",
    },
    "saved_query.set.preview": {
        "suite": "investigation",
        "tool": "lc_preview_set_saved_query",
        "action": "preview",
        "resource_type": "saved_query",
        "required_inputs": ["oid", "name", "query"],
        "optional_inputs": ["start", "end", "stream", "tags", "comment", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating one saved LCQL query.",
    },
    "saved_query.delete.preview": {
        "suite": "investigation",
        "tool": "lc_preview_delete_saved_query",
        "action": "preview",
        "resource_type": "saved_query",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting one saved LCQL query.",
    },
    "saved_query.execute": {
        "suite": "investigation",
        "tool": "lc_execute_saved_query",
        "action": "execute",
        "resource_type": "lcql_search_job",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["start", "end", "stream"],
        "side_effects": "starts_server_search_query",
        "notes": "Loads a saved query and starts the existing paginated LCQL search flow.",
    },
    "replay.validate_rule": {
        "suite": "content",
        "tool": "lc_validate_replay_rule",
        "action": "read",
        "resource_type": "replay_validation",
        "required_inputs": ["oid", "rule_content"],
        "optional_inputs": ["trace", "limit_events", "limit_evals"],
        "bounds": {"limit_events_max": 1000, "limit_evals_max": 100000},
        "side_effects": "none",
        "notes": "Validates a D&R rule by dry-running a minimal event through Replay.",
    },
    "replay.scan_events": {
        "suite": "content",
        "tool": "lc_replay_scan_events",
        "action": "read",
        "resource_type": "replay_result",
        "required_inputs": ["oid", "events"],
        "optional_inputs": ["rule_name", "namespace", "rule_content", "trace", "limit_events", "limit_evals", "stream"],
        "bounds": {"events_max": 100, "limit_events_max": 1000, "limit_evals_max": 100000, "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Dry-runs a rule against explicit events through Replay without generating detections.",
    },
    "replay.run_dry": {
        "suite": "content",
        "tool": "lc_replay_dry_run",
        "action": "read",
        "resource_type": "replay_result",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["rule_name", "detect", "respond", "sensor_id", "selector", "stream", "trace", "limit_events", "limit_evals"],
        "bounds": {"time_format": "unix_seconds", "limit_events_max": 100000, "limit_evals_max": 1000000, "stream": ["event", "detect", "audit"]},
        "side_effects": "none",
        "notes": "Dry-runs a D&R rule against historical data. Non-dry-run replay remains gated behind future preview/confirm.",
    },
    "artifact.list": {
        "suite": "investigation",
        "tool": "lc_list_artifacts",
        "action": "read",
        "resource_type": "artifact_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["sensor_id", "start", "end", "cursor", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Use a time window or cursor; returns one bounded page.",
    },
    "artifact.get_url": {
        "suite": "investigation",
        "tool": "lc_get_artifact_url",
        "action": "read",
        "resource_type": "artifact",
        "required_inputs": ["oid", "artifact_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Requests original artifact data or signed export URL.",
    },
    "payload.list": {
        "suite": "content",
        "tool": "lc_list_payloads",
        "action": "read",
        "resource_type": "payload_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists payload metadata. Does not download payload bytes.",
    },
    "payload.get_url": {
        "suite": "content",
        "tool": "lc_get_payload_download_url",
        "action": "read",
        "resource_type": "payload",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Returns the API response containing a signed payload download URL when available; does not fetch binary bytes.",
    },
    "payload.upload_url.preview": {
        "suite": "content",
        "tool": "lc_preview_payload_upload_url",
        "action": "preview",
        "resource_type": "payload",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews requesting a signed payload upload URL. Does not upload binary bytes.",
    },
    "payload.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_payload",
        "action": "preview",
        "resource_type": "payload",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a payload record.",
    },
    "arl.get": {
        "suite": "investigation",
        "tool": "lc_get_arl",
        "action": "read",
        "resource_type": "authenticated_resource_locator",
        "required_inputs": ["oid", "arl_url"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Resolves a LimaCharlie authenticated resource locator in explicit org context.",
    },
    "job.list": {
        "suite": "investigation",
        "tool": "lc_list_jobs",
        "action": "read",
        "resource_type": "job_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["sensor_id", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Lists service jobs without returned job data payloads.",
    },
    "job.get": {
        "suite": "investigation",
        "tool": "lc_get_job",
        "action": "read",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one job status/result record.",
    },
    "job.wait": {
        "suite": "investigation",
        "tool": "lc_wait_job",
        "action": "read",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": ["timeout_seconds", "poll_interval_seconds"],
        "bounds": {"timeout_min": 1, "timeout_max": 600, "poll_interval_min": 1, "poll_interval_max": 30},
        "side_effects": "none",
        "notes": "Polls one job until terminal state or timeout with bounded intervals.",
    },
    "job.delete.preview": {
        "suite": "response",
        "tool": "lc_preview_delete_job",
        "action": "preview",
        "resource_type": "job",
        "required_inputs": ["oid", "job_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting one job record.",
    },
    "reliable_task.list": {
        "suite": "response",
        "tool": "lc_list_reliable_tasks",
        "action": "read",
        "resource_type": "reliable_task_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists pending reliable-tasking extension tasks for an org.",
    },
    "reliable_task.send.preview": {
        "suite": "response",
        "tool": "lc_preview_reliable_task",
        "action": "preview",
        "resource_type": "reliable_task",
        "required_inputs": ["oid", "task"],
        "optional_inputs": ["sensor_id", "selector", "context", "ttl_seconds", "token_ttl_seconds"],
        "bounds": {"ttl_min": 60, "ttl_max": 2592000, "token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews queueing a reliable task through ext-reliable-tasking.",
    },
    "reliable_task.delete.preview": {
        "suite": "response",
        "tool": "lc_preview_delete_reliable_task",
        "action": "preview",
        "resource_type": "reliable_task",
        "required_inputs": ["oid", "task_id"],
        "optional_inputs": ["sensor_id", "selector", "token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews cancelling one pending reliable task through ext-reliable-tasking.",
    },
    "audit.list": {
        "suite": "investigation",
        "tool": "lc_list_audit_logs",
        "action": "read",
        "resource_type": "audit_log_collection",
        "required_inputs": ["oid", "start", "end"],
        "optional_inputs": ["event_type", "sensor_id", "limit", "cursor"],
        "bounds": {"limit_min": 1, "limit_max": 500, "time_format": "unix_seconds"},
        "side_effects": "none",
        "notes": "Returns one bounded audit-log page for an explicit time window.",
    },
    "tag.list": {
        "suite": "investigation",
        "tool": "lc_list_tags",
        "action": "read",
        "resource_type": "tag_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists tags observed across sensors in the org.",
    },
    "sensor.tag.list": {
        "suite": "investigation",
        "tool": "lc_list_sensor_tags",
        "action": "read",
        "resource_type": "sensor_tag_collection",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists tags applied to one sensor and normalizes legacy tag response shapes.",
    },
    "tag.sensor_search": {
        "suite": "investigation",
        "tool": "lc_find_sensors_by_tag",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid", "tag"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Finds sensors matching a specific tag.",
    },
    "sensor.hostname_search": {
        "suite": "investigation",
        "tool": "lc_find_sensors_by_hostname",
        "action": "read",
        "resource_type": "sensor_collection",
        "required_inputs": ["oid", "hostname"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Finds sensors by hostname prefix.",
    },
    "schema.list": {
        "suite": "content",
        "tool": "lc_list_schemas",
        "action": "read",
        "resource_type": "schema_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["platform", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists event schemas for the org, optionally filtered by platform.",
    },
    "schema.get": {
        "suite": "content",
        "tool": "lc_get_schema",
        "action": "read",
        "resource_type": "schema",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one event schema definition.",
    },
    "ontology.get": {
        "suite": "content",
        "tool": "lc_get_ontology",
        "action": "read",
        "resource_type": "ontology",
        "required_inputs": [],
        "optional_inputs": ["oid", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Fetches LimaCharlie ontology/event definitions. Org API key mode uses oid, or LC_ORG_ID when set, as the JWT auth scope.",
    },
    "event_type.list": {
        "suite": "content",
        "tool": "lc_list_event_types",
        "action": "read",
        "resource_type": "event_type_collection",
        "required_inputs": [],
        "optional_inputs": ["oid", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists available event types. Org API key mode uses oid, or LC_ORG_ID when set, as the JWT auth scope.",
    },
    "mitre.get": {
        "suite": "content",
        "tool": "lc_get_mitre_report",
        "action": "read",
        "resource_type": "mitre_report",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches org MITRE ATT&CK coverage data.",
    },
    "org.get": {
        "suite": "administration",
        "tool": "lc_get_org_info",
        "action": "read",
        "resource_type": "organization",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Org inventory, quotas, and service metadata.",
    },
    "org.stats": {
        "suite": "administration",
        "tool": "lc_get_org_stats",
        "action": "read",
        "resource_type": "organization_stats",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Usage and quota statistics.",
    },
    "org.errors": {
        "suite": "administration",
        "tool": "lc_list_org_errors",
        "action": "read",
        "resource_type": "organization_error_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Current organization component errors.",
    },
    "org.urls": {
        "suite": "administration",
        "tool": "lc_get_org_urls",
        "action": "read",
        "resource_type": "organization_urls",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Service URLs for sensors, adapters, webhooks, replay, and other org-scoped connectivity.",
    },
    "org.runtime_metadata": {
        "suite": "administration",
        "tool": "lc_get_runtime_metadata",
        "action": "read",
        "resource_type": "runtime_metadata",
        "required_inputs": ["oid"],
        "optional_inputs": ["entity_type", "entity_name", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists runtime metadata, optionally filtered by entity type/name.",
    },
    "org.quota_usage": {
        "suite": "administration",
        "tool": "lc_get_quota_usage",
        "action": "read",
        "resource_type": "quota_usage",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Returns enforced quota usage; use with online sensor count for capacity checks.",
    },
    "org.quota.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_org_quota",
        "action": "preview",
        "resource_type": "organization_quota",
        "required_inputs": ["oid", "quota"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews setting the org sensor quota.",
    },
    "org.rename.preview": {
        "suite": "administration",
        "tool": "lc_preview_rename_org",
        "action": "preview",
        "resource_type": "organization",
        "required_inputs": ["oid", "new_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews renaming the organization.",
    },
    "group.list": {
        "suite": "administration",
        "tool": "lc_list_groups",
        "action": "read",
        "resource_type": "group_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists organization groups accessible to the authenticated identity.",
    },
    "group.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_group",
        "action": "preview",
        "resource_type": "group",
        "required_inputs": ["name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an organization group.",
    },
    "billing.status": {
        "suite": "administration",
        "tool": "lc_get_billing_status",
        "action": "read",
        "resource_type": "billing_status",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Gets current billing status for an org.",
    },
    "billing.details": {
        "suite": "administration",
        "tool": "lc_get_billing_details",
        "action": "read",
        "resource_type": "billing_details",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Gets detailed billing information for an org.",
    },
    "billing.invoice_url": {
        "suite": "administration",
        "tool": "lc_get_billing_invoice_url",
        "action": "read",
        "resource_type": "billing_invoice",
        "required_inputs": ["oid", "year", "month"],
        "optional_inputs": ["fmt"],
        "bounds": {"month_min": 1, "month_max": 12, "fmt": ["pdf", "csv"]},
        "side_effects": "none",
        "notes": "Gets an invoice URL for a specific billing month.",
    },
    "billing.plans": {
        "suite": "administration",
        "tool": "lc_list_billing_plans",
        "action": "read",
        "resource_type": "billing_plan_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists available billing plans.",
    },
    "group.get": {
        "suite": "administration",
        "tool": "lc_get_group",
        "action": "read",
        "resource_type": "group",
        "required_inputs": ["group_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one group definition, including members, owners, orgs, and permissions when available.",
    },
    "group.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_group",
        "action": "preview",
        "resource_type": "group",
        "required_inputs": ["group_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an organization group.",
    },
    "group.member.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_member",
        "action": "preview",
        "resource_type": "group_member",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding a group member.",
    },
    "group.member.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_member",
        "action": "preview",
        "resource_type": "group_member",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a group member.",
    },
    "group.owner.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_owner",
        "action": "preview",
        "resource_type": "group_owner",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding a group owner.",
    },
    "group.owner.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_owner",
        "action": "preview",
        "resource_type": "group_owner",
        "required_inputs": ["group_id", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a group owner.",
    },
    "group.permissions.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_group_permissions",
        "action": "preview",
        "resource_type": "group_permissions",
        "required_inputs": ["group_id", "permissions"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews replacing a group's permission list.",
    },
    "group.org.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_group_org",
        "action": "preview",
        "resource_type": "group_org_membership",
        "required_inputs": ["group_id", "member_oid"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews adding an org to a group.",
    },
    "group.org.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_group_org",
        "action": "preview",
        "resource_type": "group_org_membership",
        "required_inputs": ["group_id", "member_oid"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing an org from a group.",
    },
    "group.logs": {
        "suite": "administration",
        "tool": "lc_list_group_logs",
        "action": "read",
        "resource_type": "group_log_collection",
        "required_inputs": ["group_id"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists audit logs for one group.",
    },
    "user.list": {
        "suite": "administration",
        "tool": "lc_list_users",
        "action": "read",
        "resource_type": "user_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists users with access to the org.",
    },
    "user.invite.preview": {
        "suite": "administration",
        "tool": "lc_preview_invite_user",
        "action": "preview",
        "resource_type": "user",
        "required_inputs": ["oid", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews inviting a user to an org.",
    },
    "user.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_user",
        "action": "preview",
        "resource_type": "user",
        "required_inputs": ["oid", "email"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews removing a user from an org.",
    },
    "user.permission.list": {
        "suite": "administration",
        "tool": "lc_list_user_permissions",
        "action": "read",
        "resource_type": "user_permission_collection",
        "required_inputs": ["oid"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists permission mappings by user.",
    },
    "user.permission.add.preview": {
        "suite": "administration",
        "tool": "lc_preview_add_user_permission",
        "action": "preview",
        "resource_type": "user_permission",
        "required_inputs": ["oid", "email", "permission"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews granting one permission to a user.",
    },
    "user.permission.remove.preview": {
        "suite": "administration",
        "tool": "lc_preview_remove_user_permission",
        "action": "preview",
        "resource_type": "user_permission",
        "required_inputs": ["oid", "email", "permission"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews revoking one permission from a user.",
    },
    "user.role.set.preview": {
        "suite": "administration",
        "tool": "lc_preview_set_user_role",
        "action": "preview",
        "resource_type": "user_role",
        "required_inputs": ["oid", "email", "role"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews replacing a user's permissions with a predefined role.",
    },
    "api_key.list": {
        "suite": "administration",
        "tool": "lc_list_api_keys",
        "action": "read",
        "resource_type": "api_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists API key metadata. Secrets are not expected from list responses.",
    },
    "api_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_api_key",
        "action": "preview",
        "resource_type": "api_key",
        "required_inputs": ["oid", "name", "permissions"],
        "optional_inputs": ["ip_range", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an API key. Credential-shaped confirmation response fields are redacted.",
    },
    "api_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_api_key",
        "action": "preview",
        "resource_type": "api_key",
        "required_inputs": ["oid", "key_hash"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an API key by key hash.",
    },
    "installation_key.list": {
        "suite": "administration",
        "tool": "lc_list_installation_keys",
        "action": "read",
        "resource_type": "installation_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists installation key metadata.",
    },
    "installation_key.get": {
        "suite": "administration",
        "tool": "lc_get_installation_key",
        "action": "read",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "installation_key_id"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one installation key by ID.",
    },
    "installation_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_installation_key",
        "action": "preview",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "description"],
        "optional_inputs": ["tags", "use_public_ca", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an installation key.",
    },
    "installation_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_installation_key",
        "action": "preview",
        "resource_type": "installation_key",
        "required_inputs": ["oid", "installation_key_id"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an installation key.",
    },
    "ingestion_key.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_ingestion_key",
        "action": "preview",
        "resource_type": "ingestion_key",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an ingestion key.",
    },
    "ingestion_key.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_ingestion_key",
        "action": "preview",
        "resource_type": "ingestion_key",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an ingestion key.",
    },
    "output.list": {
        "suite": "administration",
        "tool": "lc_list_outputs",
        "action": "read",
        "resource_type": "output_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists output integration configuration.",
    },
    "output.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_output",
        "action": "preview",
        "resource_type": "output",
        "required_inputs": ["oid", "name", "module", "data_type"],
        "optional_inputs": ["config", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an output integration.",
    },
    "output.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_output",
        "action": "preview",
        "resource_type": "output",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an output integration.",
    },
    "extension.list_subscribed": {
        "suite": "administration",
        "tool": "lc_list_extension_subscriptions",
        "action": "read",
        "resource_type": "extension_subscription_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists extensions subscribed by the org.",
    },
    "extension.subscribe.preview": {
        "suite": "administration",
        "tool": "lc_preview_subscribe_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews subscribing an org to an extension.",
    },
    "extension.unsubscribe.preview": {
        "suite": "administration",
        "tool": "lc_preview_unsubscribe_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews unsubscribing an org from an extension.",
    },
    "extension.rekey.preview": {
        "suite": "administration",
        "tool": "lc_preview_rekey_extension",
        "action": "preview",
        "resource_type": "extension_subscription",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews rotating an extension subscription API key.",
    },
    "extension.list_available": {
        "suite": "administration",
        "tool": "lc_list_available_extensions",
        "action": "read",
        "resource_type": "extension_definition_collection",
        "required_inputs": [],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists extension definitions available globally.",
    },
    "extension.get": {
        "suite": "administration",
        "tool": "lc_get_extension",
        "action": "read",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one extension definition.",
    },
    "extension.create.preview": {
        "suite": "administration",
        "tool": "lc_preview_create_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_definition"],
        "optional_inputs": ["extension_name", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating an extension definition.",
    },
    "extension.update.preview": {
        "suite": "administration",
        "tool": "lc_preview_update_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_definition"],
        "optional_inputs": ["extension_name", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews updating an extension definition.",
    },
    "extension.delete.preview": {
        "suite": "administration",
        "tool": "lc_preview_delete_extension",
        "action": "preview",
        "resource_type": "extension_definition",
        "required_inputs": ["extension_name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an extension definition.",
    },
    "extension.schema.get": {
        "suite": "administration",
        "tool": "lc_get_extension_schema",
        "action": "read",
        "resource_type": "extension_schema",
        "required_inputs": ["oid", "extension_name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches extension schema for an org context.",
    },
    "extension.request.preview": {
        "suite": "administration",
        "tool": "lc_preview_extension_request",
        "action": "preview",
        "resource_type": "extension_request",
        "required_inputs": ["oid", "extension_name", "action"],
        "optional_inputs": ["data", "impersonate", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews a generic extension request. Side effects depend on the extension action.",
    },
    "vulnerability.cve.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cves",
        "action": "read",
        "resource_type": "vulnerability_cve_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "include_enrichment", "filter_via_state"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Paginated CVE rollup from ext-vulnerability-reporting.",
    },
    "vulnerability.cve.get": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_cve",
        "action": "read",
        "resource_type": "vulnerability_cve",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["include_enrichment"],
        "side_effects": "none",
        "notes": "Single-CVE details, optionally including KEV, EPSS, and exploit refs.",
    },
    "vulnerability.cve.hosts": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cve_hosts",
        "action": "read",
        "resource_type": "vulnerability_host_collection",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "filter_via_state", "normalized_package_name"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists endpoints affected by one CVE.",
    },
    "vulnerability.cve.packages": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_cve_packages",
        "action": "read",
        "resource_type": "vulnerability_package_collection",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "include_enrichment"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists package/version pairs affected by one CVE.",
    },
    "vulnerability.endpoint.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_endpoints",
        "action": "read",
        "resource_type": "vulnerability_endpoint_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "filter_via_state"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists endpoints with vulnerability counts.",
    },
    "vulnerability.host.packages": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_host_packages",
        "action": "read",
        "resource_type": "vulnerability_package_collection",
        "required_inputs": ["oid", "sensor_id"],
        "optional_inputs": ["cursor", "limit", "sort_by", "sort_asc", "filters", "search", "include_tags", "include_enrichment", "filter_via_state", "rollup_subpackages"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists vulnerable packages and CVEs on one sensor.",
    },
    "vulnerability.dashboard": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_dashboard",
        "action": "read",
        "resource_type": "vulnerability_dashboard",
        "required_inputs": ["oid"],
        "optional_inputs": ["sort_asc"],
        "side_effects": "none",
        "notes": "Dashboard graph data from ext-vulnerability-reporting.",
    },
    "vulnerability.resolution.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_resolutions",
        "action": "read",
        "resource_type": "vulnerability_resolution_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["scope", "resolutions", "cursor", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "scope": ["org", "host"]},
        "side_effects": "none",
        "notes": "Lists stored finding resolution overlays. Missing rows imply open findings.",
    },
    "vulnerability.snapshot.list": {
        "suite": "investigation",
        "tool": "lc_list_vulnerability_snapshots",
        "action": "read",
        "resource_type": "vulnerability_snapshot_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["days", "severities"],
        "bounds": {"days_min": 1, "days_max": 365},
        "side_effects": "none",
        "notes": "Daily open-finding counts for burndown views.",
    },
    "vulnerability.epss_history": {
        "suite": "investigation",
        "tool": "lc_get_vulnerability_epss_history",
        "action": "read",
        "resource_type": "vulnerability_epss_history",
        "required_inputs": ["oid", "cve"],
        "optional_inputs": ["days"],
        "bounds": {"days_min": 1, "days_max": 365},
        "side_effects": "none",
        "notes": "Per-day EPSS score and percentile history for one CVE.",
    },
    "artifact_rule.list": {
        "suite": "content",
        "tool": "lc_list_artifact_rules",
        "action": "read",
        "resource_type": "artifact_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists artifact collection rules.",
    },
    "artifact_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_artifact_rule",
        "action": "preview",
        "resource_type": "artifact_rule",
        "required_inputs": ["oid", "name", "platforms", "patterns"],
        "optional_inputs": ["is_delete_after", "retention_days", "tags", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating an artifact collection rule.",
    },
    "artifact_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_artifact_rule",
        "action": "preview",
        "resource_type": "artifact_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an artifact collection rule.",
    },
    "ingestion_key.list": {
        "suite": "administration",
        "tool": "lc_list_ingestion_keys",
        "action": "read",
        "resource_type": "ingestion_key_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists ingestion key metadata.",
    },
    "logging_rule.list": {
        "suite": "content",
        "tool": "lc_list_logging_rules",
        "action": "read",
        "resource_type": "logging_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists logging collection rules through the logging service.",
    },
    "logging_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_logging_rule",
        "action": "preview",
        "resource_type": "logging_rule",
        "required_inputs": ["oid", "name", "patterns"],
        "optional_inputs": ["tags", "platforms", "retention_days", "delete_after", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a logging collection rule.",
    },
    "logging_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_logging_rule",
        "action": "preview",
        "resource_type": "logging_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a logging collection rule.",
    },
    "dr_rule.list": {
        "suite": "content",
        "tool": "lc_list_dr_rules",
        "action": "read",
        "resource_type": "dr_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["namespace", "limit"],
        "bounds": {"limit_min": 1, "limit_max": 500, "namespace": ["general", "managed"]},
        "side_effects": "none",
        "notes": "Lists D&R rules from user-managed or managed-content hive namespaces.",
    },
    "dr_rule.get": {
        "suite": "content",
        "tool": "lc_get_dr_rule",
        "action": "read",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["namespace"],
        "bounds": {"namespace": ["general", "managed"]},
        "side_effects": "none",
        "notes": "Fetches one D&R hive record from user-managed or managed-content namespaces.",
    },
    "dr_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_dr_rule",
        "action": "preview",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name", "data"],
        "optional_inputs": ["namespace", "enabled", "tags", "comment", "expiry", "etag", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a D&R hive record.",
    },
    "dr_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_dr_rule",
        "action": "preview",
        "resource_type": "dr_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["namespace", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a D&R hive record.",
    },
    "fp_rule.list": {
        "suite": "content",
        "tool": "lc_list_fp_rules",
        "action": "read",
        "resource_type": "fp_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists false-positive rules from the fp hive.",
    },
    "fp_rule.get": {
        "suite": "content",
        "tool": "lc_get_fp_rule",
        "action": "read",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one false-positive hive record.",
    },
    "fp_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_fp_rule",
        "action": "preview",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name", "data"],
        "optional_inputs": ["enabled", "tags", "comment", "expiry", "etag", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a false-positive hive record.",
    },
    "fp_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_fp_rule",
        "action": "preview",
        "resource_type": "fp_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a false-positive hive record.",
    },
    "integrity_rule.list": {
        "suite": "content",
        "tool": "lc_list_integrity_rules",
        "action": "read",
        "resource_type": "integrity_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists integrity monitoring rules through the integrity service.",
    },
    "integrity_rule.get": {
        "suite": "content",
        "tool": "lc_get_integrity_rule",
        "action": "read",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one integrity rule by name from the integrity service list.",
    },
    "integrity_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_integrity_rule",
        "action": "preview",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name", "patterns"],
        "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating an integrity monitoring rule.",
    },
    "integrity_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_integrity_rule",
        "action": "preview",
        "resource_type": "integrity_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting an integrity monitoring rule.",
    },
    "usp.validate": {
        "suite": "content",
        "tool": "lc_validate_usp_mapping",
        "action": "read",
        "resource_type": "usp_validation",
        "required_inputs": ["oid", "platform"],
        "optional_inputs": ["mapping", "mappings", "text_input", "json_input", "hostname", "indexing"],
        "bounds": {"payload_max_bytes": 200000},
        "side_effects": "none",
        "notes": "Validates Universal Sensor Protocol mapping/input configuration.",
    },
    "yara_rule.list": {
        "suite": "content",
        "tool": "lc_list_yara_rules",
        "action": "read",
        "resource_type": "yara_rule_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists YARA scanning rules through the YARA service.",
    },
    "yara.scan.preview": {
        "suite": "response",
        "tool": "lc_preview_yara_scan",
        "action": "preview",
        "resource_type": "yara_scan",
        "required_inputs": ["oid", "sensor_id", "rule"],
        "optional_inputs": ["timeout_seconds", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews running an ad-hoc YARA scan on one sensor.",
    },
    "yara_rule.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_yara_rule",
        "action": "preview",
        "resource_type": "yara_rule",
        "required_inputs": ["oid", "name", "sources"],
        "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a YARA scanning rule.",
    },
    "yara_rule.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_yara_rule",
        "action": "preview",
        "resource_type": "yara_rule",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a YARA scanning rule.",
    },
    "yara_source.list": {
        "suite": "content",
        "tool": "lc_list_yara_sources",
        "action": "read",
        "resource_type": "yara_source_collection",
        "required_inputs": ["oid"],
        "optional_inputs": ["limit"],
        "bounds": {"limit_min": 1, "limit_max": 500},
        "side_effects": "none",
        "notes": "Lists YARA source names through the YARA service.",
    },
    "yara_source.get": {
        "suite": "content",
        "tool": "lc_get_yara_source",
        "action": "read",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name"],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Fetches one YARA source through the YARA service.",
    },
    "yara_source.set.preview": {
        "suite": "content",
        "tool": "lc_preview_set_yara_source",
        "action": "preview",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name", "source"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews creating or updating a YARA source.",
    },
    "yara_source.delete.preview": {
        "suite": "content",
        "tool": "lc_preview_delete_yara_source",
        "action": "preview",
        "resource_type": "yara_source",
        "required_inputs": ["oid", "name"],
        "optional_inputs": ["token_ttl_seconds"],
        "side_effects": "none_until_confirmed",
        "notes": "Previews deleting a YARA source.",
    },
    "mutation.pending.list": {
        "suite": "response",
        "tool": "lc_list_pending_mutations",
        "action": "read",
        "resource_type": "mutation_preview_collection",
        "required_inputs": [],
        "optional_inputs": [],
        "side_effects": "none",
        "notes": "Lists short-lived local mutation previews that can still be confirmed.",
    },
    "mutation.cancel": {
        "suite": "response",
        "tool": "lc_cancel_mutation",
        "action": "local_execute",
        "resource_type": "mutation_preview",
        "required_inputs": ["confirmation_token"],
        "optional_inputs": [],
        "side_effects": "local_preview_deleted",
        "notes": "Cancels one pending preview token without calling LimaCharlie.",
    },
    "mutation.confirm": {
        "suite": "response",
        "tool": "lc_confirm_mutation",
        "action": "execute",
        "resource_type": "mutation_preview",
        "required_inputs": ["confirmation_token"],
        "optional_inputs": [],
        "side_effects": "executes_exact_previewed_mutation",
        "notes": "Executes only the exact operation, target, and payload bound to a preview token.",
    },
    "sensor.tag.add.preview": {
        "suite": "response",
        "tool": "lc_preview_add_sensor_tag",
        "action": "preview",
        "resource_type": "sensor_tag",
        "required_inputs": ["oid", "sensor_id", "tag"],
        "optional_inputs": ["ttl_seconds", "token_ttl_seconds"],
        "bounds": {"ttl_min": 0, "ttl_max": 2592000, "token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews POST /v1/{sid}/tags. Requires lc_confirm_mutation before any remote write.",
    },
    "sensor.tag.remove.preview": {
        "suite": "response",
        "tool": "lc_preview_remove_sensor_tag",
        "action": "preview",
        "resource_type": "sensor_tag",
        "required_inputs": ["oid", "sensor_id", "tag"],
        "optional_inputs": ["token_ttl_seconds"],
        "bounds": {"token_ttl_min": 30, "token_ttl_max": 900},
        "side_effects": "none_until_confirmed",
        "notes": "Previews DELETE /v1/{sid}/tags. Requires lc_confirm_mutation before any remote write.",
    },
}

OPERATION_CATALOG.update(
    {
        "review.org_posture": {
            "suite": "review",
            "tool": "lc_review_org_posture",
            "action": "read",
            "resource_type": "posture_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["start", "end", "limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Aggregates bounded review findings across fleet, outputs, access, content, cases, org errors, and optional detection-noise window.",
        },
        "review.fleet_health": {
            "suite": "review",
            "tool": "lc_review_fleet_health",
            "action": "read",
            "resource_type": "fleet_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Summarizes bounded sensor and online-sensor reads for fleet posture review.",
        },
        "review.detection_noise": {
            "suite": "review",
            "tool": "lc_review_detection_noise",
            "action": "read",
            "resource_type": "detection_review",
            "required_inputs": ["oid", "start", "end"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Summarizes bounded detection volume, concentration, and case backlog indicators for a time window.",
        },
        "review.content_coverage": {
            "suite": "review",
            "tool": "lc_review_content_coverage",
            "action": "read",
            "resource_type": "content_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Summarizes D&R, false-positive, logging, integrity, YARA, and MITRE coverage evidence.",
        },
        "review.case_backlog": {
            "suite": "review",
            "tool": "lc_review_case_backlog",
            "action": "read",
            "resource_type": "case_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 200},
            "side_effects": "none",
            "notes": "Summarizes bounded case backlog, status distribution, and dashboard evidence.",
        },
        "review.output_health": {
            "suite": "review",
            "tool": "lc_review_output_health",
            "action": "read",
            "resource_type": "output_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Summarizes outputs, extension subscriptions, and feedback channels for telemetry/action delivery health.",
        },
        "review.access_hygiene": {
            "suite": "review",
            "tool": "lc_review_access_hygiene",
            "action": "read",
            "resource_type": "access_review",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Summarizes users, permissions, groups, and API-key metadata for access hygiene review.",
        },
        "case.create.preview": {
            "suite": "investigation",
            "tool": "lc_preview_create_case",
            "action": "preview",
            "resource_type": "case",
            "required_inputs": ["oid"],
            "optional_inputs": ["detection", "severity", "summary", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews ext-cases create_case request. Confirmation creates the case.",
        },
        "case.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case",
            "action": "preview",
            "resource_type": "case",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": ["status", "severity", "assignees", "classification", "summary", "conclusion", "tags", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews PATCH /cases/{case_number} against the Cases API.",
        },
        "case.note.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_note",
            "action": "preview",
            "resource_type": "case_note",
            "required_inputs": ["oid", "case_number", "content"],
            "optional_inputs": ["note_type", "is_public", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding an analyst note to a case.",
        },
        "case.note.visibility.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_note_visibility",
            "action": "preview",
            "resource_type": "case_note",
            "required_inputs": ["oid", "case_number", "event_id", "is_public"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews toggling note stakeholder visibility.",
        },
        "case.bulk_update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_bulk_update_cases",
            "action": "preview",
            "resource_type": "case_collection",
            "required_inputs": ["oid", "case_numbers"],
            "optional_inputs": ["status", "severity", "assignees", "classification", "summary", "conclusion", "tags", "token_ttl_seconds"],
            "bounds": {"case_numbers_max": 200},
            "side_effects": "none_until_confirmed",
            "notes": "Previews a Cases bulk-update request.",
        },
        "case.merge.preview": {
            "suite": "investigation",
            "tool": "lc_preview_merge_cases",
            "action": "preview",
            "resource_type": "case_merge",
            "required_inputs": ["oid", "target_case_number", "source_case_numbers"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews merging source cases into a target case.",
        },
        "case.detection.list": {
            "suite": "investigation",
            "tool": "lc_list_case_detections",
            "action": "read",
            "resource_type": "case_detection_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists detections linked to a case.",
        },
        "case.detection.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_detection",
            "action": "preview",
            "resource_type": "case_detection",
            "required_inputs": ["oid", "case_number", "detection"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews linking a full LC detection object to a case.",
        },
        "case.detection.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_detection",
            "action": "preview",
            "resource_type": "case_detection",
            "required_inputs": ["oid", "case_number", "detection_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a detection link from a case.",
        },
        "case.entity.list": {
            "suite": "investigation",
            "tool": "lc_list_case_entities",
            "action": "read",
            "resource_type": "case_entity_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists entities/IOCs attached to a case.",
        },
        "case.entity.search": {
            "suite": "investigation",
            "tool": "lc_search_case_entities",
            "action": "read",
            "resource_type": "case_entity_collection",
            "required_inputs": ["oid", "entity_type", "entity_value"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Searches case entities across an org.",
        },
        "case.entity.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_type", "entity_value"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding an IOC/entity to a case.",
        },
        "case.entity.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_id"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews updating an entity's note or verdict.",
        },
        "case.entity.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_entity",
            "action": "preview",
            "resource_type": "case_entity",
            "required_inputs": ["oid", "case_number", "entity_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing an entity from a case.",
        },
        "case.telemetry.list": {
            "suite": "investigation",
            "tool": "lc_list_case_telemetry",
            "action": "read",
            "resource_type": "case_telemetry_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists telemetry references linked to a case.",
        },
        "case.telemetry.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "event"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews linking a full LC event object to a case.",
        },
        "case.telemetry.update.preview": {
            "suite": "investigation",
            "tool": "lc_preview_update_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "telemetry_id"],
            "optional_inputs": ["note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews updating a telemetry note or verdict.",
        },
        "case.telemetry.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_telemetry",
            "action": "preview",
            "resource_type": "case_telemetry",
            "required_inputs": ["oid", "case_number", "telemetry_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a telemetry reference from a case.",
        },
        "case.artifact.list": {
            "suite": "investigation",
            "tool": "lc_list_case_artifacts",
            "action": "read",
            "resource_type": "case_artifact_collection",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists forensic artifact references attached to a case.",
        },
        "case.artifact.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_artifact",
            "action": "preview",
            "resource_type": "case_artifact",
            "required_inputs": ["oid", "case_number", "path", "source"],
            "optional_inputs": ["artifact_type", "note", "verdict", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews adding a forensic artifact reference to a case.",
        },
        "case.artifact.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_artifact",
            "action": "preview",
            "resource_type": "case_artifact",
            "required_inputs": ["oid", "case_number", "artifact_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews removing a forensic artifact from a case.",
        },
        "case.export": {
            "suite": "investigation",
            "tool": "lc_export_case",
            "action": "read",
            "resource_type": "case_export",
            "required_inputs": ["oid", "case_number"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches a case plus detections, entities, telemetry, and artifacts.",
        },
        "case.report": {
            "suite": "investigation",
            "tool": "lc_get_cases_report_summary",
            "action": "read",
            "resource_type": "case_report",
            "required_inputs": ["oid", "time_from", "time_to"],
            "optional_inputs": ["group_by"],
            "side_effects": "none",
            "notes": "Gets SOC report summary metrics from the Cases API.",
        },
        "case.dashboard": {
            "suite": "investigation",
            "tool": "lc_get_cases_dashboard_counts",
            "action": "read",
            "resource_type": "case_dashboard",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Gets real-time case counts by status/severity and SLA breach state.",
        },
        "case.config.get": {
            "suite": "administration",
            "tool": "lc_get_cases_config",
            "action": "read",
            "resource_type": "case_config",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches Cases configuration for an org.",
        },
        "case.config.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_cases_config",
            "action": "preview",
            "resource_type": "case_config",
            "required_inputs": ["oid", "config"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing Cases configuration for an org.",
        },
        "case.assignees.list": {
            "suite": "investigation",
            "tool": "lc_list_case_assignees",
            "action": "read",
            "resource_type": "case_assignee_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists unique assignees across cases in an org.",
        },
        "case.org.list": {
            "suite": "administration",
            "tool": "lc_list_case_orgs",
            "action": "read",
            "resource_type": "case_org_collection",
            "required_inputs": [],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists orgs subscribed to ext-cases that the caller can access.",
        },
        "case.tag.set.preview": {
            "suite": "investigation",
            "tool": "lc_preview_set_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing all tags on a case.",
        },
        "case.tag.add.preview": {
            "suite": "investigation",
            "tool": "lc_preview_add_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Reads current tags, then previews the exact replacement tag list.",
        },
        "case.tag.remove.preview": {
            "suite": "investigation",
            "tool": "lc_preview_remove_case_tags",
            "action": "preview",
            "resource_type": "case_tag_collection",
            "required_inputs": ["oid", "case_number", "tags"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Reads current tags, then previews the exact replacement tag list.",
        },
    }
)

OPERATION_CATALOG.update(
    {
        "org.name.check": {
            "suite": "administration",
            "tool": "lc_check_org_name",
            "action": "read",
            "resource_type": "organization_name",
            "required_inputs": ["name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Checks whether an organization name is available.",
        },
        "org.create.preview": {
            "suite": "administration",
            "tool": "lc_preview_create_org",
            "action": "preview",
            "resource_type": "organization",
            "required_inputs": ["name"],
            "optional_inputs": ["location", "template", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating a new LimaCharlie org.",
        },
        "org.config.get": {
            "suite": "administration",
            "tool": "lc_get_org_config_value",
            "action": "read",
            "resource_type": "organization_config_value",
            "required_inputs": ["oid", "config_name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Gets one org config value by name.",
        },
        "org.config.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_org_config_value",
            "action": "preview",
            "resource_type": "organization_config_value",
            "required_inputs": ["oid", "config_name", "value"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews setting one org config value.",
        },
        "org.error.dismiss.preview": {
            "suite": "administration",
            "tool": "lc_preview_dismiss_org_error",
            "action": "preview",
            "resource_type": "organization_error",
            "required_inputs": ["oid", "component"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews dismissing one org component error.",
        },
        "org.delete.confirmation": {
            "suite": "administration",
            "tool": "lc_get_org_delete_confirmation",
            "action": "read",
            "resource_type": "organization_delete_confirmation",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Requests the LimaCharlie delete confirmation token for an org.",
        },
        "org.delete.preview": {
            "suite": "administration",
            "tool": "lc_preview_delete_org",
            "action": "preview",
            "resource_type": "organization",
            "required_inputs": ["oid", "confirmation"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an org using the confirmation returned by lc_get_org_delete_confirmation.",
        },
        "sensor.export": {
            "suite": "administration",
            "tool": "lc_export_sensors",
            "action": "read",
            "resource_type": "sensor_export",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Exports the full sensor manifest through the org export endpoint.",
        },
        "sensor.version.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_sensor_version",
            "action": "preview",
            "resource_type": "sensor_version_policy",
            "required_inputs": ["oid"],
            "optional_inputs": ["version", "is_fallback", "is_sleep", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews changing org sensor version/branch policy.",
        },
        "service.list": {
            "suite": "administration",
            "tool": "lc_list_available_services",
            "action": "read",
            "resource_type": "service_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists available services/replicants for an org.",
        },
        "service.request.preview": {
            "suite": "administration",
            "tool": "lc_preview_service_request",
            "action": "preview",
            "resource_type": "service_request",
            "required_inputs": ["oid", "service_name", "request_data"],
            "optional_inputs": ["is_async", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews a generic non-impersonated service request. JWT impersonation is intentionally not exposed.",
        },
        "spotcheck.run.preview": {
            "suite": "response",
            "tool": "lc_preview_spotcheck_run",
            "action": "preview",
            "resource_type": "spotcheck_run",
            "required_inputs": ["oid", "task"],
            "optional_inputs": ["tag", "selector", "token_ttl_seconds"],
            "bounds": {"task_max_chars": 8192, "selector_max_chars": 300, "token_ttl_min": 30, "token_ttl_max": 900},
            "side_effects": "none_until_confirmed",
            "notes": "Previews an ad-hoc fleet-wide spotcheck task through the spotcheck service.",
        },
        "config.fetch": {
            "suite": "administration",
            "tool": "lc_fetch_config",
            "action": "read",
            "resource_type": "infrastructure_config",
            "required_inputs": ["oid"],
            "optional_inputs": ["sync_outputs", "sync_integrity", "sync_artifact", "sync_exfil", "sync_resources", "sync_extensions", "sync_org_values", "sync_hives", "sync_installation_keys", "sync_yara"],
            "side_effects": "none",
            "notes": "Fetches org IaC configuration via ext-infrastructure without exposing JWTs in tool output.",
        },
        "config.push.preview": {
            "suite": "administration",
            "tool": "lc_preview_push_config",
            "action": "preview",
            "resource_type": "infrastructure_config",
            "required_inputs": ["oid", "config"],
            "optional_inputs": ["is_force", "is_dry_run", "ignore_inaccessible", "sync_outputs", "sync_integrity", "sync_artifact", "sync_exfil", "sync_resources", "sync_extensions", "sync_org_values", "sync_hives", "sync_installation_keys", "sync_yara", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews an ext-infrastructure config push request. Use is_dry_run for backend simulation.",
        },
        "exfil_rule.list": {
            "suite": "content",
            "tool": "lc_list_exfil_rules",
            "action": "read",
            "resource_type": "exfil_rule_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists exfil prevention rules through the exfil service.",
        },
        "exfil_watch.create.preview": {
            "suite": "content",
            "tool": "lc_preview_create_exfil_watch",
            "action": "preview",
            "resource_type": "exfil_watch",
            "required_inputs": ["oid", "name", "event", "value", "operator", "path"],
            "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating an exfil watch rule.",
        },
        "exfil_event.create.preview": {
            "suite": "content",
            "tool": "lc_preview_create_exfil_event",
            "action": "preview",
            "resource_type": "exfil_event_rule",
            "required_inputs": ["oid", "name", "events"],
            "optional_inputs": ["tags", "platforms", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating an exfil event rule.",
        },
        "exfil_event.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_exfil_event",
            "action": "preview",
            "resource_type": "exfil_event_rule",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an exfil event rule.",
        },
        "exfil_watch.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_exfil_watch",
            "action": "preview",
            "resource_type": "exfil_watch",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an exfil watch rule.",
        },
    }
)

OPERATION_CATALOG.update(
    {
        "feedback.channel.list": {
            "suite": "administration",
            "tool": "lc_list_feedback_channels",
            "action": "read",
            "resource_type": "feedback_channel_collection",
            "required_inputs": ["oid"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Reads ext-feedback channel configuration from the extension_config hive.",
        },
        "feedback.channel.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_feedback_channels",
            "action": "preview",
            "resource_type": "feedback_channel_collection",
            "required_inputs": ["oid", "channels"],
            "optional_inputs": ["etag", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews replacing ext-feedback channel configuration.",
        },
        "feedback.approval.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_simple_approval",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "approved_content", "denied_content", "timeout_seconds", "timeout_choice", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external approval request through ext-feedback.",
        },
        "feedback.acknowledgement.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_acknowledgement",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "acknowledged_content", "timeout_seconds", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external acknowledgement request through ext-feedback.",
        },
        "feedback.question.preview": {
            "suite": "response",
            "tool": "lc_preview_feedback_question",
            "action": "preview",
            "resource_type": "feedback_request",
            "required_inputs": ["oid", "channel", "question", "feedback_destination"],
            "optional_inputs": ["case_id", "playbook_name", "timeout_seconds", "timeout_content", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews sending an external free-form question through ext-feedback.",
        },
    }
)

OPERATION_CATALOG.update(
    {
        "hive.type.list": {
            "suite": "content",
            "tool": "lc_list_hive_types",
            "action": "read",
            "resource_type": "hive_type_collection",
            "required_inputs": [],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Lists known LimaCharlie hive names for generic hive tools.",
        },
        "hive.record.list": {
            "suite": "content",
            "tool": "lc_list_hive_records",
            "action": "read",
            "resource_type": "hive_record_collection",
            "required_inputs": ["oid", "hive_name"],
            "optional_inputs": ["partition_key", "limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists records in a hive partition. Secret-shaped fields are redacted.",
        },
        "hive.record.get": {
            "suite": "content",
            "tool": "lc_get_hive_record",
            "action": "read",
            "resource_type": "hive_record",
            "required_inputs": ["oid", "hive_name", "key"],
            "optional_inputs": ["partition_key"],
            "side_effects": "none",
            "notes": "Fetches one hive record data payload. Secret-shaped fields are redacted.",
        },
        "hive.record.metadata.get": {
            "suite": "content",
            "tool": "lc_get_hive_record_metadata",
            "action": "read",
            "resource_type": "hive_record_metadata",
            "required_inputs": ["oid", "hive_name", "key"],
            "optional_inputs": ["partition_key"],
            "side_effects": "none",
            "notes": "Fetches one hive record's metadata endpoint.",
        },
        "hive.schema.get": {
            "suite": "content",
            "tool": "lc_get_hive_schema",
            "action": "read",
            "resource_type": "hive_schema",
            "required_inputs": ["hive_name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches the JSON Schema for a typed hive when LimaCharlie exposes one.",
        },
        "hive.record.validate": {
            "suite": "content",
            "tool": "lc_validate_hive_record",
            "action": "validate",
            "resource_type": "hive_record",
            "required_inputs": ["oid", "hive_name", "key", "data"],
            "optional_inputs": ["partition_key", "arl_url", "enabled", "tags", "comment", "expiry", "etag", "ui_actions"],
            "side_effects": "none",
            "notes": "Validates a hive record payload without saving it.",
        },
        "hive.record.set.preview": {
            "suite": "content",
            "tool": "lc_preview_set_hive_record",
            "action": "preview",
            "resource_type": "hive_record",
            "required_inputs": ["oid", "hive_name", "key"],
            "optional_inputs": ["data", "partition_key", "arl_url", "enabled", "tags", "comment", "expiry", "etag", "ui_actions", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating or updating a generic hive record.",
        },
        "hive.record.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_hive_record",
            "action": "preview",
            "resource_type": "hive_record",
            "required_inputs": ["oid", "hive_name", "key"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting a generic hive record.",
        },
        "hive.record.rename.preview": {
            "suite": "content",
            "tool": "lc_preview_rename_hive_record",
            "action": "preview",
            "resource_type": "hive_record",
            "required_inputs": ["oid", "hive_name", "key", "new_name"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews renaming a hive record key while preserving the record.",
        },
        "hive.record.enabled.set.preview": {
            "suite": "content",
            "tool": "lc_preview_set_hive_record_enabled",
            "action": "preview",
            "resource_type": "hive_record_metadata",
            "required_inputs": ["oid", "hive_name", "key", "enabled"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "metadata_read_before_preview_then_none_until_confirmed",
            "notes": "Reads current metadata, then previews changing only usr_mtd.enabled with etag preservation.",
        },
        "secret.list": {
            "suite": "administration",
            "tool": "lc_list_secrets",
            "action": "read",
            "resource_type": "secret_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists secret hive records. Secret-shaped values are redacted.",
        },
        "secret.get": {
            "suite": "administration",
            "tool": "lc_get_secret",
            "action": "read",
            "resource_type": "secret",
            "required_inputs": ["oid", "name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches one secret hive record with secret-shaped values redacted.",
        },
        "secret.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_secret",
            "action": "preview",
            "resource_type": "secret",
            "required_inputs": ["oid", "name", "secret_value"],
            "optional_inputs": ["tags", "comment", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating or updating one secret hive record. Preview/audit outputs redact the secret value.",
        },
        "secret.delete.preview": {
            "suite": "administration",
            "tool": "lc_preview_delete_secret",
            "action": "preview",
            "resource_type": "secret",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting one secret hive record.",
        },
        "secret.enabled.set.preview": {
            "suite": "administration",
            "tool": "lc_preview_set_secret_enabled",
            "action": "preview",
            "resource_type": "secret",
            "required_inputs": ["oid", "name", "enabled"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "metadata_read_before_preview_then_none_until_confirmed",
            "notes": "Reads secret metadata, then previews changing only usr_mtd.enabled with etag preservation.",
        },
        "lookup.list": {
            "suite": "content",
            "tool": "lc_list_lookups",
            "action": "read",
            "resource_type": "lookup_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists lookup hive records used by D&R enrichment.",
        },
        "lookup.get": {
            "suite": "content",
            "tool": "lc_get_lookup",
            "action": "read",
            "resource_type": "lookup",
            "required_inputs": ["oid", "name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches one lookup hive record.",
        },
        "lookup.set.preview": {
            "suite": "content",
            "tool": "lc_preview_set_lookup",
            "action": "preview",
            "resource_type": "lookup",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["lookup_data", "newline_content", "yaml_content", "tags", "comment", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews creating or updating one lookup hive record using exactly one supported data format.",
        },
        "lookup.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_lookup",
            "action": "preview",
            "resource_type": "lookup",
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting one lookup hive record.",
        },
        "lookup.enabled.set.preview": {
            "suite": "content",
            "tool": "lc_preview_set_lookup_enabled",
            "action": "preview",
            "resource_type": "lookup",
            "required_inputs": ["oid", "name", "enabled"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "metadata_read_before_preview_then_none_until_confirmed",
            "notes": "Reads lookup metadata, then previews changing only usr_mtd.enabled with etag preservation.",
        },
        "ai_memory.record.list": {
            "suite": "content",
            "tool": "lc_list_ai_memory_records",
            "action": "read",
            "resource_type": "ai_memory_record_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["partition_key", "limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists ai_memory hive records.",
        },
        "ai_memory.record.get": {
            "suite": "content",
            "tool": "lc_get_ai_memory_record",
            "action": "read",
            "resource_type": "ai_memory_record",
            "required_inputs": ["oid", "agent"],
            "optional_inputs": ["partition_key"],
            "side_effects": "none",
            "notes": "Fetches the full ai_memory record for an agent.",
        },
        "ai_memory.list": {
            "suite": "content",
            "tool": "lc_list_ai_memories",
            "action": "read",
            "resource_type": "ai_memory_collection",
            "required_inputs": ["oid", "agent"],
            "optional_inputs": ["partition_key"],
            "side_effects": "none",
            "notes": "Returns the memory-name to content map from an ai_memory record.",
        },
        "ai_memory.get": {
            "suite": "content",
            "tool": "lc_get_ai_memory",
            "action": "read",
            "resource_type": "ai_memory",
            "required_inputs": ["oid", "agent", "memory_name"],
            "optional_inputs": ["partition_key"],
            "side_effects": "none",
            "notes": "Fetches a single memory value from an ai_memory record.",
        },
        "ai_memory.set.preview": {
            "suite": "content",
            "tool": "lc_preview_set_ai_memory",
            "action": "preview",
            "resource_type": "ai_memory",
            "required_inputs": ["oid", "agent", "memory_name", "content"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews an ai_memory partial merge that sets one memory entry.",
        },
        "ai_memory.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_ai_memory",
            "action": "preview",
            "resource_type": "ai_memory",
            "required_inputs": ["oid", "agent", "memory_name"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews an ai_memory partial merge that deletes one memory entry.",
        },
        "ai_memory.record.delete.preview": {
            "suite": "content",
            "tool": "lc_preview_delete_ai_memory_record",
            "action": "preview",
            "resource_type": "ai_memory_record",
            "required_inputs": ["oid", "agent"],
            "optional_inputs": ["partition_key", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews deleting an entire ai_memory record.",
        },
        "ai.session.list": {
            "suite": "administration",
            "tool": "lc_list_ai_sessions",
            "action": "read",
            "resource_type": "ai_session_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["status", "cursor", "limit"],
            "bounds": {"limit_min": 1, "limit_max": 200},
            "side_effects": "none",
            "notes": "Lists org-scoped AI sessions for governance and cost visibility. Does not start AI work.",
        },
        "ai.session.get": {
            "suite": "administration",
            "tool": "lc_get_ai_session",
            "action": "read",
            "resource_type": "ai_session",
            "required_inputs": ["oid", "session_id"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": "Fetches one org-scoped AI session record.",
        },
        "ai.session.history": {
            "suite": "administration",
            "tool": "lc_get_ai_session_history",
            "action": "read",
            "resource_type": "ai_session_history",
            "required_inputs": ["oid", "session_id"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Fetches bounded conversation history for one org-scoped AI session.",
        },
        "ai.session.terminate.preview": {
            "suite": "administration",
            "tool": "lc_preview_terminate_ai_session",
            "action": "preview",
            "resource_type": "ai_session",
            "required_inputs": ["oid", "session_id"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": "Previews terminating a running AI session. Does not start AI work.",
        },
        "ai.usage.identity.list": {
            "suite": "administration",
            "tool": "lc_list_ai_usage_identities",
            "action": "read",
            "resource_type": "ai_usage_identity_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Lists API key identities with AI-session usage data.",
        },
        "ai.usage.get": {
            "suite": "administration",
            "tool": "lc_get_ai_usage",
            "action": "read",
            "resource_type": "ai_usage",
            "required_inputs": ["oid", "identity"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": "Fetches bounded hourly token and cost usage for one AI usage identity.",
        },
    }
)

_STRUCTURED_HIVE_SHORTCUTS: tuple[dict[str, str], ...] = (
    {
        "operation_prefix": "cloud_adapter",
        "hive_name": "cloud_sensor",
        "suite": "administration",
        "tool_singular": "cloud_adapter",
        "tool_plural": "cloud_adapters",
        "resource_type": "cloud_adapter",
        "label": "cloud adapter",
        "description": "cloud-hosted adapter configuration",
    },
    {
        "operation_prefix": "external_adapter",
        "hive_name": "external_adapter",
        "suite": "administration",
        "tool_singular": "external_adapter",
        "tool_plural": "external_adapters",
        "resource_type": "external_adapter",
        "label": "external adapter",
        "description": "self-hosted adapter configuration",
    },
    {
        "operation_prefix": "playbook",
        "hive_name": "playbook",
        "suite": "content",
        "tool_singular": "playbook",
        "tool_plural": "playbooks",
        "resource_type": "playbook",
        "label": "playbook",
        "description": "serverless automation playbook",
    },
    {
        "operation_prefix": "sop",
        "hive_name": "sop",
        "suite": "content",
        "tool_singular": "sop",
        "tool_plural": "sops",
        "resource_type": "sop",
        "label": "SOP",
        "description": "standard operating procedure",
    },
    {
        "operation_prefix": "org_note",
        "hive_name": "org_notes",
        "suite": "content",
        "tool_singular": "org_note",
        "tool_plural": "org_notes",
        "resource_type": "org_note",
        "label": "org note",
        "description": "organization note",
    },
    {
        "operation_prefix": "ai_agent",
        "hive_name": "ai_agent",
        "suite": "administration",
        "tool_singular": "ai_agent",
        "tool_plural": "ai_agents",
        "resource_type": "ai_agent",
        "label": "AI agent",
        "description": "AI agent configuration",
    },
    {
        "operation_prefix": "ai_skill",
        "hive_name": "ai_skill",
        "suite": "content",
        "tool_singular": "ai_skill",
        "tool_plural": "ai_skills",
        "resource_type": "ai_skill",
        "label": "AI skill",
        "description": "Claude Code skill definition",
    },
)


def _structured_hive_catalog_entries() -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for spec in _STRUCTURED_HIVE_SHORTCUTS:
        prefix = spec["operation_prefix"]
        resource_type = spec["resource_type"]
        suite = spec["suite"]
        label = spec["label"]
        description = spec["description"]
        entries[f"{prefix}.list"] = {
            "suite": suite,
            "tool": f"lc_list_{spec['tool_plural']}",
            "action": "read",
            "resource_type": f"{resource_type}_collection",
            "required_inputs": ["oid"],
            "optional_inputs": ["limit"],
            "bounds": {"limit_min": 1, "limit_max": 500},
            "side_effects": "none",
            "notes": f"Lists {description} records from the {spec['hive_name']} hive.",
        }
        entries[f"{prefix}.get"] = {
            "suite": suite,
            "tool": f"lc_get_{spec['tool_singular']}",
            "action": "read",
            "resource_type": resource_type,
            "required_inputs": ["oid", "name"],
            "optional_inputs": [],
            "side_effects": "none",
            "notes": f"Fetches one {label} record. Secret-shaped fields are redacted.",
        }
        entries[f"{prefix}.set.preview"] = {
            "suite": suite,
            "tool": f"lc_preview_set_{spec['tool_singular']}",
            "action": "preview",
            "resource_type": resource_type,
            "required_inputs": ["oid", "name", "data"],
            "optional_inputs": ["enabled", "tags", "comment", "expiry", "etag", "ui_actions", "token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": f"Previews creating or updating one {label} record. Preview/audit outputs redact credential-shaped fields.",
        }
        entries[f"{prefix}.delete.preview"] = {
            "suite": suite,
            "tool": f"lc_preview_delete_{spec['tool_singular']}",
            "action": "preview",
            "resource_type": resource_type,
            "required_inputs": ["oid", "name"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "none_until_confirmed",
            "notes": f"Previews deleting one {label} record.",
        }
        entries[f"{prefix}.enabled.set.preview"] = {
            "suite": suite,
            "tool": f"lc_preview_set_{spec['tool_singular']}_enabled",
            "action": "preview",
            "resource_type": resource_type,
            "required_inputs": ["oid", "name", "enabled"],
            "optional_inputs": ["token_ttl_seconds"],
            "side_effects": "metadata_read_before_preview_then_none_until_confirmed",
            "notes": f"Reads {label} metadata, then previews changing only usr_mtd.enabled with etag preservation.",
        }
    return entries


OPERATION_CATALOG.update(_structured_hive_catalog_entries())


_SAFE_DETECT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_SAFE_CASE_NUMBER = re.compile(r"^[0-9]{1,20}$")
_SAFE_PERMISSION = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@+=% -]{1,300}$")
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_.:@+=%-]{1,300}$")
_SAFE_EXTENSION_NAME = re.compile(r"^[A-Za-z0-9_.:/@+=%-]{1,300}$")
_UNSAFE_SELECTOR = re.compile(r"[\x00-\x1f;&|`$]")
_IOC_TYPES = {"domain", "ip", "file_hash", "file_path", "file_name", "user", "service_name", "package_name"}
_INFO_TYPES = {"summary", "locations"}
_DR_NAMESPACES = {"general", "managed"}
_SEARCH_STREAMS = {"event", "detect", "audit"}
_INVOICE_FORMATS = {"pdf", "csv"}
_SAFE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_VULN_SEARCH_OPS = {"is", "contains"}
_VULN_RESOLUTIONS = {"mitigated", "accepted", "false_positive"}
_VULN_SCOPES = {"org", "host"}
_VULN_SEVERITIES = {"critical", "high", "medium", "low"}
_AI_SESSION_STATUSES = {"running", "ended", "starting", "failed"}
_KNOWN_HIVE_TYPES = (
    "dr-general",
    "dr-managed",
    "fp",
    "cloud_sensor",
    "extension_config",
    "yara",
    "lookup",
    "secret",
    "query",
    "playbook",
    "ai_agent",
    "ai_skill",
    "ai_memory",
    "external_adapter",
    "sop",
    "org_notes",
)
_ORG_USER_ROLES = {"Owner", "Administrator", "Operator", "Viewer", "Basic"}
_CASE_STATUSES = {"new", "in_progress", "resolved", "closed"}
_CASE_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CASE_CLASSIFICATIONS = {"pending", "true_positive", "false_positive"}
_CASE_NOTE_TYPES = {"general", "analysis", "remediation", "escalation", "handoff", "to_stakeholder", "from_stakeholder"}
_CASE_ENTITY_TYPES = {"ip", "domain", "hash", "url", "user", "email", "file", "process", "registry", "other"}
_CASE_VERDICTS = {"malicious", "suspicious", "benign", "unknown", "informational"}
_CASE_ORDERS = {"asc", "desc"}
_EMAIL_RE = re.compile(r"^[^@\s\x00]{1,254}@[^@\s\x00]{1,253}\.[^@\s\x00]{1,63}$")
_SENSOR_DOWNLOAD_TARGETS: dict[tuple[str, str], str] = {
    ("windows", "64"): "sensor/windows/64",
    ("windows", "32"): "sensor/windows/32",
    ("windows", "arm64"): "sensor/windows/arm64",
    ("windows", "msi64"): "sensor/windows/msi64",
    ("windows", "msi32"): "sensor/windows/msi32",
    ("linux", "64"): "sensor/linux/64",
    ("linux", "deb64"): "sensor/linux/deb64",
    ("linux", "debarm64"): "sensor/linux/debarm64",
    ("linux", "alpine64"): "sensor/linux/alpine64",
    ("mac", "64"): "sensor/mac/64",
    ("mac", "arm64"): "sensor/mac/arm64",
    ("chrome", ""): "sensor/chrome",
}
_ADAPTER_DOWNLOAD_TARGETS: dict[tuple[str, str], str] = {
    ("linux", "64"): "adapter/linux/64",
    ("linux", "arm"): "adapter/linux/arm",
    ("linux", "arm64"): "adapter/linux/arm64",
    ("windows", "64"): "adapter/windows/64",
    ("mac", "64"): "adapter/mac/64",
    ("mac", "arm64"): "adapter/mac/arm64",
    ("aix", "ppc64"): "adapter/aix/ppc64",
    ("freebsd", "64"): "adapter/freebsd/64",
    ("openbsd", "64"): "adapter/openbsd/64",
    ("netbsd", "64"): "adapter/netbsd/64",
    ("solaris", "64"): "adapter/solaris/64",
}
_SUMMARY_LIST_KEYS = (
    "data",
    "items",
    "sensors",
    "detects",
    "detections",
    "cases",
    "orgs",
    "events",
    "endpoints",
    "artifacts",
    "messages",
    "history",
    "jobs",
    "packages",
    "users",
    "api_keys",
    "keys",
    "outputs",
    "resources",
    "extensions",
    "groups",
    "logs",
    "rules",
    "records",
    "resolutions",
    "results",
    "sessions",
    "snapshots",
    "tasks",
    "identities",
    "usage",
    "urls",
)
REDACTED = "[redacted]"
_SENSITIVE_RESPONSE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "access_key",
        "accesskey",
        "authorization",
        "client_secret",
        "clientsecret",
        "credential",
        "credentials",
        "installation_key",
        "installationkey",
        "jwt",
        "key",
        "key_material",
        "keymaterial",
        "lc_api_key",
        "lcapikey",
        "new_key",
        "newkey",
        "one_time_key",
        "onetimekey",
        "password",
        "private_key",
        "privatekey",
        "refresh_token",
        "refreshtoken",
        "secret",
        "secret_key",
        "secretkey",
        "session_token",
        "sessiontoken",
        "token",
    }
)
_AUDIT_ONLY_SENSITIVE_KEYS = frozenset({"confirmation", "confirmation_token", "confirmationtoken"})
_BASE64_JSON_PREVIEW_KEYS = frozenset({"request_data"})
_GZIP_BASE64_JSON_PREVIEW_KEYS = frozenset({"gzdata"})
_JSON_STRING_PREVIEW_KEYS = frozenset({"config", "data", "usr_mtd"})
_SENSITIVE_TEXT_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|client[_-]?secret|credential|jwt|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token|uid|user[_-]?id)"
    r"([\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)"
)
_AUTH_IDENTIFIER_TEXT_RES = (
    re.compile(r"(?i)(\buser\s+not\s+found\s*:\s*)([A-Za-z0-9][A-Za-z0-9_-]{7,})"),
)


def default_audit_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "limacharlie-mcp" / "audit.jsonl"
    return Path.home() / ".cache" / "limacharlie-mcp" / "audit.jsonl"


def require_oid(oid: str) -> str:
    try:
        return str(uuid.UUID(oid))
    except (TypeError, ValueError) as exc:
        raise ValidationError("oid must be a LimaCharlie organization UUID") from exc


def require_limit(limit: int, *, maximum: int = 500) -> int:
    if not isinstance(limit, int):
        raise ValidationError("limit must be an integer")
    if limit < 1 or limit > maximum:
        raise ValidationError(f"limit must be between 1 and {maximum}")
    return limit


def require_seconds(value: int, name: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}")
    return value


def require_ttl_seconds(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("ttl_seconds must be an integer")
    if value < 0 or value > 2_592_000:
        raise ValidationError("ttl_seconds must be between 0 and 2592000")
    return value


def require_unix_seconds(value: int, name: str) -> int:
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer unix timestamp in seconds")
    if value < 0 or value > 4_102_444_800:
        raise ValidationError(f"{name} is outside the accepted unix timestamp range")
    return value


def require_detect_id(detect_id: str) -> str:
    if not isinstance(detect_id, str) or not _SAFE_DETECT_ID.match(detect_id):
        raise ValidationError("detect_id contains unsupported characters")
    return detect_id


def require_case_number(case_number: str | int) -> str:
    if isinstance(case_number, bool):
        raise ValidationError("case_number must be a numeric case number")
    value = str(case_number)
    if not _SAFE_CASE_NUMBER.match(value):
        raise ValidationError("case_number must be a numeric case number")
    return value


def require_case_number_int(case_number: str | int) -> int:
    value = int(require_case_number(case_number))
    if value < 1:
        raise ValidationError("case_number must be greater than zero")
    return value


def require_case_numbers(case_numbers: list[str | int] | str, *, maximum: int = 200) -> list[int]:
    if isinstance(case_numbers, str):
        raw_values: list[str | int] = [value.strip() for value in case_numbers.split(",") if value.strip()]
    else:
        raw_values = case_numbers
    if not isinstance(raw_values, list) or not raw_values or len(raw_values) > maximum:
        raise ValidationError(f"case_numbers must contain between 1 and {maximum} case numbers")
    checked = [require_case_number_int(value) for value in raw_values]
    if len(set(checked)) != len(checked):
        raise ValidationError("case_numbers must not contain duplicates")
    return checked


def require_permission(permission: str) -> str:
    if not isinstance(permission, str) or not _SAFE_PERMISSION.match(permission):
        raise ValidationError("permission contains unsupported characters")
    return permission


def require_path_segment(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_PATH_SEGMENT.match(value):
        raise ValidationError(f"{name} contains unsupported characters")
    return value


def require_extension_name(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_EXTENSION_NAME.match(value):
        raise ValidationError("extension_name contains unsupported characters")
    return value


def require_hive_name(value: str) -> str:
    return require_path_segment(value, "hive_name")


def require_hive_partition(value: str | None, oid: str) -> str:
    if value is None:
        return oid
    return require_path_segment(value, "partition_key")


def require_hive_record_key(value: str, name: str = "key") -> str:
    return require_token(value, name)


def require_token(value: str, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_TOKEN.match(value):
        raise ValidationError(f"{name} contains unsupported characters")
    return value


def require_case_text(value: str | None, name: str, *, maximum: int = 8192, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ValidationError(f"{name} must be a string without NUL bytes")
    stripped = value.strip()
    if required and not stripped:
        raise ValidationError(f"{name} must be non-empty")
    if len(value) > maximum:
        raise ValidationError(f"{name} must be {maximum} characters or less")
    return value


def require_case_choice(value: str | None, name: str, choices: set[str]) -> str | None:
    if value is None:
        return None
    checked = str(value).lower()
    if checked not in choices:
        raise ValidationError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return checked


def require_case_choice_list(values: list[str] | str | None, name: str, choices: set[str], *, maximum: int = 20) -> list[str] | None:
    if values is None:
        return None
    raw_values = [value.strip() for value in values.split(",") if value.strip()] if isinstance(values, str) else values
    if not isinstance(raw_values, list) or not raw_values or len(raw_values) > maximum:
        raise ValidationError(f"{name} must be a non-empty list with at most {maximum} entries")
    checked = [require_case_choice(str(value), name, choices) for value in raw_values]
    return [value for value in checked if value is not None]


def require_case_tag_list(values: list[str] | str | None, name: str = "tags", *, maximum: int = 50) -> list[str] | None:
    raw_values = require_string_list(values, name, maximum=maximum)
    if raw_values is None:
        return None
    checked: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        tag = value.strip()
        if not tag:
            raise ValidationError(f"{name} entries must be non-empty")
        if len(tag) > 120:
            raise ValidationError(f"{name} entries must be 120 characters or less")
        key = tag.lower()
        if key not in seen:
            checked.append(tag)
            seen.add(key)
    return checked


def require_case_email_list(values: list[str] | str | None, name: str = "assignees", *, maximum: int = 50) -> list[str] | None:
    raw_values = require_string_list(values, name, maximum=maximum)
    if raw_values is None:
        return None
    return [require_email(value) for value in raw_values]


def require_email(value: str) -> str:
    if not isinstance(value, str) or not _EMAIL_RE.match(value):
        raise ValidationError("email must be a valid email address")
    return value


def require_org_name(value: str) -> str:
    checked = require_case_text(value, "name", maximum=120, required=True)
    assert checked is not None
    return checked


def require_config_value(value: str) -> str:
    checked = require_case_text(value, "value", maximum=20_000, required=True)
    assert checked is not None
    return checked


def require_exfil_path(path: str | list[str]) -> list[str]:
    raw_segments = path.split("/") if isinstance(path, str) else path
    if not isinstance(raw_segments, list) or not raw_segments or len(raw_segments) > 32:
        raise ValidationError("path must be a string or list with 1 to 32 segments")
    checked: list[str] = []
    for segment in raw_segments:
        if not isinstance(segment, str) or not segment or len(segment) > 120 or "\x00" in segment:
            raise ValidationError("path segments must be non-empty strings under 120 characters")
        checked.append(segment)
    return checked


def require_org_role(value: str) -> str:
    if value not in _ORG_USER_ROLES:
        raise ValidationError("role must be one of: Owner, Administrator, Operator, Viewer, Basic")
    return value


def require_quota(value: int) -> int:
    if not isinstance(value, int) or value < 0 or value > 10_000_000:
        raise ValidationError("quota must be an integer between 0 and 10000000")
    return value


def require_confirmation_token(value: str) -> str:
    if not isinstance(value, str) or not re.match(r"^mut_[a-f0-9]{32}$", value):
        raise ValidationError("confirmation_token is not a valid mutation preview token")
    return value


def require_ioc_type(obj_type: str) -> str:
    if obj_type not in _IOC_TYPES:
        raise ValidationError(f"obj_type must be one of: {', '.join(sorted(_IOC_TYPES))}")
    return obj_type


def require_info_type(info: str) -> str:
    if info not in _INFO_TYPES:
        raise ValidationError("info must be 'summary' or 'locations'")
    return info


def require_invoice_year(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("year must be an integer")
    if value < 2020 or value > 2100:
        raise ValidationError("year must be between 2020 and 2100")
    return value


def require_invoice_month(value: int) -> int:
    if not isinstance(value, int):
        raise ValidationError("month must be an integer")
    if value < 1 or value > 12:
        raise ValidationError("month must be between 1 and 12")
    return value


def require_invoice_format(value: str | None) -> str | None:
    if value is None:
        return None
    fmt = str(value).lower()
    if fmt not in _INVOICE_FORMATS:
        raise ValidationError("fmt must be pdf or csv")
    return fmt


def require_search_query(query: str) -> str:
    if not isinstance(query, str):
        raise ValidationError("query must be a string")
    stripped = query.strip()
    if not stripped:
        raise ValidationError("query must be non-empty")
    if len(stripped) > 20_000 or "\x00" in stripped:
        raise ValidationError("query must be under 20000 characters and cannot contain NUL bytes")
    return stripped


def require_search_stream(stream: str | None) -> str | None:
    if stream is None:
        return None
    value = str(stream).lower()
    if value not in _SEARCH_STREAMS:
        raise ValidationError("stream must be event, detect, or audit")
    return value


def require_json_size(value: Any, name: str, *, maximum: int = 200_000) -> Any:
    try:
        size = len(json.dumps(value).encode())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be JSON-serializable") from exc
    if size > maximum:
        raise ValidationError(f"{name} must serialize to {maximum} bytes or less")
    return value


def require_dict(value: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    return require_json_size(value, name)


def require_dict_list(value: list[dict[str, Any]] | None, name: str, *, maximum: int = 100) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError(f"{name} must be a list with at most {maximum} objects")
    if any(not isinstance(item, dict) for item in value):
        raise ValidationError(f"{name} must contain only objects")
    return require_json_size(value, name)


def require_ioc_batch(objects: dict[str, list[str]]) -> dict[str, list[str]]:
    if not isinstance(objects, dict) or not objects:
        raise ValidationError("objects must be a non-empty object of IOC type to string list")
    checked: dict[str, list[str]] = {}
    total = 0
    for key, values in objects.items():
        obj_type = require_ioc_type(str(key))
        if not isinstance(values, list) or not values:
            raise ValidationError("each objects entry must be a non-empty list")
        if len(values) > 100:
            raise ValidationError("each objects entry may contain at most 100 indicators")
        checked_values: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 500 or "\x00" in value:
                raise ValidationError("IOC values must be non-empty strings under 500 characters")
            checked_values.append(value)
        checked[obj_type] = checked_values
        total += len(checked_values)
    if total > 500:
        raise ValidationError("objects may contain at most 500 total indicators")
    return checked


def require_arl(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2000 or "\x00" in value:
        raise ValidationError("arl_url must be a non-empty string under 2000 characters")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        raise ValidationError("arl_url must include a URL scheme")
    return value


def require_sensor_tasks(tasks: str | list[str]) -> list[str]:
    raw_tasks = [tasks] if isinstance(tasks, str) else tasks
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ValidationError("tasks must be a non-empty string or list of strings")
    if len(raw_tasks) > 20:
        raise ValidationError("tasks may contain at most 20 commands")
    checked: list[str] = []
    total = 0
    for task in raw_tasks:
        if not isinstance(task, str) or not task.strip() or "\x00" in task:
            raise ValidationError("each task must be a non-empty string without NUL bytes")
        encoded_size = len(task.encode())
        if encoded_size > 4000:
            raise ValidationError("each task must be 4000 bytes or less")
        total += encoded_size
        checked.append(task)
    if total > 20_000:
        raise ValidationError("tasks must be 20000 total bytes or less")
    return checked


def require_string_list(values: list[str] | str | None, name: str, *, maximum: int = 100) -> list[str] | None:
    if values is None:
        return None
    raw_values = [values] if isinstance(values, str) else values
    if not isinstance(raw_values, list) or len(raw_values) > maximum:
        raise ValidationError(f"{name} must be a string or list of at most {maximum} strings")
    checked: list[str] = []
    for value in raw_values:
        if not isinstance(value, str) or not value or len(value) > 1000 or "\x00" in value:
            raise ValidationError(f"{name} entries must be non-empty strings under 1000 characters")
        checked.append(value)
    return checked


def require_permission_list(values: list[str] | str, name: str = "permissions", *, maximum: int = 100) -> list[str]:
    checked = require_string_list(values, name, maximum=maximum)
    if not checked:
        raise ValidationError(f"{name} must include at least one permission")
    return [require_permission(value) for value in checked]


def require_retention_days(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 1 or value > 3650:
        raise ValidationError("retention_days must be between 1 and 3650")
    return value


def require_cve(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_CVE.match(value):
        raise ValidationError("cve must look like CVE-YYYY-NNNN")
    return value.upper()


def require_days(value: int, *, maximum: int = 365) -> int:
    if not isinstance(value, int):
        raise ValidationError("days must be an integer")
    if value < 1 or value > maximum:
        raise ValidationError(f"days must be between 1 and {maximum}")
    return value


def require_bool_or_none(value: bool | None, name: str) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ValidationError(f"{name} must be a boolean")


def require_vuln_search(search: dict[str, Any] | None) -> dict[str, Any] | None:
    if search is None:
        return None
    if not isinstance(search, dict):
        raise ValidationError("search must be an object")
    field = require_token(str(search.get("field", "")), "search.field")
    op = str(search.get("op", "")).lower()
    if op not in _VULN_SEARCH_OPS:
        raise ValidationError("search.op must be is or contains")
    value = search.get("value")
    if not isinstance(value, str) or not value or len(value) > 300 or "\x00" in value:
        raise ValidationError("search.value must be a non-empty string under 300 characters")
    return {"field": field, "op": op, "value": value}


def require_vuln_filters(filters: dict[str, list[str]] | None) -> dict[str, list[str]] | None:
    if filters is None:
        return None
    if not isinstance(filters, dict):
        raise ValidationError("filters must be an object of field names to string arrays")
    checked: dict[str, list[str]] = {}
    for key, values in filters.items():
        safe_key = require_token(str(key), "filter key")
        if not isinstance(values, list) or not values:
            raise ValidationError("each filter value must be a non-empty list")
        checked[safe_key] = [require_token(str(value), f"filter {safe_key}") for value in values]
    return checked


def require_vuln_resolutions(resolutions: list[str] | None) -> list[str] | None:
    if resolutions is None:
        return None
    if not isinstance(resolutions, list) or not resolutions:
        raise ValidationError("resolutions must be a non-empty list")
    checked = [str(value).lower() for value in resolutions]
    if any(value not in _VULN_RESOLUTIONS for value in checked):
        raise ValidationError("resolutions must contain only mitigated, accepted, or false_positive")
    return checked


def require_vuln_severities(severities: list[str] | None) -> list[str] | None:
    if severities is None:
        return None
    if not isinstance(severities, list) or not severities:
        raise ValidationError("severities must be a non-empty list")
    checked = [str(value).lower() for value in severities]
    if any(value not in _VULN_SEVERITIES for value in checked):
        raise ValidationError("severities must contain only critical, high, medium, or low")
    return checked


def require_dr_namespace(namespace: str | None) -> str:
    value = namespace or "general"
    if value not in _DR_NAMESPACES:
        raise ValidationError("namespace must be general or managed")
    return value


def require_selector(selector: str | None) -> str | None:
    if selector is None:
        return None
    if not isinstance(selector, str) or not selector or len(selector) > 300 or _UNSAFE_SELECTOR.search(selector):
        raise ValidationError("selector contains unsupported characters")
    return selector


def require_time_window(start: int, end: int) -> tuple[int, int]:
    start_ts = require_unix_seconds(start, "start")
    end_ts = require_unix_seconds(end, "end")
    if end_ts <= start_ts:
        raise ValidationError("end must be greater than start")
    return start_ts, end_ts


def bool_param(value: bool) -> str:
    return "true" if value else "false"


def service_request_params(data: dict[str, Any], *, is_async: bool = False) -> dict[str, Any]:
    return {
        "request_data": base64.b64encode(json.dumps(data).encode()).decode(),
        "is_async": is_async,
    }


def extension_request_params(oid: str, action: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "oid": oid,
        "action": action,
        "gzdata": base64.b64encode(gzip.compress(json.dumps(data).encode())).decode(),
    }


def bound_output(data: Any, limit: int) -> tuple[Any, bool]:
    if isinstance(data, list):
        return data[:limit], len(data) > limit
    if isinstance(data, dict):
        bounded = dict(data)
        truncated = False
        for key in _SUMMARY_LIST_KEYS:
            value = bounded.get(key)
            if isinstance(value, list) and len(value) > limit:
                bounded[key] = value[:limit]
                truncated = True
        return bounded, truncated
    return data, False


def _sensitive_key_variants(key: str) -> tuple[str, str]:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")
    return normalized, normalized.replace("_", "")


def is_sensitive_response_key(key: str, *, extra_keys: frozenset[str] = frozenset()) -> bool:
    normalized, compact = _sensitive_key_variants(key)
    if normalized in extra_keys or compact in extra_keys:
        return True
    if normalized in _SENSITIVE_RESPONSE_KEYS or compact in _SENSITIVE_RESPONSE_KEYS:
        return True
    return normalized.endswith("_secret") or normalized.endswith("_api_key") or normalized.endswith("_private_key")


def redact_sensitive(data: Any, *, extra_keys: frozenset[str] = frozenset()) -> Any:
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_response_key(str(key), extra_keys=extra_keys) and value is not None:
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_sensitive(value, extra_keys=extra_keys)
        return redacted
    if isinstance(data, list):
        return [redact_sensitive(item, extra_keys=extra_keys) for item in data]
    return data


def redact_text(text: str) -> str:
    redacted = _SENSITIVE_TEXT_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)
    for pattern in _AUTH_IDENTIFIER_TEXT_RES:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    return redacted


def redacted_response_excerpt(data: Any, raw_text: str) -> str:
    redacted = redact_sensitive(data, extra_keys=_AUDIT_ONLY_SENSITIVE_KEYS)
    if redacted is not None and not isinstance(redacted, str):
        try:
            return redact_text(json.dumps(redacted, sort_keys=True, default=str))[:500]
        except (TypeError, ValueError):
            pass
    return redact_text(raw_text or str(redacted or ""))[:500]


def _preview_key_kind(key: str) -> str:
    normalized, compact = _sensitive_key_variants(key)
    if normalized in _BASE64_JSON_PREVIEW_KEYS or compact in _BASE64_JSON_PREVIEW_KEYS:
        return "base64_json"
    if normalized in _GZIP_BASE64_JSON_PREVIEW_KEYS or compact in _GZIP_BASE64_JSON_PREVIEW_KEYS:
        return "gzip_base64_json"
    if normalized in _JSON_STRING_PREVIEW_KEYS or compact in _JSON_STRING_PREVIEW_KEYS:
        return "json_string"
    return ""


def _redact_json_string_preview(value: str) -> Any:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return redact_text(str(value))
    return redact_sensitive(parsed)


def _redact_base64_json_preview(value: str) -> Any:
    try:
        parsed = json.loads(base64.b64decode(value).decode())
    except Exception:
        return REDACTED
    return {"encoding": "base64-json", "decoded_redacted": redact_sensitive(parsed)}


def _redact_gzip_base64_json_preview(value: str) -> Any:
    try:
        parsed = json.loads(gzip.decompress(base64.b64decode(value)).decode())
    except Exception:
        return REDACTED
    return {"encoding": "gzip+base64-json", "decoded_redacted": redact_sensitive(parsed)}


def redact_preview_data(data: Any) -> Any:
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_response_key(str(key)) and value is not None:
                redacted[key] = REDACTED
                continue
            kind = _preview_key_kind(str(key))
            if kind == "json_string" and isinstance(value, str):
                redacted[key] = _redact_json_string_preview(value)
            elif kind == "base64_json" and isinstance(value, str):
                redacted[key] = _redact_base64_json_preview(value)
            elif kind == "gzip_base64_json" and isinstance(value, str):
                redacted[key] = _redact_gzip_base64_json_preview(value)
            else:
                redacted[key] = redact_preview_data(value)
        return redacted
    if isinstance(data, list):
        return [redact_preview_data(item) for item in data]
    return data


def observed_at() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def summarize_data(data: Any) -> dict[str, Any]:
    if isinstance(data, list):
        return {"shape": "list", "count": len(data)}
    if isinstance(data, dict):
        summary: dict[str, Any] = {"shape": "object"}
        for key in _SUMMARY_LIST_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                summary[f"{key}_count"] = len(value)
            elif isinstance(value, dict):
                summary[f"{key}_count"] = len(value)
        for key in ("detect_id", "sid", "case_number", "uid", "next_cursor", "job_id", "iid"):
            if key in data:
                summary[key] = data[key]
        return summary
    if data is None:
        return {"shape": "empty"}
    return {"shape": type(data).__name__}


def normalize_api_data(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    normalized = dict(data)
    for key in ("events", "detects", "jobs"):
        value = normalized.get(key)
        if isinstance(value, str) and value:
            try:
                normalized[key] = json.loads(zlib.decompress(base64.b64decode(value), 16 + zlib.MAX_WBITS).decode())
            except Exception:
                normalized.setdefault("warnings", [])
                if isinstance(normalized["warnings"], list):
                    normalized["warnings"].append(f"{key} field could not be decompressed")
    return normalized


def normalize_job_state(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"current": "unknown", "terminal": False}
    raw_state = str(data.get("state") or data.get("status") or "").lower()
    is_done = bool(data.get("is_done") or data.get("completed") or data.get("done"))
    error = data.get("error") or data.get("last_error")
    if error or raw_state in {"failed", "failure", "error", "errored"}:
        current = "failed"
        terminal = True
    elif is_done or raw_state in {"succeeded", "success", "complete", "completed", "done"}:
        current = "succeeded"
        terminal = True
    elif raw_state in {"pending", "queued"}:
        current = "pending"
        terminal = False
    elif raw_state in {"running", "started", "in_progress"}:
        current = "running"
        terminal = False
    else:
        current = "unknown"
        terminal = False
    return {"current": current, "terminal": terminal}


def sensor_info(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    info = data.get("info")
    if isinstance(info, dict):
        return info
    return data


def sensor_online(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    online = data.get("online")
    if isinstance(online, dict):
        return bool(online) and "error" not in online
    if isinstance(online, bool):
        return online
    info = sensor_info(data)
    alive = info.get("alive")
    return bool(alive)


def classify_error(status_code: int | None, data: Any, raw_text: str) -> dict[str, Any]:
    message = redact_text(error_text(data, raw_text))
    message_lower = message.lower()
    permission_denied = (
        "missing permission" in message_lower
        or "requires " in message_lower and ("permission" in message_lower or "lc_error_code:unauthorized" in message_lower)
    )
    auth_denied = "unauthorized" in message_lower or "unknown api key" in message_lower or "user not found" in message_lower
    if permission_denied:
        error_class = "policy"
        code = "missing_permission"
        retryable = False
        next_actions = [
            "Check the required LimaCharlie permission for this operation.",
            "Use an API key with the required permission or choose a narrower tool.",
        ]
    elif status_code in (401, 403):
        error_class = "auth" if status_code == 401 else "policy"
        code = "unauthorized" if status_code == 401 else "forbidden"
        retryable = False
        next_actions = ["Verify LC_API_KEY and org scope.", "Check the required LimaCharlie permission for this operation."]
    elif status_code == 400 and auth_denied:
        error_class = "auth"
        code = "unauthorized"
        retryable = False
        next_actions = ["Verify the selected LimaCharlie API key and UID.", "Check the configured auth mode and org scope."]
    elif status_code == 404:
        error_class = "not_found"
        code = "resource_not_found"
        retryable = False
        next_actions = ["List the resource collection.", "Retry with a valid resource id in the same org."]
    elif status_code == 409:
        error_class = "conflict"
        code = "resource_conflict"
        retryable = False
        next_actions = ["Inspect current resource state.", "Retry only after resolving the conflicting state."]
    elif status_code == 429:
        error_class = "capacity"
        code = "rate_limited"
        retryable = True
        next_actions = ["Wait before retrying.", "Reduce limit or query window size."]
    elif status_code is not None and 500 <= status_code <= 599:
        error_class = "transient"
        code = "upstream_error"
        retryable = True
        next_actions = ["Retry with the same input after a short delay.", "If repeated, narrow the query or check LimaCharlie service status."]
    else:
        error_class = "internal"
        code = "request_failed"
        retryable = False
        next_actions = ["Inspect the returned message.", "Retry only after changing the input or credentials if indicated."]
    return {
        "code": code,
        "class": error_class,
        "message": message,
        "retryable": retryable,
        "same_input_retryable": retryable,
        "suggested_next_actions": next_actions,
    }


def error_text(data: Any, raw_text: str) -> str:
    if isinstance(data, dict):
        for key in ("error", "message", "error_message"):
            value = data.get(key)
            if value:
                return str(value)
    if isinstance(data, str) and data:
        return data
    return raw_text or "LimaCharlie API returned an error"


class LimaCharlieAPI:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        user_api_key: str | None = None,
        uid: str | None = None,
        auth_mode: str | None = None,
        credential_provider: str | None = None,
        api_key_ref: str | None = None,
        user_api_key_ref: str | None = None,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        vault_token_file: str | None = None,
        vault_namespace: str | None = None,
        api_root: str | None = None,
        jwt_root: str | None = None,
        cases_root: str | None = None,
        ai_root: str | None = None,
        default_oid: str | None = None,
        timeout_seconds: float | None = None,
        audit_path: Path | None = None,
        config_path: str | Path | None = None,
        http_client: HttpClient | None = None,
    ) -> None:
        config = load_runtime_config(config_path)
        managed_vault = config.get("managed_vault")
        if isinstance(managed_vault, dict) and managed_vault.get("enabled"):
            status = ensure_managed_vault(managed_vault)
            config.setdefault("vault_addr", status.addr)
            config.setdefault("vault_token_file", str(status.runtime_token_file))
        environ = os.environ
        self._explicit_api_key = api_key is not None
        self._explicit_api_key_ref = api_key_ref is not None
        self._explicit_user_api_key = user_api_key is not None
        self._explicit_user_api_key_ref = user_api_key_ref is not None
        self.api_key = env_first(config, environ, "api_key", "LC_API_KEY", explicit=api_key)
        self.user_api_key = (
            env_first(config, environ, "user_api_key", "LC_USER_API_KEY", explicit=user_api_key)
        )
        self.uid = env_first(config, environ, "uid", "LC_UID", explicit=uid)
        self.default_oid = (
            env_first(config, environ, "oid", "LC_ORG_ID", "LC_OID", explicit=default_oid)
        )
        raw_auth_mode = (
            env_first(config, environ, "auth_mode", "LC_AUTH_MODE", explicit=auth_mode) or "auto"
        ).strip().lower()
        if raw_auth_mode in {"", "auto"}:
            self.auth_mode: str | None = None
        elif raw_auth_mode in {"org", "org_api_key"}:
            self.auth_mode = "org_api_key"
        elif raw_auth_mode in {"user", "user_api_key"}:
            self.auth_mode = "user_api_key"
        else:
            raise ValidationError("auth_mode must be auto, org_api_key, or user_api_key")
        configured_provider = (
            env_first(
                config,
                environ,
                "credential_provider",
                "LC_SECRET_PROVIDER",
                "LC_CREDENTIAL_PROVIDER",
                explicit=credential_provider,
            )
        )
        self.credential_provider = (
            configured_provider or ("env" if self.api_key or self.user_api_key else "vault")
        ).strip().lower()
        if self.credential_provider not in {"env", "vault"}:
            raise ValidationError("credential_provider must be env or vault")
        self.api_key_ref = (
            env_first(
                config,
                environ,
                "api_key_ref",
                "LC_API_KEY_REF",
                "LC_API_KEY_SECRET_REF",
                explicit=api_key_ref,
            )
        )
        self.user_api_key_ref = (
            env_first(
                config,
                environ,
                "user_api_key_ref",
                "LC_USER_API_KEY_REF",
                "LC_USER_API_KEY_SECRET_REF",
                explicit=user_api_key_ref,
            )
        )
        if self.credential_provider == "vault" and not self.api_key_ref and not self.user_api_key_ref:
            self.api_key_ref = "vault://secret/data/limacharlie/mcp#api_key"
        self.vault_addr = (
            env_first(
                config,
                environ,
                "vault_addr",
                "LC_VAULT_ADDR",
                "VAULT_ADDR",
                explicit=vault_addr,
            )
            or ""
        ).rstrip("/")
        self.vault_token = (
            env_first(
                config,
                environ,
                "vault_token",
                "LC_VAULT_TOKEN",
                "VAULT_TOKEN",
                explicit=vault_token,
            )
        )
        self.vault_token_file = (
            env_first(
                config,
                environ,
                "vault_token_file",
                "LC_VAULT_TOKEN_FILE",
                "VAULT_TOKEN_FILE",
                explicit=vault_token_file,
            )
        )
        self.vault_namespace = (
            env_first(
                config,
                environ,
                "vault_namespace",
                "LC_VAULT_NAMESPACE",
                "VAULT_NAMESPACE",
                explicit=vault_namespace,
            )
        )
        self.api_root = (
            env_first(config, environ, "api_root", "LC_API_ROOT", explicit=api_root)
            or "https://api.limacharlie.io"
        ).rstrip("/")
        self.jwt_root = (
            env_first(config, environ, "jwt_root", "LC_JWT_ROOT", explicit=jwt_root)
            or "https://jwt.limacharlie.io"
        ).rstrip("/")
        self.cases_root = (
            env_first(
                config,
                environ,
                "cases_root",
                "LC_CASES_API_ROOT",
                explicit=cases_root,
            )
            or "https://cases.limacharlie.io"
        ).rstrip("/")
        self.ai_root = (
            env_first(
                config,
                environ,
                "ai_root",
                "LC_AI_SESSIONS_ROOT",
                explicit=ai_root,
            )
            or "https://ai.limacharlie.io"
        ).rstrip("/")
        raw_timeout = env_first(
            config,
            environ,
            "timeout_seconds",
            "LC_MCP_TIMEOUT_SECONDS",
            explicit=timeout_seconds,
        )
        self.timeout_seconds = float(raw_timeout or 30)
        raw_audit_path = env_first(
            config,
            environ,
            "audit_log",
            "LC_MCP_AUDIT_LOG",
            explicit=audit_path,
        )
        self.audit_path = Path(raw_audit_path) if raw_audit_path else Path(default_audit_path())
        self.http: HttpClient = http_client or httpx.Client()
        self._tokens: dict[str, Token] = {}
        self._pending_mutations: dict[str, PendingMutation] = {}
        self._search_roots: dict[str, str] = {}

    def _uses_user_api_key(self) -> bool:
        if not self.uid:
            return False
        user_key_configured = bool(self.user_api_key or self.user_api_key_ref)
        org_key_configured = bool(self.api_key or self.api_key_ref)
        if self.auth_mode == "org_api_key":
            return False
        if self.auth_mode == "user_api_key":
            return user_key_configured or (self._explicit_api_key and bool(self.api_key)) or (
                self._explicit_api_key_ref and bool(self.api_key_ref)
            )
        if self._explicit_user_api_key or self._explicit_user_api_key_ref:
            return user_key_configured and not org_key_configured
        if self._explicit_api_key and self.api_key:
            return True
        if self.credential_provider == "vault" and self._explicit_api_key_ref and self.api_key_ref:
            return True
        return user_key_configured and not org_key_configured

    def _credential_mode(self) -> str:
        return "user_api_key" if self._uses_user_api_key() else "org_api_key"

    def _global_reference_auth_oid(self, oid: str | None = None) -> str:
        if oid:
            return require_oid(oid)
        if self._uses_user_api_key():
            return "-"
        if self.default_oid:
            return require_oid(self.default_oid)
        return "-"

    def _vault_token(self) -> str | None:
        if self.vault_token:
            return self.vault_token
        if not self.vault_token_file:
            return None
        try:
            token = Path(self.vault_token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Vault token file is not readable") from exc
        return token or None

    @staticmethod
    def _parse_vault_ref(ref: str) -> tuple[str, str]:
        if not ref.startswith("vault://"):
            raise ValidationError("Vault API key references must use vault://path#field")
        raw = ref.removeprefix("vault://")
        path, sep, field = raw.partition("#")
        path = path.strip("/")
        field = field.strip() if sep else "value"
        if not path:
            raise ValidationError("Vault API key reference must include a path")
        if not field:
            raise ValidationError("Vault API key reference must include a field")
        return path, field

    def _resolve_vault_secret(self, ref: str) -> str:
        if not self.vault_addr:
            raise RuntimeError("Vault address is required for the Vault credential provider")
        token = self._vault_token()
        if not token:
            raise RuntimeError("Vault token is required for the Vault credential provider")
        path, field = self._parse_vault_ref(ref)
        headers = {"X-Vault-Token": token}
        if self.vault_namespace:
            headers["X-Vault-Namespace"] = self.vault_namespace
        response = self.http.request(
            "GET",
            f"{self.vault_addr}/v1/{quote(path, safe='/')}",
            headers=headers,
            timeout=self.timeout_seconds,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"Vault credential lookup failed with status {response.status_code}")
        payload = self._parse_response(response)
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data["data"]
        if not isinstance(data, dict):
            raise RuntimeError("Vault credential lookup returned an unexpected payload shape")
        value = data.get(field)
        if not isinstance(value, str) or not value:
            raise RuntimeError("Vault credential lookup did not return a usable API key")
        return value

    def _api_key_configured(self) -> bool:
        if self._uses_user_api_key():
            if self.user_api_key or (self._explicit_api_key and self.api_key):
                return True
            if self.credential_provider != "vault":
                return False
            try:
                return bool((self.user_api_key_ref or self.api_key_ref) and self.vault_addr and self._vault_token())
            except RuntimeError:
                return False
        if self.api_key:
            return True
        if self.credential_provider != "vault":
            return False
        try:
            return bool(self.api_key_ref and self.vault_addr and self._vault_token())
        except RuntimeError:
            return False

    def _resolve_api_key(self) -> str | None:
        if self._uses_user_api_key():
            if self.user_api_key:
                return self.user_api_key
            if self._explicit_api_key and self.api_key:
                return self.api_key
            if self.credential_provider == "vault":
                ref = self.user_api_key_ref or self.api_key_ref
                if ref:
                    return self._resolve_vault_secret(ref)
            return None
        if self.api_key:
            return self.api_key
        if self.credential_provider == "vault" and self.api_key_ref:
            return self._resolve_vault_secret(self.api_key_ref)
        return None

    def auth_whoami(self, oid: str | None = None, check_perm: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        if check_perm:
            if not scoped_oid:
                raise ValidationError("check_perm requires an explicit oid")
            if scoped_oid == "-":
                raise ValidationError("check_perm requires an explicit oid")
            safe_perm = require_permission(check_perm)
        response = self._request(
            "GET",
            "who",
            operation="auth.whoami",
            oid=scoped_oid,
            resource={"type": "identity", "id": scoped_oid},
        ).as_dict()
        if check_perm and response["ok"]:
            data = response.get("data") or {}
            all_perms: list[str] = []
            raw = data.get("perms", []) if isinstance(data, dict) else []
            if isinstance(raw, list):
                all_perms.extend(str(perm) for perm in raw)
            raw_user = data.get("user_perms", {}) if isinstance(data, dict) else {}
            if isinstance(raw_user, dict):
                for value in raw_user.values():
                    if isinstance(value, list):
                        all_perms.extend(str(perm) for perm in value)
            response["data"] = {"perm": safe_perm, "has_perm": safe_perm in all_perms}
        return response

    def auth_status(self, oid: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        token = self._tokens.get(scoped_oid)
        now = time.time()
        expires_in = int(token.expires_at - now) if token else None
        credential_mode = self._credential_mode()
        api_key_configured = self._api_key_configured()
        if credential_mode == "user_api_key":
            if self.user_api_key or (self._explicit_api_key and self.api_key):
                api_key_source = "user_direct"
            elif self.credential_provider == "vault" and api_key_configured:
                api_key_source = "user_vault_ref"
            else:
                api_key_source = "missing"
        else:
            if self.api_key:
                api_key_source = "direct"
            elif self.credential_provider == "vault" and api_key_configured:
                api_key_source = "vault_ref"
            else:
                api_key_source = "missing"
        try:
            vault_token_configured = bool(self._vault_token()) if self.credential_provider == "vault" else False
        except RuntimeError:
            vault_token_configured = False
        warnings: list[str] = []
        if not api_key_configured and self.credential_provider == "vault":
            warnings.append("Vault credential provider is not fully configured.")
        elif not api_key_configured:
            warnings.append("LC_API_KEY is not configured.")
        if self.uid and credential_mode == "org_api_key":
            if self.user_api_key or self.user_api_key_ref:
                warnings.append(
                    "LC_UID and a user API key source are set, but organization API key mode is active; set LC_AUTH_MODE=user_api_key to use the user key."
                )
            else:
                warnings.append("LC_UID is set but no user API key source is configured; using organization API key mode.")
        if credential_mode == "user_api_key" and scoped_oid == "-":
            warnings.append(
                "User API key mode can produce large multi-org JWTs; pass oid for org-scoped refresh if needed."
            )
        return ToolResponse(
            ok=api_key_configured,
            operation="auth.status",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "auth_session", "id": scoped_oid},
            state={
                "current": "configured" if api_key_configured else "missing_credentials",
                "credential_mode": credential_mode,
                "credential_provider": self.credential_provider,
                "jwt_cached": token is not None,
                "jwt_expires_in_seconds": max(0, expires_in) if expires_in is not None else None,
            },
            data={
                "credential_mode": credential_mode,
                "credential_provider": self.credential_provider,
                "api_key_source": api_key_source,
                "uses_limacharlie_jwt_exchange": True,
                "jwt_managed_by_server": True,
                "jwt_cached": token is not None,
                "jwt_expires_in_seconds": max(0, expires_in) if expires_in is not None else None,
                "configured": {
                    "api_key": api_key_configured,
                    "api_key_ref": bool(self.api_key_ref) if self.credential_provider == "vault" else False,
                    "user_api_key": bool(self.user_api_key),
                    "user_api_key_ref": bool(self.user_api_key_ref) if self.credential_provider == "vault" else False,
                    "vault_addr": bool(self.vault_addr),
                    "vault_token": vault_token_configured,
                    "vault_namespace": bool(self.vault_namespace),
                    "uid": bool(self.uid),
                    "api_root": self.api_root,
                    "jwt_root": self.jwt_root,
                    "cases_root": self.cases_root,
                },
            },
            side_effects=[],
            warnings=warnings,
            meta={
                "summary": {
                    "credential_mode": credential_mode,
                    "credential_provider": self.credential_provider,
                    "api_key_source": api_key_source,
                    "jwt_cached": token is not None,
                    "configured": api_key_configured,
                },
                "truncated": False,
            },
            observed_at=observed_at(),
            error=None
            if api_key_configured
            else {
                "code": "missing_credentials",
                "class": "auth",
                "message": "LimaCharlie API credentials are not fully configured.",
                "retryable": False,
                "same_input_retryable": False,
                "suggested_next_actions": [
                    "Configure Vault with LC_SECRET_PROVIDER=vault, LC_VAULT_ADDR, and LC_API_KEY_REF for org mode.",
                    "For user API key mode, configure LC_UID and LC_USER_API_KEY_REF.",
                    "For local development only, set LC_SECRET_PROVIDER=env and LC_API_KEY or LC_USER_API_KEY.",
                ],
            },
        ).as_dict()

    def auth_refresh(self, oid: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid) if oid else "-"
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        self._tokens.pop(scoped_oid, None)
        try:
            self._get_jwt(scoped_oid, force_refresh=True)
        except Exception as exc:
            duration_ms = int((time.time() - started) * 1000)
            return ToolResponse(
                ok=False,
                operation="auth.refresh",
                request_id=request_id,
                resource={"type": "auth_session", "id": scoped_oid},
                state={"current": "refresh_failed"},
                data=None,
                side_effects=[],
                warnings=[],
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                observed_at=observed_at(),
                error=classify_error(None, None, str(exc)),
            ).as_dict()
        token = self._tokens[scoped_oid]
        duration_ms = int((time.time() - started) * 1000)
        credential_mode = self._credential_mode()
        return ToolResponse(
            ok=True,
            operation="auth.refresh",
            request_id=request_id,
            resource={"type": "auth_session", "id": scoped_oid},
            state={"previous": "unknown_or_expiring", "current": "refreshed"},
            data={
                "credential_mode": credential_mode,
                "credential_provider": self.credential_provider,
                "jwt_managed_by_server": True,
                "jwt_cached": True,
                "jwt_expires_in_seconds": max(0, int(token.expires_at - time.time())),
            },
            side_effects=[{"type": "local_jwt_cache_refresh", "resource": {"type": "auth_session", "id": scoped_oid}}],
            warnings=[],
            meta={
                "duration_ms": duration_ms,
                "summary": {"jwt_cached": True, "credential_mode": credential_mode},
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def list_orgs(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "user/orgs",
            operation="org.list",
            oid="-",
            resource={"type": "organization_collection", "id": "-"},
        ).as_dict()

    def tool_catalog(self, profile: str | None = None) -> dict[str, Any]:
        selected_profile = normalize_profile(profile)
        operations = filter_operation_catalog(OPERATION_CATALOG, selected_profile)
        return ToolResponse(
            ok=True,
            operation="tool.catalog",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "tool_surface", "id": f"limacharlie-mcp:{selected_profile}"},
            state={},
            data={
                "server": "limacharlie-mcp",
                "profile": selected_profile,
                "transport": "stdio",
                "auth": "vault_or_env_api_key_jwt_exchange",
                "credential_provider_default": "vault",
                "default_mode": "read_only",
                "operations": operations,
                "profiles": profile_catalog(OPERATION_CATALOG),
                "unsupported_capabilities": UNSUPPORTED_CAPABILITIES,
            },
            side_effects=[],
            warnings=[],
            meta={
                "summary": {
                    "profile": selected_profile,
                    "operation_count": len(operations),
                    "unsupported_capability_count": len(UNSUPPORTED_CAPABILITIES),
                },
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def list_sensor_download_targets(self) -> dict[str, Any]:
        return self._local_response(
            "download.sensor_targets.list",
            {"targets": self._download_targets(_SENSOR_DOWNLOAD_TARGETS)},
            resource={"type": "download_target_collection", "id": "sensor"},
        )

    def list_adapter_download_targets(self) -> dict[str, Any]:
        return self._local_response(
            "download.adapter_targets.list",
            {"targets": self._download_targets(_ADAPTER_DOWNLOAD_TARGETS)},
            resource={"type": "download_target_collection", "id": "adapter"},
        )

    def _review_finding(
        self,
        finding_id: str,
        severity: str,
        title: str,
        evidence: dict[str, Any],
        recommendation: str,
        *,
        category: str,
        confidence: str = "medium",
    ) -> dict[str, Any]:
        return {
            "id": finding_id,
            "category": category,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
            "confidence": confidence,
        }

    def _review_source(self, name: str, result: dict[str, Any]) -> dict[str, Any]:
        source: dict[str, Any] = {
            "name": name,
            "operation": result.get("operation"),
            "ok": bool(result.get("ok")),
            "summary": result.get("meta", {}).get("summary", {}),
            "truncated": bool(result.get("meta", {}).get("truncated", False)),
        }
        if not source["ok"]:
            error = result.get("error") or {}
            source["error"] = {
                "code": error.get("code", "unknown"),
                "class": error.get("class", "unknown"),
                "message": error.get("message", "source read failed"),
            }
        return source

    def _review_call(self, name: str, fn: Any, *args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            result = fn(*args, **kwargs)
        except ValidationError:
            raise
        except Exception as exc:
            result = {
                "ok": False,
                "operation": name,
                "data": None,
                "meta": {"summary": {"shape": "empty"}, "truncated": False},
                "error": {
                    "code": "source_exception",
                    "class": "internal",
                    "message": redact_text(str(exc)),
                    "retryable": False,
                    "same_input_retryable": False,
                },
            }
        return result, self._review_source(name, result)

    def _review_count(self, result: dict[str, Any], *preferred_keys: str) -> int:
        data = result.get("data")
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for key in (*preferred_keys, *_SUMMARY_LIST_KEYS):
                value = data.get(key)
                if isinstance(value, (list, dict)):
                    return len(value)
            return len(data)
        return 0

    def _review_items(self, result: dict[str, Any], *preferred_keys: str) -> list[Any]:
        data = result.get("data")
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        for key in (*preferred_keys, *_SUMMARY_LIST_KEYS):
            value = data.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return list(value.values())
        if data and all(isinstance(value, dict) for value in data.values()):
            return list(data.values())
        return []

    def _top_values(self, items: list[Any], keys: tuple[str, ...], *, limit: int = 5) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            value = None
            for key in keys:
                candidate = item.get(key)
                if candidate not in (None, ""):
                    value = candidate
                    break
            if value is None:
                continue
            label = str(value)
            counts[label] = counts.get(label, 0) + 1
        return [
            {"value": value, "count": count}
            for value, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]
        ]

    def _review_response(
        self,
        operation: str,
        oid: str,
        *,
        metrics: dict[str, Any],
        findings: list[dict[str, Any]],
        recommendations: list[str],
        sources: list[dict[str, Any]],
        limit: int,
        warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda finding: (severity_order.get(str(finding.get("severity")), 9), str(finding.get("id"))))
        failed_sources = [source for source in sources if not source.get("ok")]
        response_warnings = list(warnings or [])
        for source in failed_sources:
            error = source.get("error", {})
            response_warnings.append(f"{source.get('name')}: {error.get('message', 'source read failed')}")
        state = "needs_attention" if any(f.get("severity") in {"critical", "high", "medium"} for f in sorted_findings) else "reviewed"
        return self._local_response(
            operation,
            {
                "oid": oid,
                "metrics": metrics,
                "findings": sorted_findings,
                "recommendations": recommendations,
                "sources": sources,
            },
            resource={"type": OPERATION_CATALOG[operation]["resource_type"], "id": oid},
            state={"current": state, "terminal": True},
            warnings=response_warnings,
            limit=limit,
        )

    def review_fleet_health(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        sensors, sensors_source = self._review_call("sensor.list", self.list_sensors, scoped_oid, limit=bounded_limit)
        online, online_source = self._review_call("sensor.online.list", self.list_online_sensors, scoped_oid, limit=bounded_limit)
        tags, tags_source = self._review_call("tag.list", self.list_tags, scoped_oid, limit=bounded_limit)
        sensor_items = self._review_items(sensors, "sensors")
        sensor_count = self._review_count(sensors, "sensors")
        online_endpoint_count = self._review_count(online, "sensors")
        sensor_list_online_count = None
        if sensor_items and all(isinstance(sensor, dict) and "is_online" in sensor for sensor in sensor_items):
            sensor_list_online_count = sum(1 for sensor in sensor_items if sensor.get("is_online") is True)
        online_count = sensor_list_online_count if sensor_list_online_count is not None else online_endpoint_count
        findings: list[dict[str, Any]] = []
        if sensors.get("ok") and sensor_count == 0:
            findings.append(
                self._review_finding(
                    "fleet.no_sensors",
                    "high",
                    "No sensors returned in the bounded fleet sample",
                    {"sensor_count": sensor_count},
                    "Verify enrollment, installation keys, and org selection before relying on detections or response workflows.",
                    category="fleet",
                )
            )
        elif online.get("ok") and sensor_count > 0 and online_count == 0:
            findings.append(
                self._review_finding(
                    "fleet.no_online_sensors",
                    "medium",
                    "No online sensors returned in the bounded fleet sample",
                    {"sensor_count": sensor_count, "online_sensor_count": online_count},
                    "Check sensor connectivity and confirm whether endpoint telemetry is expected in this org.",
                    category="fleet",
                )
            )
        elif sensors.get("ok") and online.get("ok") and sensor_count > 0:
            ratio = online_count / sensor_count
            if ratio < 0.5:
                findings.append(
                    self._review_finding(
                        "fleet.low_online_ratio",
                        "low",
                        "Online sensor sample is materially smaller than the fleet sample",
                        {"sensor_count": sensor_count, "online_sensor_count": online_count, "sample_ratio": round(ratio, 3)},
                        "Inspect stale hosts and expected check-in patterns before interpreting detection gaps.",
                        category="fleet",
                    )
                )
        return self._review_response(
            "review.fleet_health",
            scoped_oid,
            metrics={
                "sensor_sample_count": sensor_count,
                "online_sensor_sample_count": online_count,
                "online_sensor_endpoint_count": online_endpoint_count,
                "sensor_list_online_count": sensor_list_online_count,
                "tag_count": self._review_count(tags, "tags"),
            },
            findings=findings,
            recommendations=["Use lc_list_sensors and lc_list_online_sensors to inspect concrete endpoints behind these counts."],
            sources=[sensors_source, online_source, tags_source],
            limit=bounded_limit,
        )

    def review_detection_noise(self, oid: str, start: int, end: int, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        detections, detections_source = self._review_call(
            "detection.list",
            self.list_detections,
            scoped_oid,
            start_ts,
            end_ts,
            bounded_limit,
        )
        cases, cases_source = self._review_call("case.list", self.list_cases, scoped_oid, limit=min(bounded_limit, 200))
        detection_items = self._review_items(detections, "detects", "detections")
        detection_count = len(detection_items) if detection_items else self._review_count(detections, "detects", "detections")
        top_categories = self._top_values(detection_items, ("cat", "category", "routing", "event_type"))
        top_rules = self._top_values(detection_items, ("rule_name", "rule", "detect_name", "name"))
        findings: list[dict[str, Any]] = []
        if detections.get("ok") and detection_count == 0:
            findings.append(
                self._review_finding(
                    "detection.no_detections",
                    "low",
                    "No detections returned in the requested window",
                    {"start": start_ts, "end": end_ts},
                    "Confirm telemetry coverage and D&R enablement before treating the environment as quiet.",
                    category="detection",
                )
            )
        if detections_source.get("truncated"):
            findings.append(
                self._review_finding(
                    "detection.sample_truncated",
                    "medium",
                    "Detection sample hit the requested limit",
                    {"limit": bounded_limit, "detection_sample_count": detection_count},
                    "Repeat with a narrower time window or category filter, then tune the highest-volume rules first.",
                    category="detection",
                )
            )
        if top_rules and detection_count >= 10 and top_rules[0]["count"] / detection_count >= 0.5:
            findings.append(
                self._review_finding(
                    "detection.concentrated_rule_volume",
                    "medium",
                    "One detection rule dominates the bounded sample",
                    {"top_rule": top_rules[0], "detection_sample_count": detection_count},
                    "Review the dominant rule for expected prevalence, suppression candidates, or missing context filters.",
                    category="detection",
                )
            )
        return self._review_response(
            "review.detection_noise",
            scoped_oid,
            metrics={
                "start": start_ts,
                "end": end_ts,
                "detection_sample_count": detection_count,
                "case_sample_count": self._review_count(cases, "cases"),
                "top_categories": top_categories,
                "top_rules": top_rules,
            },
            findings=findings,
            recommendations=["Use lc_list_detections with narrower bounds before changing any D&R or false-positive content."],
            sources=[detections_source, cases_source],
            limit=bounded_limit,
        )

    def review_content_coverage(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        dr, dr_source = self._review_call("dr_rule.list", self.list_dr_rules, scoped_oid, limit=bounded_limit)
        fp, fp_source = self._review_call("fp_rule.list", self.list_fp_rules, scoped_oid, limit=bounded_limit)
        logging, logging_source = self._review_call("logging_rule.list", self.list_logging_rules, scoped_oid, limit=bounded_limit)
        integrity, integrity_source = self._review_call("integrity_rule.list", self.list_integrity_rules, scoped_oid, limit=bounded_limit)
        yara, yara_source = self._review_call("yara_rule.list", self.list_yara_rules, scoped_oid, limit=bounded_limit)
        mitre, mitre_source = self._review_call("mitre.get", self.get_mitre_report, scoped_oid)
        metrics = {
            "dr_rule_count": self._review_count(dr, "rules"),
            "fp_rule_count": self._review_count(fp, "rules"),
            "logging_rule_count": self._review_count(logging, "rules"),
            "integrity_rule_count": self._review_count(integrity, "rules"),
            "yara_rule_count": self._review_count(yara, "rules"),
            "mitre_summary": mitre.get("meta", {}).get("summary", {}),
        }
        findings: list[dict[str, Any]] = []
        if dr.get("ok") and metrics["dr_rule_count"] == 0:
            findings.append(
                self._review_finding(
                    "content.no_dr_rules",
                    "high",
                    "No D&R rules returned in the bounded content sample",
                    {"dr_rule_count": metrics["dr_rule_count"]},
                    "Add or enable detection and response rules before depending on automated detection coverage.",
                    category="content",
                )
            )
        if logging.get("ok") and integrity.get("ok") and metrics["logging_rule_count"] == 0 and metrics["integrity_rule_count"] == 0:
            findings.append(
                self._review_finding(
                    "content.no_collection_rules",
                    "medium",
                    "No logging or integrity collection rules returned",
                    {"logging_rule_count": metrics["logging_rule_count"], "integrity_rule_count": metrics["integrity_rule_count"]},
                    "Review whether collection rules should be enabled for the operating systems and assets in scope.",
                    category="content",
                )
            )
        if fp.get("ok") and dr.get("ok") and metrics["fp_rule_count"] > metrics["dr_rule_count"] and metrics["fp_rule_count"] >= 5:
            findings.append(
                self._review_finding(
                    "content.fp_outnumbers_dr",
                    "low",
                    "False-positive rules outnumber D&R rules in the bounded sample",
                    {"fp_rule_count": metrics["fp_rule_count"], "dr_rule_count": metrics["dr_rule_count"]},
                    "Review whether suppression is compensating for noisy or overly broad detections.",
                    category="content",
                )
            )
        return self._review_response(
            "review.content_coverage",
            scoped_oid,
            metrics=metrics,
            findings=findings,
            recommendations=["Use lc_get_mitre_report and content-specific list tools to identify concrete coverage gaps before editing rules."],
            sources=[dr_source, fp_source, logging_source, integrity_source, yara_source, mitre_source],
            limit=bounded_limit,
        )

    def review_case_backlog(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit, maximum=200)
        cases, cases_source = self._review_call("case.list", self.list_cases, scoped_oid, limit=bounded_limit)
        dashboard, dashboard_source = self._review_call("case.dashboard", self.get_cases_dashboard_counts, scoped_oid)
        case_items = self._review_items(cases, "cases")
        status_counts = self._top_values(case_items, ("status",), limit=10)
        severity_counts = self._top_values(case_items, ("severity",), limit=10)
        case_count = len(case_items) if case_items else self._review_count(cases, "cases")
        open_count = sum(item["count"] for item in status_counts if str(item["value"]).lower() not in {"closed", "resolved", "done"})
        findings: list[dict[str, Any]] = []
        if cases_source.get("truncated"):
            findings.append(
                self._review_finding(
                    "case.sample_truncated",
                    "medium",
                    "Case sample hit the requested limit",
                    {"limit": bounded_limit, "case_sample_count": case_count},
                    "Filter by open statuses or use case dashboard counts before deciding backlog health.",
                    category="case",
                )
            )
        if case_items and open_count > 0:
            findings.append(
                self._review_finding(
                    "case.open_backlog",
                    "low",
                    "Open or non-terminal cases are present in the bounded sample",
                    {"open_case_sample_count": open_count, "status_counts": status_counts},
                    "Review oldest high-severity cases first and close or classify stale cases.",
                    category="case",
                )
            )
        return self._review_response(
            "review.case_backlog",
            scoped_oid,
            metrics={
                "case_sample_count": case_count,
                "open_case_sample_count": open_count,
                "status_counts": status_counts,
                "severity_counts": severity_counts,
                "dashboard_summary": dashboard.get("meta", {}).get("summary", {}),
            },
            findings=findings,
            recommendations=["Use lc_list_cases with status and severity filters for case-level follow-up."],
            sources=[cases_source, dashboard_source],
            limit=bounded_limit,
        )

    def review_output_health(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        outputs, outputs_source = self._review_call("output.list", self.list_outputs, scoped_oid, limit=bounded_limit)
        subscriptions, subscriptions_source = self._review_call("extension.list_subscribed", self.list_extension_subscriptions, scoped_oid, limit=bounded_limit)
        feedback, feedback_source = self._review_call("feedback.channel.list", self.list_feedback_channels, scoped_oid)
        metrics = {
            "output_count": self._review_count(outputs, "outputs"),
            "extension_subscription_count": self._review_count(subscriptions, "extensions", "subscriptions"),
            "feedback_channel_count": self._review_count(feedback, "channels", "resources"),
        }
        findings: list[dict[str, Any]] = []
        if outputs.get("ok") and metrics["output_count"] == 0:
            findings.append(
                self._review_finding(
                    "output.no_outputs",
                    "high",
                    "No output integrations returned",
                    {"output_count": metrics["output_count"]},
                    "Configure at least one durable output for telemetry export, retention, or downstream investigation workflows.",
                    category="output",
                )
            )
        if feedback.get("ok") and metrics["feedback_channel_count"] == 0:
            findings.append(
                self._review_finding(
                    "output.no_feedback_channels",
                    "low",
                    "No feedback channels returned",
                    {"feedback_channel_count": metrics["feedback_channel_count"]},
                    "Configure feedback channels if approval, acknowledgement, or analyst questions are expected in workflows.",
                    category="output",
                )
            )
        return self._review_response(
            "review.output_health",
            scoped_oid,
            metrics=metrics,
            findings=findings,
            recommendations=["Use lc_list_outputs to inspect concrete destinations before making integration changes."],
            sources=[outputs_source, subscriptions_source, feedback_source],
            limit=bounded_limit,
        )

    def review_access_hygiene(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        users, users_source = self._review_call("user.list", self.list_users, scoped_oid, limit=bounded_limit)
        permissions, permissions_source = self._review_call("user.permission.list", self.list_user_permissions, scoped_oid)
        keys, keys_source = self._review_call("api_key.list", self.list_api_keys, scoped_oid, limit=bounded_limit)
        groups, groups_source = self._review_call("group.list", self.list_groups, limit=bounded_limit)
        metrics = {
            "user_count": self._review_count(users, "users"),
            "permission_principal_count": self._review_count(permissions, "users", "permissions"),
            "api_key_count": self._review_count(keys, "api_keys", "keys"),
            "group_count": self._review_count(groups, "groups"),
        }
        findings: list[dict[str, Any]] = []
        if users.get("ok") and metrics["user_count"] == 0:
            findings.append(
                self._review_finding(
                    "access.no_users",
                    "high",
                    "No users returned for the organization",
                    {"user_count": metrics["user_count"]},
                    "Confirm the organization ID and account permissions before making access decisions.",
                    category="access",
                )
            )
        if keys.get("ok") and metrics["api_key_count"] == 0:
            findings.append(
                self._review_finding(
                    "access.no_org_api_keys",
                    "low",
                    "No organization API keys returned",
                    {"api_key_count": metrics["api_key_count"]},
                    "Prefer scoped organization API keys stored in Vault over user API keys for MCP runtime access.",
                    category="access",
                )
            )
        elif keys.get("ok") and metrics["api_key_count"] >= 10:
            findings.append(
                self._review_finding(
                    "access.many_org_api_keys",
                    "low",
                    "Many organization API keys returned in the bounded sample",
                    {"api_key_count": metrics["api_key_count"]},
                    "Review key ownership, last-used metadata, and permissions; retire unused keys through preview/confirm deletion.",
                    category="access",
                )
            )
        return self._review_response(
            "review.access_hygiene",
            scoped_oid,
            metrics=metrics,
            findings=findings,
            recommendations=["Use lc_list_api_keys and lc_list_user_permissions to inspect principals before changing access."],
            sources=[users_source, permissions_source, keys_source, groups_source],
            limit=bounded_limit,
        )

    def review_org_posture(self, oid: str, start: int | None = None, end: int | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        if start is None and end is not None or start is not None and end is None:
            raise ValidationError("start and end must be provided together for detection-noise review")
        if start is not None and end is not None:
            start_ts, end_ts = require_time_window(start, end)
        else:
            start_ts = None
            end_ts = None
        component_results: list[dict[str, Any]] = [
            self.review_fleet_health(scoped_oid, limit=bounded_limit),
            self.review_output_health(scoped_oid, limit=bounded_limit),
            self.review_access_hygiene(scoped_oid, limit=bounded_limit),
            self.review_content_coverage(scoped_oid, limit=bounded_limit),
            self.review_case_backlog(scoped_oid, limit=min(bounded_limit, 200)),
        ]
        if start_ts is not None and end_ts is not None:
            component_results.append(self.review_detection_noise(scoped_oid, start_ts, end_ts, limit=bounded_limit))
        org_errors, org_errors_source = self._review_call("org.errors", self.list_org_errors, scoped_oid)
        component_summaries = []
        findings: list[dict[str, Any]] = []
        component_sources: list[dict[str, Any]] = []
        for result in component_results:
            data = result.get("data", {})
            sources = data.get("sources", []) if isinstance(data, dict) else []
            failed_sources = [source for source in sources if not source.get("ok")]
            component_summaries.append(
                {
                    "operation": result.get("operation"),
                    "state": result.get("state", {}).get("current"),
                    "finding_count": len(data.get("findings", [])) if isinstance(data, dict) else 0,
                    "failed_source_count": len(failed_sources),
                    "metrics": data.get("metrics", {}) if isinstance(data, dict) else {},
                }
            )
            if isinstance(data, dict):
                findings.extend(data.get("findings", []))
                component_sources.extend(sources)
        org_error_count = self._review_count(org_errors, "errors")
        if org_errors.get("ok") and org_error_count > 0:
            findings.append(
                self._review_finding(
                    "org.component_errors",
                    "medium",
                    "Organization component errors are present",
                    {"org_error_count": org_error_count},
                    "Inspect lc_list_org_errors and dismiss only after validating the underlying component issue is resolved.",
                    category="organization",
                )
            )
        all_sources = [org_errors_source, *component_sources]
        failed_sources = [source for source in all_sources if not source.get("ok")]
        return self._review_response(
            "review.org_posture",
            scoped_oid,
            metrics={
                "component_count": len(component_results),
                "source_count": len(all_sources),
                "failed_source_count": len(failed_sources),
                "failed_sources": [
                    {
                        "name": source.get("name"),
                        "operation": source.get("operation"),
                        "error": source.get("error"),
                    }
                    for source in failed_sources
                ],
                "org_error_count": org_error_count,
                "detection_window": {"start": start_ts, "end": end_ts} if start_ts is not None and end_ts is not None else None,
                "components": component_summaries,
            },
            findings=findings,
            recommendations=[
                "Prioritize high and medium findings, then inspect each component review for concrete follow-up tools.",
                "Do not change content, access, or response state from this aggregate; use preview/confirm mutation tools for any remediation.",
            ],
            sources=all_sources,
            limit=bounded_limit,
        )

    def list_sensors(self, oid: str, selector: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {"limit": bounded_limit}
        safe_selector = require_selector(selector)
        if safe_selector:
            params["selector"] = safe_selector
        return self._request(
            "GET",
            f"sensors/{scoped_oid}",
            operation="sensor.list",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_sensor(self, oid: str, sensor_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        return self._request(
            "GET",
            safe_sensor_id,
            operation="sensor.get",
            oid=scoped_oid,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def get_sensor_isolation_status(self, oid: str, sensor_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        result = self._request(
            "GET",
            safe_sensor_id,
            operation="sensor.isolation_status.get",
            oid=scoped_oid,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()
        if result.get("ok"):
            isolated = bool(sensor_info(result.get("data")).get("should_isolate", False))
            result["state"] = {"current": "isolated" if isolated else "not_isolated", "terminal": True}
            result["data"] = {"sid": safe_sensor_id, "is_isolated": isolated, "sensor": result.get("data")}
            result["meta"]["summary"]["is_isolated"] = isolated
        return result

    def get_sensor_seal_status(self, oid: str, sensor_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        result = self._request(
            "GET",
            safe_sensor_id,
            operation="sensor.seal_status.get",
            oid=scoped_oid,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()
        if result.get("ok"):
            sealed = bool(sensor_info(result.get("data")).get("should_seal", False))
            result["state"] = {"current": "sealed" if sealed else "not_sealed", "terminal": True}
            result["data"] = {"sid": safe_sensor_id, "is_sealed": sealed, "sensor": result.get("data")}
            result["meta"]["summary"]["is_sealed"] = sealed
        return result

    def wait_sensor_online(
        self,
        oid: str,
        sensor_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 5,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        timeout = require_seconds(timeout_seconds, "timeout_seconds", minimum=1, maximum=3600)
        poll_interval = require_seconds(poll_interval_seconds, "poll_interval_seconds", minimum=1, maximum=60)
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        attempts = 0
        last_result: dict[str, Any] | None = None
        while True:
            attempts += 1
            result = self._request(
                "GET",
                safe_sensor_id,
                operation="sensor.wait_online",
                oid=scoped_oid,
                resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            ).as_dict()
            last_result = result
            if not result["ok"]:
                result["meta"]["attempts"] = attempts
                return result
            if sensor_online(result.get("data")):
                duration_ms = int((time.time() - started) * 1000)
                result["request_id"] = request_id
                result["state"] = {"current": "online", "terminal": True}
                result["data"] = {"sid": safe_sensor_id, "is_online": True, "sensor": result.get("data")}
                result["meta"]["duration_ms"] = duration_ms
                result["meta"]["attempts"] = attempts
                result["meta"]["summary"]["is_online"] = True
                return result
            elapsed = time.time() - started
            if elapsed + poll_interval > timeout:
                break
            time.sleep(poll_interval)

        duration_ms = int((time.time() - started) * 1000)
        return ToolResponse(
            ok=False,
            operation="sensor.wait_online",
            request_id=request_id,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            state={"current": "offline", "terminal": False},
            data={"last_observation": last_result.get("data") if last_result else None},
            side_effects=[],
            warnings=[],
            meta={
                "duration_ms": duration_ms,
                "attempts": attempts,
                "summary": {"is_online": False, "timed_out": True},
                "truncated": False,
            },
            observed_at=observed_at(),
            error={
                "code": "sensor_wait_online_timeout",
                "class": "transient",
                "message": f"Sensor {safe_sensor_id} did not come online within {timeout} seconds.",
                "retryable": True,
                "same_input_retryable": True,
                "suggested_next_actions": [
                    "Call lc_get_sensor to inspect the latest sensor record.",
                    "Retry lc_wait_sensor_online with a longer timeout if the sensor is expected to check in.",
                ],
            },
        ).as_dict()

    def preview_sensor_task(
        self,
        oid: str,
        sensor_id: str,
        tasks: str | list[str],
        investigation_id: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        checked_tasks = require_sensor_tasks(tasks)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        data: dict[str, Any] = {"tasks": checked_tasks}
        if investigation_id:
            data["investigation_id"] = require_token(investigation_id, "investigation_id")
        return self._create_mutation_preview(
            operation="sensor.task",
            oid=scoped_oid,
            method="POST",
            path=safe_sensor_id,
            resource={"type": "sensor_task", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=data,
            data=None,
            json_body=None,
            expected_effect=f"Queue {len(checked_tasks)} task command(s) on sensor {safe_sensor_id}.",
            reversibility="Tasking is not generally reversible; inspect job/task output and issue compensating commands if needed.",
            side_effects=[{"type": "sensor_task_queued", "resource": {"type": "sensor", "id": safe_sensor_id}, "task_count": len(checked_tasks)}],
            token_ttl_seconds=token_ttl,
        )

    def preview_isolate_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.isolate",
            oid=oid,
            sensor_id=sensor_id,
            method="POST",
            path_suffix="isolation",
            resource_type="sensor_isolation",
            expected_effect="Enable network isolation on the sensor.",
            reversibility="Call lc_preview_rejoin_sensor and confirm it to remove isolation.",
            side_effect_type="sensor_isolated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_rejoin_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.rejoin",
            oid=oid,
            sensor_id=sensor_id,
            method="DELETE",
            path_suffix="isolation",
            resource_type="sensor_isolation",
            expected_effect="Remove network isolation from the sensor.",
            reversibility="Call lc_preview_isolate_sensor and confirm it to isolate again.",
            side_effect_type="sensor_rejoined",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_seal_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.seal",
            oid=oid,
            sensor_id=sensor_id,
            method="POST",
            path_suffix="seal",
            resource_type="sensor_seal",
            expected_effect="Seal the sensor against uninstall.",
            reversibility="Call lc_preview_unseal_sensor and confirm it to unseal.",
            side_effect_type="sensor_sealed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_unseal_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._sensor_state_preview(
            operation="sensor.unseal",
            oid=oid,
            sensor_id=sensor_id,
            method="DELETE",
            path_suffix="seal",
            resource_type="sensor_seal",
            expected_effect="Unseal the sensor.",
            reversibility="Call lc_preview_seal_sensor and confirm it to seal again.",
            side_effect_type="sensor_unsealed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_sensor(self, oid: str, sensor_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="sensor.delete",
            oid=scoped_oid,
            method="DELETE",
            path=safe_sensor_id,
            resource={"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete sensor record {safe_sensor_id}.",
            reversibility="Deletion may require reinstalling or re-enrolling the sensor.",
            side_effects=[{"type": "sensor_deleted", "resource": {"type": "sensor", "id": safe_sensor_id}}],
            token_ttl_seconds=token_ttl,
        )

    def list_online_sensors(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"online/{scoped_oid}",
            operation="sensor.online.list",
            oid=scoped_oid,
            resource={"type": "online_sensor_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def list_detections(
        self,
        oid: str,
        start: int,
        end: int,
        limit: int = 100,
        cursor: str = "-",
        category: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "cursor": require_token(cursor, "cursor"),
            "is_compressed": "true",
            "limit": bounded_limit,
        }
        if category:
            params["cat"] = require_token(category, "category")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/detections",
            operation="detection.list",
            oid=scoped_oid,
            resource={"type": "detection_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_detection(self, oid: str, detect_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_detect_id = require_detect_id(detect_id)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/detections/{safe_detect_id}",
            operation="detection.get",
            oid=scoped_oid,
            resource={"type": "detection", "id": safe_detect_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def _case_resource(self, oid: str, case_number: str | int, resource_type: str = "case") -> dict[str, Any]:
        return {"type": resource_type, "id": require_case_number(case_number), "parent": {"type": "organization", "id": oid}}

    def _case_update_body(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        require_non_empty: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        checked_status = require_case_choice(status, "status", _CASE_STATUSES)
        if checked_status is not None:
            body["status"] = checked_status
        checked_severity = require_case_choice(severity, "severity", _CASE_SEVERITIES)
        if checked_severity is not None:
            body["severity"] = checked_severity
        checked_assignees = require_case_email_list(assignees)
        if checked_assignees is not None:
            body["assignees"] = checked_assignees
        checked_classification = require_case_choice(classification, "classification", _CASE_CLASSIFICATIONS)
        if checked_classification is not None:
            body["classification"] = checked_classification
        checked_summary = require_case_text(summary, "summary")
        if checked_summary is not None:
            body["summary"] = checked_summary
        checked_conclusion = require_case_text(conclusion, "conclusion")
        if checked_conclusion is not None:
            body["conclusion"] = checked_conclusion
        checked_tags = require_case_tag_list(tags)
        if checked_tags is not None:
            body["tags"] = checked_tags
        if require_non_empty and not body:
            raise ValidationError("at least one case update field is required")
        return body

    def _preview_case_api_mutation(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource_type: str,
        resource_id: str,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=oid,
            method=method,
            path=f"api/v1/{path.lstrip('/')}",
            resource={"type": resource_type, "id": resource_id, "parent": {"type": "organization", "id": oid}},
            params=params,
            data=None,
            json_body=json_body,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
            base_url=self.cases_root,
        )

    def list_cases(
        self,
        oid: str,
        status: list[str] | str | None = None,
        severity: list[str] | str | None = None,
        classification: list[str] | str | None = None,
        assignee: str | None = None,
        search: str | None = None,
        sensor_id: str | None = None,
        tags: list[str] | str | None = None,
        sort: str | None = None,
        order: str | None = None,
        limit: int = 100,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit, maximum=200)
        params: dict[str, Any] = {"oids": scoped_oid, "page_size": bounded_limit}
        checked_status = require_case_choice_list(status, "status", _CASE_STATUSES)
        if checked_status:
            params["status"] = ",".join(checked_status)
        checked_severity = require_case_choice_list(severity, "severity", _CASE_SEVERITIES)
        if checked_severity:
            params["severity"] = ",".join(checked_severity)
        checked_classification = require_case_choice_list(classification, "classification", _CASE_CLASSIFICATIONS)
        if checked_classification:
            params["classification"] = ",".join(checked_classification)
        if assignee:
            params["assignee"] = require_email(assignee)
        checked_search = require_case_text(search, "search", maximum=500)
        if checked_search:
            params["search"] = checked_search
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        checked_tags = require_case_tag_list(tags, "tags")
        if checked_tags:
            params["tag"] = ",".join(checked_tags)
        if sort:
            params["sort"] = require_token(sort, "sort")
        if order:
            params["order"] = require_case_choice(order, "order", _CASE_ORDERS)
        if page_token:
            params["page_token"] = require_token(page_token, "page_token")
        return self._request(
            "GET",
            "api/v1/cases",
            operation="case.list",
            oid=scoped_oid,
            resource={"type": "case_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
            base_url=self.cases_root,
        ).as_dict()

    def get_case(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}",
            operation="case.get",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_create_case(
        self,
        oid: str,
        detection: dict[str, Any] | None = None,
        severity: str | None = None,
        summary: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {}
        checked_detection = require_dict(detection, "detection")
        if checked_detection is not None:
            data["detection"] = checked_detection
        checked_severity = require_case_choice(severity, "severity", _CASE_SEVERITIES)
        if checked_severity is not None:
            data["severity"] = checked_severity
        checked_summary = require_case_text(summary, "summary")
        if checked_summary is not None:
            data["summary"] = checked_summary
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="case.create",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-cases",
            resource={"type": "case", "id": "new", "parent": {"type": "organization", "id": scoped_oid}},
            params=extension_request_params(scoped_oid, "create_case", data),
            data=None,
            json_body=None,
            expected_effect="Create a new LimaCharlie case through ext-cases.",
            reversibility="Close or merge the case if it was created unintentionally.",
            side_effects=[{"type": "case_created", "resource": {"type": "case", "id": "new"}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_update_case(
        self,
        oid: str,
        case_number: str | int,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body = self._case_update_body(
            status=status,
            severity=severity,
            assignees=assignees,
            classification=classification,
            summary=summary,
            conclusion=conclusion,
            tags=tags,
        )
        return self._preview_case_api_mutation(
            operation="case.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update case {safe_case_number}.",
            reversibility="Apply another case update to restore the previous values if needed.",
            side_effect_type="case_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_case_note(
        self,
        oid: str,
        case_number: str | int,
        content: str,
        note_type: str | None = None,
        is_public: bool | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {"content": require_case_text(content, "content", required=True)}
        checked_note_type = require_case_choice(note_type, "note_type", _CASE_NOTE_TYPES)
        if checked_note_type is not None:
            body["note_type"] = checked_note_type
        if is_public is not None:
            body["is_public"] = require_bool_or_none(is_public, "is_public")
        return self._preview_case_api_mutation(
            operation="case.note.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/notes",
            resource_type="case_note",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add a note to case {safe_case_number}.",
            reversibility="Delete or update the note visibility through the Cases UI/API if it was unintended.",
            side_effect_type="case_note_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_note_visibility(
        self,
        oid: str,
        case_number: str | int,
        event_id: str,
        is_public: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_event_id = require_path_segment(event_id, "event_id")
        return self._preview_case_api_mutation(
            operation="case.note.visibility",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/notes/{quote(safe_event_id, safe='')}",
            resource_type="case_note",
            resource_id=safe_event_id,
            params={"oid": scoped_oid},
            json_body={"is_public": require_bool_or_none(is_public, "is_public")},
            expected_effect=f"Set public visibility on note {safe_event_id} for case {safe_case_number}.",
            reversibility="Run the same preview with the opposite is_public value.",
            side_effect_type="case_note_visibility_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_bulk_update_cases(
        self,
        oid: str,
        case_numbers: list[str | int] | str,
        status: str | None = None,
        severity: str | None = None,
        assignees: list[str] | str | None = None,
        classification: str | None = None,
        summary: str | None = None,
        conclusion: str | None = None,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_case_numbers = require_case_numbers(case_numbers)
        update = self._case_update_body(
            status=status,
            severity=severity,
            assignees=assignees,
            classification=classification,
            summary=summary,
            conclusion=conclusion,
            tags=tags,
        )
        return self._preview_case_api_mutation(
            operation="case.bulk_update",
            oid=scoped_oid,
            method="POST",
            path="cases/bulk-update",
            resource_type="case_collection",
            resource_id=scoped_oid,
            json_body={"oid": scoped_oid, "case_numbers": checked_case_numbers, "update": update},
            expected_effect=f"Bulk update {len(checked_case_numbers)} cases.",
            reversibility="Bulk apply another update with prior values if needed.",
            side_effect_type="case_collection_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_merge_cases(
        self,
        oid: str,
        target_case_number: str | int,
        source_case_numbers: list[str | int] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        target = require_case_number_int(target_case_number)
        sources = require_case_numbers(source_case_numbers)
        if target in sources:
            raise ValidationError("target_case_number must not also be in source_case_numbers")
        return self._preview_case_api_mutation(
            operation="case.merge",
            oid=scoped_oid,
            method="POST",
            path="cases/merge",
            resource_type="case_merge",
            resource_id=str(target),
            json_body={"oid": scoped_oid, "target_case_number": target, "source_case_numbers": sources},
            expected_effect=f"Merge {len(sources)} source cases into case {target}.",
            reversibility="Case merge is not generally reversible; export source cases first if preservation is needed.",
            side_effect_type="cases_merged",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_detections(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/detections",
            operation="case.detection.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_detection_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_detection(
        self,
        oid: str,
        case_number: str | int,
        detection: dict[str, Any],
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_detection = require_dict(detection, "detection")
        if checked_detection is None:
            raise ValidationError("detection is required")
        return self._preview_case_api_mutation(
            operation="case.detection.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/detections",
            resource_type="case_detection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"detection": checked_detection},
            expected_effect=f"Link a detection to case {safe_case_number}.",
            reversibility="Remove the detection link from the case if it was unintended.",
            side_effect_type="case_detection_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_detection(
        self,
        oid: str,
        case_number: str | int,
        detection_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_detection_id = require_detect_id(detection_id)
        return self._preview_case_api_mutation(
            operation="case.detection.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/detections/{quote(safe_detection_id, safe='')}",
            resource_type="case_detection",
            resource_id=safe_detection_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove detection {safe_detection_id} from case {safe_case_number}.",
            reversibility="Add the detection to the case again if removal was unintended.",
            side_effect_type="case_detection_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_entities(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/entities",
            operation="case.entity.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_entity_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def search_case_entities(self, oid: str, entity_type: str, entity_value: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_entity_type = require_case_choice(entity_type, "entity_type", _CASE_ENTITY_TYPES)
        checked_entity_value = require_case_text(entity_value, "entity_value", maximum=1024, required=True)
        return self._request(
            "GET",
            "api/v1/entities/search",
            operation="case.entity.search",
            oid=scoped_oid,
            resource={"type": "case_entity_collection", "id": scoped_oid},
            params={"oids": scoped_oid, "entity_type": checked_entity_type, "entity_value": checked_entity_value},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_type: str,
        entity_value: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {
            "entity_type": require_case_choice(entity_type, "entity_type", _CASE_ENTITY_TYPES),
            "entity_value": require_case_text(entity_value, "entity_value", maximum=1024, required=True),
        }
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.entity.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/entities",
            resource_type="case_entity",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add an entity to case {safe_case_number}.",
            reversibility="Remove the entity from the case if it was unintended.",
            side_effect_type="case_entity_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_id: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_entity_id = require_path_segment(entity_id, "entity_id")
        body: dict[str, Any] = {}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        if not body:
            raise ValidationError("note or verdict is required")
        return self._preview_case_api_mutation(
            operation="case.entity.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/entities/{quote(safe_entity_id, safe='')}",
            resource_type="case_entity",
            resource_id=safe_entity_id,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update entity {safe_entity_id} on case {safe_case_number}.",
            reversibility="Apply another entity update with prior note/verdict if needed.",
            side_effect_type="case_entity_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_entity(
        self,
        oid: str,
        case_number: str | int,
        entity_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_entity_id = require_path_segment(entity_id, "entity_id")
        return self._preview_case_api_mutation(
            operation="case.entity.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/entities/{quote(safe_entity_id, safe='')}",
            resource_type="case_entity",
            resource_id=safe_entity_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove entity {safe_entity_id} from case {safe_case_number}.",
            reversibility="Add the entity to the case again if removal was unintended.",
            side_effect_type="case_entity_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_telemetry(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/telemetry",
            operation="case.telemetry.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_telemetry_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        event: dict[str, Any],
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_event = require_dict(event, "event")
        if checked_event is None:
            raise ValidationError("event is required")
        body: dict[str, Any] = {"event": checked_event}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.telemetry.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/telemetry",
            resource_type="case_telemetry",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add telemetry to case {safe_case_number}.",
            reversibility="Remove the telemetry reference if it was unintended.",
            side_effect_type="case_telemetry_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        telemetry_id: str,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_telemetry_id = require_path_segment(telemetry_id, "telemetry_id")
        body: dict[str, Any] = {}
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        if not body:
            raise ValidationError("note or verdict is required")
        return self._preview_case_api_mutation(
            operation="case.telemetry.update",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}/telemetry/{quote(safe_telemetry_id, safe='')}",
            resource_type="case_telemetry",
            resource_id=safe_telemetry_id,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Update telemetry {safe_telemetry_id} on case {safe_case_number}.",
            reversibility="Apply another telemetry update with prior note/verdict if needed.",
            side_effect_type="case_telemetry_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_telemetry(
        self,
        oid: str,
        case_number: str | int,
        telemetry_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_telemetry_id = require_path_segment(telemetry_id, "telemetry_id")
        return self._preview_case_api_mutation(
            operation="case.telemetry.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/telemetry/{quote(safe_telemetry_id, safe='')}",
            resource_type="case_telemetry",
            resource_id=safe_telemetry_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove telemetry {safe_telemetry_id} from case {safe_case_number}.",
            reversibility="Add the telemetry reference again if removal was unintended.",
            side_effect_type="case_telemetry_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_artifacts(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        return self._request(
            "GET",
            f"api/v1/cases/{safe_case_number}/artifacts",
            operation="case.artifact.list",
            oid=scoped_oid,
            resource=self._case_resource(scoped_oid, safe_case_number, "case_artifact_collection"),
            params={"oid": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_add_case_artifact(
        self,
        oid: str,
        case_number: str | int,
        path: str,
        source: str,
        artifact_type: str | None = None,
        note: str | None = None,
        verdict: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        body: dict[str, Any] = {
            "path": require_case_text(path, "path", maximum=2048, required=True),
            "source": require_case_text(source, "source", maximum=1024, required=True),
        }
        if artifact_type is not None:
            body["artifact_type"] = require_token(artifact_type, "artifact_type")
        checked_note = require_case_text(note, "note", maximum=2048)
        if checked_note is not None:
            body["note"] = checked_note
        checked_verdict = require_case_choice(verdict, "verdict", _CASE_VERDICTS)
        if checked_verdict is not None:
            body["verdict"] = checked_verdict
        return self._preview_case_api_mutation(
            operation="case.artifact.add",
            oid=scoped_oid,
            method="POST",
            path=f"cases/{safe_case_number}/artifacts",
            resource_type="case_artifact",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body=body,
            expected_effect=f"Add an artifact reference to case {safe_case_number}.",
            reversibility="Remove the artifact reference if it was unintended.",
            side_effect_type="case_artifact_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_artifact(
        self,
        oid: str,
        case_number: str | int,
        artifact_id: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        safe_artifact_id = require_path_segment(artifact_id, "artifact_id")
        return self._preview_case_api_mutation(
            operation="case.artifact.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"cases/{safe_case_number}/artifacts/{quote(safe_artifact_id, safe='')}",
            resource_type="case_artifact",
            resource_id=safe_artifact_id,
            params={"oid": scoped_oid},
            expected_effect=f"Remove artifact {safe_artifact_id} from case {safe_case_number}.",
            reversibility="Add the artifact reference again if removal was unintended.",
            side_effect_type="case_artifact_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    def export_case(self, oid: str, case_number: str | int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        resource = self._case_resource(scoped_oid, safe_case_number, "case_export")
        components: dict[str, Any] = {}
        requests = [
            ("case", self.get_case),
            ("detections", self.list_case_detections),
            ("entities", self.list_case_entities),
            ("telemetry", self.list_case_telemetry),
            ("artifacts", self.list_case_artifacts),
        ]
        for name, fn in requests:
            result = fn(scoped_oid, safe_case_number)
            if not result.get("ok"):
                return ToolResponse(
                    ok=False,
                    operation="case.export",
                    request_id=f"req_{uuid.uuid4().hex}",
                    resource=resource,
                    state={"current": "partial"},
                    data={"components": components, "failed_component": name, "failure": result.get("data")},
                    side_effects=[],
                    warnings=[],
                    meta={"summary": {"shape": "object", "failed_component": name}, "truncated": False},
                    observed_at=observed_at(),
                    error=result.get("error") or classify_error(None, None, f"case export failed while fetching {name}"),
                ).as_dict()
            components[name] = result.get("data")
        return ToolResponse(
            ok=True,
            operation="case.export",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state={},
            data=components,
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "object", "components": len(components)}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def get_cases_report_summary(self, oid: str, time_from: str, time_to: str, group_by: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        params: dict[str, Any] = {
            "oids": scoped_oid,
            "from": require_case_text(time_from, "time_from", maximum=100, required=True),
            "to": require_case_text(time_to, "time_to", maximum=100, required=True),
        }
        if group_by:
            params["group_by"] = require_token(group_by, "group_by")
        return self._request(
            "GET",
            "api/v1/reports/summary",
            operation="case.report",
            oid=scoped_oid,
            resource={"type": "case_report", "id": scoped_oid},
            params=params,
            base_url=self.cases_root,
        ).as_dict()

    def get_cases_dashboard_counts(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            "api/v1/dashboard/counts",
            operation="case.dashboard",
            oid=scoped_oid,
            resource={"type": "case_dashboard", "id": scoped_oid},
            params={"oids": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def get_cases_config(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"api/v1/config/{scoped_oid}",
            operation="case.config.get",
            oid=scoped_oid,
            resource={"type": "case_config", "id": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def preview_set_cases_config(self, oid: str, config: dict[str, Any], token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_config = require_dict(config, "config")
        if checked_config is None:
            raise ValidationError("config is required")
        return self._preview_case_api_mutation(
            operation="case.config.set",
            oid=scoped_oid,
            method="PUT",
            path=f"config/{scoped_oid}",
            resource_type="case_config",
            resource_id=scoped_oid,
            json_body=checked_config,
            expected_effect="Replace Cases configuration for the org.",
            reversibility="Restore the previous Cases configuration from a known-good export.",
            side_effect_type="case_config_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_case_assignees(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            "api/v1/assignees",
            operation="case.assignees.list",
            oid=scoped_oid,
            resource={"type": "case_assignee_collection", "id": scoped_oid},
            params={"oids": scoped_oid},
            base_url=self.cases_root,
        ).as_dict()

    def list_case_orgs(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "api/v1/orgs",
            operation="case.org.list",
            oid="-",
            resource={"type": "case_org_collection", "id": "-"},
            base_url=self.cases_root,
        ).as_dict()

    def preview_set_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        checked_tags = require_case_tag_list(tags)
        if checked_tags is None:
            raise ValidationError("tags are required")
        return self._preview_case_api_mutation(
            operation="case.tag.set",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": checked_tags},
            expected_effect=f"Replace all tags on case {safe_case_number}.",
            reversibility="Run another tag set preview with the prior complete tag list.",
            side_effect_type="case_tags_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        requested_tags = require_case_tag_list(tags)
        if requested_tags is None:
            raise ValidationError("tags are required")
        current = self.get_case(scoped_oid, safe_case_number)
        if not current.get("ok"):
            current["operation"] = "case.tag.add.preview"
            return current
        existing = self._case_tags_from_data(current.get("data"))
        seen = {tag.lower(): tag for tag in existing}
        for tag in requested_tags:
            seen.setdefault(tag.lower(), tag)
        merged = list(seen.values())
        return self._preview_case_api_mutation(
            operation="case.tag.add",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": merged},
            expected_effect=f"Add tags to case {safe_case_number} by replacing tags with the merged set.",
            reversibility="Run tag set with the prior complete tag list.",
            side_effect_type="case_tags_added",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_remove_case_tags(
        self,
        oid: str,
        case_number: str | int,
        tags: list[str] | str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_case_number = require_case_number(case_number)
        requested_tags = require_case_tag_list(tags)
        if requested_tags is None:
            raise ValidationError("tags are required")
        current = self.get_case(scoped_oid, safe_case_number)
        if not current.get("ok"):
            current["operation"] = "case.tag.remove.preview"
            return current
        remove_set = {tag.lower() for tag in requested_tags}
        remaining = [tag for tag in self._case_tags_from_data(current.get("data")) if tag.lower() not in remove_set]
        return self._preview_case_api_mutation(
            operation="case.tag.remove",
            oid=scoped_oid,
            method="PATCH",
            path=f"cases/{safe_case_number}",
            resource_type="case_tag_collection",
            resource_id=safe_case_number,
            params={"oid": scoped_oid},
            json_body={"tags": remaining},
            expected_effect=f"Remove tags from case {safe_case_number} by replacing tags with the remaining set.",
            reversibility="Run tag set with the prior complete tag list.",
            side_effect_type="case_tags_removed",
            token_ttl_seconds=token_ttl_seconds,
        )

    @staticmethod
    def _case_tags_from_data(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []
        case_data = data.get("case") if isinstance(data.get("case"), dict) else data
        raw_tags = case_data.get("tags") if isinstance(case_data, dict) else None
        if not isinstance(raw_tags, list):
            return []
        return [str(tag) for tag in raw_tags if isinstance(tag, str) and tag]

    def list_sensor_events(
        self,
        oid: str,
        sensor_id: str,
        start: int,
        end: int,
        event_type: str | None = None,
        limit: int = 100,
        cursor: str = "-",
        is_forward: bool = True,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "is_compressed": "true",
            "is_forward": bool_param(is_forward),
            "cursor": require_token(cursor, "cursor"),
            "limit": bounded_limit,
        }
        if event_type:
            params["event_type"] = require_token(event_type, "event_type")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}",
            operation="event.list",
            oid=scoped_oid,
            resource={
                "type": "event_collection",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_sensor_event_overview(self, oid: str, sensor_id: str, start: int, end: int) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        start_ts, end_ts = require_time_window(start, end)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/overview",
            operation="event.overview",
            oid=scoped_oid,
            resource={
                "type": "event_overview",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params={"start": start_ts, "end": end_ts},
        ).as_dict()

    def get_event(self, oid: str, sensor_id: str, atom: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_atom = require_path_segment(atom, "atom")
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/{quote(safe_atom, safe='')}",
            operation="event.get",
            oid=scoped_oid,
            resource={
                "type": "event",
                "id": safe_atom,
                "parent": {"type": "sensor", "id": safe_sensor_id},
            },
        ).as_dict()

    def list_child_events(self, oid: str, sensor_id: str, atom: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_atom = require_path_segment(atom, "atom")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/{safe_sensor_id}/{quote(safe_atom, safe='')}/children",
            operation="event.children",
            oid=scoped_oid,
            resource={
                "type": "event_collection",
                "id": safe_atom,
                "parent": {"type": "sensor", "id": safe_sensor_id},
            },
            params={"is_compressed": "true"},
            limit=bounded_limit,
        ).as_dict()

    def get_event_retention(
        self,
        oid: str,
        sensor_id: str,
        start: int,
        end: int,
        is_detailed: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {"start": start_ts, "end": end_ts}
        if is_detailed:
            params["is_detailed"] = "true"
        return self._request(
            "GET",
            f"insight/event_count/{scoped_oid}/{safe_sensor_id}",
            operation="event.retention",
            oid=scoped_oid,
            resource={
                "type": "event_retention",
                "id": safe_sensor_id,
                "parent": {"type": "organization", "id": scoped_oid},
            },
            params=params,
        ).as_dict()

    def search_ioc(
        self,
        oid: str,
        obj_type: str,
        obj_name: str,
        info: str = "summary",
        case_sensitive: bool = True,
        wildcards: bool = False,
        limit: int = 100,
        per_object: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_obj_type = require_ioc_type(obj_type)
        safe_info = require_info_type(info)
        bounded_limit = require_limit(limit, maximum=1000)
        if not isinstance(obj_name, str) or not obj_name or len(obj_name) > 500 or "\x00" in obj_name:
            raise ValidationError("obj_name must be a non-empty indicator string under 500 characters")
        if per_object is None:
            per_object_value = wildcards and safe_info == "summary"
        else:
            per_object_value = per_object
        return self._request(
            "GET",
            f"insight/{scoped_oid}/objects/{quote(safe_obj_type, safe='')}",
            operation="ioc.search",
            oid=scoped_oid,
            resource={"type": "ioc_search", "id": safe_obj_type, "parent": {"type": "organization", "id": scoped_oid}},
            params={
                "name": obj_name,
                "info": safe_info,
                "case_sensitive": bool_param(case_sensitive),
                "with_wildcards": bool_param(wildcards),
                "per_object": bool_param(per_object_value),
                "limit": bounded_limit,
            },
            limit=bounded_limit,
        ).as_dict()

    def batch_search_iocs(
        self,
        oid: str,
        objects: dict[str, list[str]],
        info: str = "summary",
        case_sensitive: bool = True,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_objects = require_ioc_batch(objects)
        safe_info = require_info_type(info)
        bounded_limit = require_limit(limit, maximum=1000)
        params: dict[str, Any] = {
            "objects": json.dumps(safe_objects),
            "case_sensitive": bool_param(case_sensitive),
            "info": safe_info,
        }
        if safe_info == "locations":
            params["limit"] = bounded_limit
        return self._request(
            "POST",
            f"insight/{scoped_oid}/objects",
            operation="ioc.batch_search",
            oid=scoped_oid,
            resource={"type": "ioc_batch_search", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_object_information(
        self,
        oid: str,
        obj_type: str,
        obj_name: str,
        info: str = "summary",
        case_sensitive: bool = True,
        wildcards: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        result = self.search_ioc(
            oid,
            obj_type,
            obj_name,
            info=info,
            case_sensitive=case_sensitive,
            wildcards=wildcards,
            limit=limit,
        )
        result["operation"] = "ioc.object_info"
        return result

    def get_insight_status(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        result = self._request(
            "GET",
            f"insight/{scoped_oid}",
            operation="insight.status",
            oid=scoped_oid,
            resource={"type": "insight_status", "id": scoped_oid},
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            result["state"] = {
                "current": "enabled" if result["data"].get("insight_bucket") else "unknown_or_disabled",
                "enabled": bool(result["data"].get("insight_bucket")),
            }
            result["meta"]["summary"]["enabled"] = bool(result["data"].get("insight_bucket"))
        return result

    def validate_search_query(
        self,
        oid: str,
        query: str,
        start: int | None = None,
        end: int | None = None,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        if start is None and end is None:
            end_ts = int(time.time())
            start_ts = end_ts - 86_400
        elif start is not None and end is not None:
            start_ts, end_ts = require_time_window(start, end)
        else:
            raise ValidationError("start and end must both be provided, or both omitted")
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        return self._request(
            "POST",
            "search/validate",
            operation="search.validate",
            oid=scoped_oid,
            resource={"type": "lcql_validation", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
        ).as_dict()

    def estimate_search_query(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        start_ts, end_ts = require_time_window(start, end)
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        result = self._request(
            "POST",
            "search/validate",
            operation="search.estimate",
            oid=scoped_oid,
            resource={"type": "lcql_estimate", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
        ).as_dict()
        if result.get("ok"):
            result["warnings"] = [
                "LimaCharlie exposes estimate data through the search validation endpoint for the supplied time window."
            ]
        return result

    def execute_search_query(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query = require_search_query(query)
        start_ts, end_ts = require_time_window(start, end)
        body = self._search_body(scoped_oid, safe_query, start_ts, end_ts, stream)
        body["paginated"] = True
        result = self._request(
            "POST",
            "search",
            operation="search.execute",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": scoped_oid},
            json_body=body,
            base_url=self._search_root(scoped_oid),
            side_effects=[{"type": "search_query_started", "resource": {"type": "organization", "id": scoped_oid}}],
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            query_id = result["data"].get("queryId") or result["data"].get("query_id")
            result["state"] = {
                "current": "running" if query_id else "unknown",
                "terminal": False,
                "query_id": query_id,
                "checkpoint": {"next_token": None},
            }
            result["meta"]["summary"]["query_id"] = query_id
            result["meta"]["suggested_next_actions"] = [
                "Call lc_poll_search_query with query_id to retrieve one bounded result page.",
                "Call lc_cancel_search_query when the search is no longer needed.",
            ]
        return result

    def poll_search_query(
        self,
        oid: str,
        query_id: str,
        token: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query_id = require_token(query_id, "query_id")
        bounded_limit = require_limit(limit)
        params = {"token": require_token(token, "token")} if token else None
        result = self._request(
            "GET",
            f"search/{quote(safe_query_id, safe='')}",
            operation="search.poll",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": safe_query_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=params,
            base_url=self._search_root(scoped_oid),
            limit=bounded_limit,
        ).as_dict()
        if result.get("ok"):
            self._finalize_search_poll(result, safe_query_id, bounded_limit)
        return result

    def cancel_search_query(self, oid: str, query_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_query_id = require_token(query_id, "query_id")
        result = self._request(
            "DELETE",
            f"search/{quote(safe_query_id, safe='')}",
            operation="search.cancel",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": safe_query_id, "parent": {"type": "organization", "id": scoped_oid}},
            base_url=self._search_root(scoped_oid),
            side_effects=[{"type": "search_query_cancelled", "resource": {"type": "lcql_search_job", "id": safe_query_id}}],
        ).as_dict()
        if result.get("ok"):
            result["state"] = {"current": "cancelled", "terminal": True, "query_id": safe_query_id}
        return result

    def list_saved_queries(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/query/{scoped_oid}",
            operation="saved_query.list",
            oid=scoped_oid,
            resource={"type": "saved_query_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def get_saved_query(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_hive_record_key(name, "name")
        return self._request(
            "GET",
            f"hive/query/{scoped_oid}/{quote(safe_name, safe='')}/data",
            operation="saved_query.get",
            oid=scoped_oid,
            resource={"type": "saved_query", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_saved_query(
        self,
        oid: str,
        name: str,
        query: str,
        start: int | None = None,
        end: int | None = None,
        stream: str | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_hive_record_key(name, "name")
        data: dict[str, Any] = {"query": require_search_query(query)}
        if start is not None or end is not None:
            if start is None or end is None:
                raise ValidationError("start and end must both be provided, or both omitted")
            start_ts, end_ts = require_time_window(start, end)
            data["start"] = start_ts
            data["end"] = end_ts
        safe_stream = require_search_stream(stream)
        if safe_stream:
            data["stream"] = safe_stream
        params = self._hive_record_params(data=data, tags=tags, comment=comment)
        return self._create_mutation_preview(
            operation="saved_query.set",
            oid=scoped_oid,
            method="POST",
            path=f"hive/query/{scoped_oid}/{quote(safe_name, safe='')}/data",
            resource={"type": "saved_query", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=params,
            data=None,
            json_body=None,
            expected_effect=f"Create or update saved query {safe_name!r}.",
            reversibility="Restore the prior saved query record or delete this record if it was newly created.",
            side_effects=[{"type": "saved_query_set", "resource": {"type": "saved_query", "id": safe_name}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_delete_saved_query(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_hive_record_key(name, "name")
        return self._create_mutation_preview(
            operation="saved_query.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/query/{scoped_oid}/{quote(safe_name, safe='')}",
            resource={"type": "saved_query", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=None,
            data=None,
            json_body=None,
            expected_effect=f"Delete saved query {safe_name!r}.",
            reversibility="Recreate the saved query from a known-good definition if deletion was unintended.",
            side_effects=[{"type": "saved_query_deleted", "resource": {"type": "saved_query", "id": safe_name}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def execute_saved_query(
        self,
        oid: str,
        name: str,
        start: int | None = None,
        end: int | None = None,
        stream: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_hive_record_key(name, "name")
        saved = self.get_saved_query(scoped_oid, safe_name)
        if not saved.get("ok"):
            saved["operation"] = "saved_query.execute"
            return saved
        raw_saved = saved.get("data") if isinstance(saved.get("data"), dict) else {}
        saved_data = raw_saved.get("data") if isinstance(raw_saved.get("data"), dict) else raw_saved
        if not isinstance(saved_data, dict):
            saved_data = {}
        query = saved_data.get("query")
        if not isinstance(query, str) or not query.strip():
            return self._saved_query_input_error(scoped_oid, safe_name, "saved_query_missing_query", "Saved query record does not contain a non-empty query field.")
        effective_start = start if start is not None else saved_data.get("start")
        effective_end = end if end is not None else saved_data.get("end")
        if effective_start is None or effective_end is None:
            return self._saved_query_input_error(
                scoped_oid,
                safe_name,
                "saved_query_missing_time_window",
                "Saved query execution requires start and end unix-second timestamps from the saved record or tool inputs.",
            )
        start_ts, end_ts = require_time_window(effective_start, effective_end)
        safe_stream = require_search_stream(stream) or require_search_stream(saved_data.get("stream"))
        body = self._search_body(scoped_oid, query, start_ts, end_ts, safe_stream)
        body["paginated"] = True
        result = self._request(
            "POST",
            "search",
            operation="saved_query.execute",
            oid=scoped_oid,
            resource={"type": "lcql_search_job", "id": safe_name, "parent": {"type": "saved_query", "id": safe_name}},
            json_body=body,
            base_url=self._search_root(scoped_oid),
            side_effects=[{"type": "search_query_started", "resource": {"type": "saved_query", "id": safe_name}}],
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            query_id = result["data"].get("queryId") or result["data"].get("query_id")
            result["state"] = {
                "current": "running" if query_id else "unknown",
                "terminal": False,
                "query_id": query_id,
                "checkpoint": {"next_token": None},
                "saved_query": safe_name,
            }
            result["meta"]["summary"]["query_id"] = query_id
            result["meta"]["summary"]["saved_query"] = safe_name
            result["meta"]["suggested_next_actions"] = [
                "Call lc_poll_search_query with query_id to retrieve one bounded result page.",
                "Call lc_cancel_search_query when the search is no longer needed.",
            ]
        return result

    def _saved_query_input_error(self, oid: str, name: str, code: str, message: str) -> dict[str, Any]:
        return ToolResponse(
            ok=False,
            operation="saved_query.execute",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "saved_query", "id": name, "parent": {"type": "organization", "id": oid}},
            state={"current": "invalid", "terminal": True},
            data=None,
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "empty"}, "truncated": False},
            observed_at=observed_at(),
            error={
                "code": code,
                "class": "input",
                "message": message,
                "retryable": False,
                "same_input_retryable": False,
                "suggested_next_actions": [
                    "Call lc_get_saved_query to inspect the saved query record.",
                    "Call lc_preview_set_saved_query with a query plus start and end, then confirm it.",
                    "Call lc_execute_search_query with explicit query, start, and end instead.",
                ],
            },
        ).as_dict()

    def validate_replay_rule(
        self,
        oid: str,
        rule_content: dict[str, Any],
        trace: bool = False,
        limit_events: int = 1,
        limit_evals: int = 1000,
    ) -> dict[str, Any]:
        return self.replay_scan_events(
            oid=oid,
            events=[{"event": {}, "routing": {}}],
            rule_content=rule_content,
            trace=trace,
            limit_events=limit_events,
            limit_evals=limit_evals,
            stream="event",
            operation="replay.validate_rule",
            resource_type="replay_validation",
        )

    def replay_scan_events(
        self,
        oid: str,
        events: list[dict[str, Any]],
        rule_name: str | None = None,
        namespace: str | None = None,
        rule_content: dict[str, Any] | None = None,
        trace: bool = False,
        limit_events: int = 100,
        limit_evals: int = 1000,
        stream: str = "event",
        *,
        operation: str = "replay.scan_events",
        resource_type: str = "replay_result",
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_events = require_dict_list(events, "events", maximum=100) or []
        checked_rule = require_dict(rule_content, "rule_content")
        if not rule_name and checked_rule is None:
            raise ValidationError("rule_name or rule_content is required")
        bounded_limit_events = require_seconds(limit_events, "limit_events", minimum=1, maximum=1000)
        bounded_limit_evals = require_seconds(limit_evals, "limit_evals", minimum=1, maximum=100_000)
        body = {
            "oid": scoped_oid,
            "rule_source": {
                "rule_name": require_token(rule_name, "rule_name") if rule_name else "",
                "namespace": require_dr_namespace(namespace) if namespace else "",
                "rule": checked_rule,
            },
            "event_source": {
                "stream": require_search_stream(stream) or "event",
                "sensor_events": {},
                "events": checked_events,
            },
            "trace": bool(trace),
            "limit_event": bounded_limit_events,
            "limit_eval": bounded_limit_evals,
            "is_dry_run": True,
        }
        return self._request(
            "POST",
            "",
            operation=operation,
            oid=scoped_oid,
            resource={"type": resource_type, "id": scoped_oid},
            json_body=body,
            base_url=self._replay_root(scoped_oid),
        ).as_dict()

    def replay_dry_run(
        self,
        oid: str,
        start: int,
        end: int,
        rule_name: str | None = None,
        detect: dict[str, Any] | None = None,
        respond: list[dict[str, Any]] | None = None,
        sensor_id: str | None = None,
        selector: str | None = None,
        stream: str = "event",
        trace: bool = False,
        limit_events: int = 1000,
        limit_evals: int = 10_000,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        start_ts, end_ts = require_time_window(start, end)
        safe_rule_name = require_token(rule_name, "rule_name") if rule_name else None
        checked_detect = require_dict(detect, "detect")
        checked_respond = require_dict_list(respond, "respond", maximum=100)
        if not safe_rule_name and checked_detect is None and checked_respond is None:
            raise ValidationError("rule_name or detect/respond rule content is required")
        sensor_events: dict[str, Any] = {"start_time": start_ts, "end_time": end_ts}
        if sensor_id:
            sensor_events["sid"] = require_oid(sensor_id)
        if selector:
            sensor_events["selector"] = require_selector(selector)
        rule_source: dict[str, Any] = {}
        if safe_rule_name:
            rule_source["rule_name"] = safe_rule_name
        if checked_detect is not None or checked_respond is not None:
            rule_source["rule"] = {}
            if checked_detect is not None:
                rule_source["rule"]["detect"] = checked_detect
            if checked_respond is not None:
                rule_source["rule"]["respond"] = checked_respond
        body = {
            "oid": scoped_oid,
            "rule_source": rule_source,
            "event_source": {
                "stream": require_search_stream(stream) or "event",
                "sensor_events": sensor_events,
            },
            "trace": bool(trace),
            "is_dry_run": True,
            "limit_event": require_seconds(limit_events, "limit_events", minimum=1, maximum=100_000),
            "limit_eval": require_seconds(limit_evals, "limit_evals", minimum=1, maximum=1_000_000),
        }
        return self._request(
            "POST",
            "",
            operation="replay.run_dry",
            oid=scoped_oid,
            resource={"type": "replay_result", "id": scoped_oid},
            json_body=body,
            base_url=self._replay_root(scoped_oid),
        ).as_dict()

    def list_artifacts(
        self,
        oid: str,
        sensor_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {}
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        if cursor:
            params["cursor"] = require_token(cursor, "cursor")
        else:
            if start is None or end is None:
                raise ValidationError("start and end are required when cursor is not provided")
            start_ts, end_ts = require_time_window(start, end)
            params["start"] = start_ts
            params["end"] = end_ts
        return self._request(
            "GET",
            f"insight/{scoped_oid}/artifacts",
            operation="artifact.list",
            oid=scoped_oid,
            resource={"type": "artifact_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_artifact_url(self, oid: str, artifact_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_artifact_id = require_path_segment(artifact_id, "artifact_id")
        return self._request(
            "POST",
            f"insight/{scoped_oid}/artifacts/originals/{quote(safe_artifact_id, safe='')}",
            operation="artifact.get_url",
            oid=scoped_oid,
            resource={"type": "artifact", "id": safe_artifact_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def list_payloads(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"payload/{scoped_oid}",
            operation="payload.list",
            oid=scoped_oid,
            resource={"type": "payload_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def get_payload_download_url(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"payload/{scoped_oid}/{quote(safe_name, safe='')}",
            operation="payload.get_url",
            oid=scoped_oid,
            resource={"type": "payload", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_payload_upload_url(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="payload.upload_url",
            oid=scoped_oid,
            method="POST",
            path=f"payload/{scoped_oid}/{quote(safe_name, safe='')}",
            resource_type="payload",
            resource_id=safe_name,
            expected_effect=f"Request a signed upload URL for payload {safe_name!r}. Binary bytes are not uploaded by this MCP tool.",
            reversibility="No payload bytes are uploaded by this operation; discard the signed URL if it was requested unintentionally.",
            side_effect_type="payload_upload_url_requested",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_payload(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="payload.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"payload/{scoped_oid}/{quote(safe_name, safe='')}",
            resource_type="payload",
            resource_id=safe_name,
            expected_effect=f"Delete payload {safe_name!r}.",
            reversibility="Re-upload the payload from a known-good binary if deletion was unintended.",
            side_effect_type="payload_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def get_arl(self, oid: str, arl_url: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_arl = require_arl(arl_url)
        return self._request(
            "GET",
            f"arl/{scoped_oid}",
            operation="arl.get",
            oid=scoped_oid,
            resource={"type": "authenticated_resource_locator", "id": scoped_oid},
            params={"arl": safe_arl},
            limit=bounded_limit,
        ).as_dict()

    def list_jobs(
        self,
        oid: str,
        start: int,
        end: int,
        sensor_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "is_compressed": "true",
            "with_data": "false",
            "start": start_ts,
            "end": end_ts,
            "limit": bounded_limit,
        }
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        return self._request(
            "GET",
            f"job/{scoped_oid}",
            operation="job.list",
            oid=scoped_oid,
            resource={"type": "job_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_job(self, oid: str, job_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        return self._request(
            "GET",
            f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
            operation="job.get",
            oid=scoped_oid,
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def wait_job(
        self,
        oid: str,
        job_id: str,
        timeout_seconds: int = 60,
        poll_interval_seconds: int = 5,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        timeout = require_seconds(timeout_seconds, "timeout_seconds", minimum=1, maximum=600)
        poll_interval = require_seconds(poll_interval_seconds, "poll_interval_seconds", minimum=1, maximum=30)
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        attempts = 0
        last_result: dict[str, Any] | None = None
        last_state = {"current": "unknown", "terminal": False}
        while True:
            attempts += 1
            result = self._request(
                "GET",
                f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
                operation="job.wait",
                oid=scoped_oid,
                resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            ).as_dict()
            last_result = result
            if not result["ok"]:
                result["meta"]["attempts"] = attempts
                return result
            last_state = normalize_job_state(result.get("data"))
            if last_state["terminal"]:
                duration_ms = int((time.time() - started) * 1000)
                result["request_id"] = request_id
                result["state"] = last_state
                result["meta"]["duration_ms"] = duration_ms
                result["meta"]["attempts"] = attempts
                result["meta"]["summary"]["job_state"] = last_state["current"]
                return result
            elapsed = time.time() - started
            if elapsed + poll_interval > timeout:
                break
            time.sleep(poll_interval)

        duration_ms = int((time.time() - started) * 1000)
        return ToolResponse(
            ok=False,
            operation="job.wait",
            request_id=request_id,
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            state=last_state,
            data={"last_observation": last_result.get("data") if last_result else None},
            side_effects=[],
            warnings=[],
            meta={
                "duration_ms": duration_ms,
                "attempts": attempts,
                "summary": {"job_state": last_state["current"], "timed_out": True},
                "truncated": False,
            },
            observed_at=observed_at(),
            error={
                "code": "job_wait_timeout",
                "class": "transient",
                "message": f"Job {safe_job_id} did not reach a terminal state within {timeout} seconds.",
                "retryable": True,
                "same_input_retryable": True,
                "suggested_next_actions": [
                    "Call lc_get_job to inspect the latest job state.",
                    "Retry lc_wait_job with a longer timeout if the job is expected to continue.",
                ],
            },
        ).as_dict()

    def preview_delete_job(self, oid: str, job_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_job_id = require_path_segment(job_id, "job_id")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="job.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"job/{scoped_oid}/{quote(safe_job_id, safe='')}",
            resource={"type": "job", "id": safe_job_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete job record {safe_job_id}.",
            reversibility="Deletion is not generally reversible; list jobs again to verify current state.",
            side_effects=[{"type": "job_deleted", "resource": {"type": "job", "id": safe_job_id}}],
            token_ttl_seconds=token_ttl,
        )

    def list_reliable_tasks(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            "extension/request/ext-reliable-tasking",
            operation="reliable_task.list",
            oid=scoped_oid,
            resource={"type": "reliable_task_collection", "id": scoped_oid, "parent": {"type": "organization", "id": scoped_oid}},
            params=extension_request_params(scoped_oid, "list", {}),
            limit=bounded_limit,
        ).as_dict()

    def preview_reliable_task(
        self,
        oid: str,
        task: str,
        sensor_id: str | None = None,
        selector: str | None = None,
        context: str | None = None,
        ttl_seconds: int | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        if sensor_id and selector:
            raise ValidationError("provide either sensor_id or selector, not both")
        checked_tasks = require_sensor_tasks(task)
        safe_task = checked_tasks[0]
        request_data: dict[str, Any] = {"task": safe_task}
        resource_id = scoped_oid
        if sensor_id:
            safe_sensor_id = require_oid(sensor_id)
            request_data["selector"] = f"sid=='{safe_sensor_id}'"
            resource_id = safe_sensor_id
        if selector:
            safe_selector = require_selector(selector)
            request_data["selector"] = safe_selector
            resource_id = safe_selector
        if context:
            request_data["context"] = require_token(context, "context")
        if ttl_seconds is not None:
            request_data["ttl"] = require_seconds(ttl_seconds, "ttl_seconds", minimum=60, maximum=2_592_000)
        return self._preview_mutation(
            operation="reliable_task.send",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-reliable-tasking",
            resource_type="reliable_task",
            resource_id=resource_id,
            params=extension_request_params(scoped_oid, "task", request_data),
            expected_effect="Queue one reliable task through ext-reliable-tasking.",
            reversibility="Cancel the pending reliable task by task ID if the extension returns or lists it.",
            side_effect_type="reliable_task_queued",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_reliable_task(
        self,
        oid: str,
        task_id: str,
        sensor_id: str | None = None,
        selector: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        if sensor_id and selector:
            raise ValidationError("provide either sensor_id or selector, not both")
        safe_task_id = require_path_segment(task_id, "task_id")
        request_data: dict[str, Any] = {"task_id": safe_task_id}
        if sensor_id:
            request_data["sid"] = require_oid(sensor_id)
        if selector:
            request_data["selector"] = require_selector(selector)
        return self._preview_mutation(
            operation="reliable_task.delete",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-reliable-tasking",
            resource_type="reliable_task",
            resource_id=safe_task_id,
            params=extension_request_params(scoped_oid, "untask", request_data),
            expected_effect=f"Cancel reliable task {safe_task_id}.",
            reversibility="Recreate the reliable task if cancellation was unintended.",
            side_effect_type="reliable_task_cancelled",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_audit_logs(
        self,
        oid: str,
        start: int,
        end: int,
        event_type: str | None = None,
        sensor_id: str | None = None,
        limit: int = 100,
        cursor: str = "-",
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        start_ts, end_ts = require_time_window(start, end)
        params: dict[str, Any] = {
            "start": start_ts,
            "end": end_ts,
            "cursor": require_token(cursor, "cursor"),
            "is_compressed": "true",
            "limit": bounded_limit,
        }
        if event_type:
            params["event_type"] = require_token(event_type, "event_type")
        if sensor_id:
            params["sid"] = require_oid(sensor_id)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/audit",
            operation="audit.list",
            oid=scoped_oid,
            resource={"type": "audit_log_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def list_tags(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"tags/{scoped_oid}",
            operation="tag.list",
            oid=scoped_oid,
            resource={"type": "tag_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def _normalize_sensor_tags(self, sensor_id: str, payload: Any) -> list[str]:
        if not isinstance(payload, dict):
            return []
        tags_data = payload.get("tags")
        if isinstance(tags_data, dict):
            sid_tags = tags_data.get(sensor_id, tags_data)
            if isinstance(sid_tags, dict):
                return [str(tag) for tag in sid_tags]
            if isinstance(sid_tags, list):
                return [str(tag) for tag in sid_tags]
            return []
        if isinstance(tags_data, list):
            return [str(tag) for tag in tags_data]
        return []

    def list_sensor_tags(self, oid: str, sensor_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        result = self._request(
            "GET",
            f"{safe_sensor_id}/tags",
            operation="sensor.tag.list",
            oid=scoped_oid,
            resource={"type": "sensor_tag_collection", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()
        if result.get("ok"):
            raw = result.get("data")
            tags = self._normalize_sensor_tags(safe_sensor_id, raw)
            result["data"] = {"sid": safe_sensor_id, "tags": tags, "raw": raw}
            result["meta"]["summary"]["tag_count"] = len(tags)
        return result

    def find_sensors_by_tag(self, oid: str, tag: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_tag = require_token(tag, "tag")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"tags/{scoped_oid}/{quote(safe_tag, safe='')}",
            operation="tag.sensor_search",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": safe_tag, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def find_sensors_by_hostname(self, oid: str, hostname: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_hostname = require_token(hostname, "hostname")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hostnames/{scoped_oid}",
            operation="sensor.hostname_search",
            oid=scoped_oid,
            resource={"type": "sensor_collection", "id": safe_hostname, "parent": {"type": "organization", "id": scoped_oid}},
            params={"hostname": safe_hostname},
            limit=bounded_limit,
        ).as_dict()

    def export_sensors(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "POST",
            f"export/{scoped_oid}/sensors",
            operation="sensor.export",
            oid=scoped_oid,
            resource={"type": "sensor_export", "id": scoped_oid},
        ).as_dict()

    def preview_set_sensor_version(
        self,
        oid: str,
        version: str | None = None,
        is_fallback: bool = False,
        is_sleep: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        params: dict[str, Any] = {}
        if version:
            params["specific_version"] = require_token(version, "version")
        if is_fallback:
            params["is_fallback"] = "true"
        if is_sleep:
            params["is_sleep"] = "true"
        if not params:
            raise ValidationError("version, is_fallback, or is_sleep is required")
        return self._preview_mutation(
            operation="sensor.version.set",
            oid=scoped_oid,
            method="POST",
            path=f"modules/{scoped_oid}",
            resource_type="sensor_version_policy",
            resource_id=scoped_oid,
            params=params,
            expected_effect="Change the organization's sensor version policy.",
            reversibility="Run another sensor version preview with the prior policy value.",
            side_effect_type="sensor_version_policy_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_available_services(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"service/{scoped_oid}",
            operation="service.list",
            oid=scoped_oid,
            resource={"type": "service_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_service_request(
        self,
        oid: str,
        service_name: str,
        request_data: dict[str, Any],
        is_async: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_service = require_path_segment(service_name, "service_name")
        checked_data = require_dict(request_data, "request_data")
        if checked_data is None:
            raise ValidationError("request_data is required")
        return self._preview_service_request(
            operation="service.request",
            oid=scoped_oid,
            service=safe_service,
            request_data=checked_data,
            resource_type="service_request",
            resource_id=safe_service,
            expected_effect=f"Send a request to service {safe_service!r}.",
            reversibility="Service request effects depend on the selected service/action.",
            side_effect_type="service_request_sent",
            token_ttl_seconds=token_ttl_seconds,
            is_async=is_async,
        )

    def preview_spotcheck_run(
        self,
        oid: str,
        task: str,
        tag: str | None = None,
        selector: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_task = require_case_text(task, "task", maximum=8192, required=True)
        assert checked_task is not None
        request_data: dict[str, Any] = {"action": "spotcheck", "task": checked_task}
        checked_tag = require_case_text(tag, "tag", maximum=1000)
        if checked_tag is not None:
            if not checked_tag.strip():
                raise ValidationError("tag must be non-empty when provided")
            request_data["tag"] = checked_tag
        checked_selector = require_selector(selector)
        if checked_selector is not None:
            request_data["selector"] = checked_selector
        return self._preview_service_request(
            operation="spotcheck.run",
            oid=scoped_oid,
            service="spotcheck",
            request_data=request_data,
            resource_type="spotcheck_run",
            resource_id=scoped_oid,
            expected_effect="Run an ad-hoc spotcheck sensor task across the selected fleet scope.",
            reversibility="Spotcheck tasking is not reversible; review returned results and issue compensating tasks if needed.",
            side_effect_type="spotcheck_requested",
            token_ttl_seconds=token_ttl_seconds,
        )

    def _config_sync_options(
        self,
        *,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
    ) -> dict[str, Any]:
        if sync_hives is not None:
            if not isinstance(sync_hives, dict):
                raise ValidationError("sync_hives must be an object of hive names to booleans")
            checked_hives = {require_token(str(name), "hive_name"): bool(value) for name, value in sync_hives.items()}
        else:
            checked_hives = {}
        return {
            "sync_outputs": bool(sync_outputs),
            "sync_resources": bool(sync_resources),
            "sync_extensions": bool(sync_extensions),
            "sync_integrity": bool(sync_integrity),
            "sync_exfil": bool(sync_exfil),
            "sync_artifacts": bool(sync_artifact),
            "sync_org_values": bool(sync_org_values),
            "sync_hives": checked_hives,
            "sync_installation_keys": bool(sync_installation_keys),
            "sync_yara": bool(sync_yara),
        }

    def fetch_config(
        self,
        oid: str,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        options = self._config_sync_options(
            sync_outputs=sync_outputs,
            sync_integrity=sync_integrity,
            sync_artifact=sync_artifact,
            sync_exfil=sync_exfil,
            sync_resources=sync_resources,
            sync_extensions=sync_extensions,
            sync_org_values=sync_org_values,
            sync_hives=sync_hives,
            sync_installation_keys=sync_installation_keys,
            sync_yara=sync_yara,
        )
        return self._request(
            "POST",
            "extension/request/ext-infrastructure",
            operation="config.fetch",
            oid=scoped_oid,
            resource={"type": "infrastructure_config", "id": scoped_oid},
            params=extension_request_params(scoped_oid, "fetch", {"options": options}),
        ).as_dict()

    def preview_push_config(
        self,
        oid: str,
        config: dict[str, Any],
        is_force: bool = False,
        is_dry_run: bool = False,
        ignore_inaccessible: bool = False,
        sync_outputs: bool = False,
        sync_integrity: bool = False,
        sync_artifact: bool = False,
        sync_exfil: bool = False,
        sync_resources: bool = False,
        sync_extensions: bool = False,
        sync_org_values: bool = False,
        sync_hives: dict[str, bool] | None = None,
        sync_installation_keys: bool = False,
        sync_yara: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        checked_config = require_dict(config, "config")
        if checked_config is None:
            raise ValidationError("config is required")
        options = self._config_sync_options(
            sync_outputs=sync_outputs,
            sync_integrity=sync_integrity,
            sync_artifact=sync_artifact,
            sync_exfil=sync_exfil,
            sync_resources=sync_resources,
            sync_extensions=sync_extensions,
            sync_org_values=sync_org_values,
            sync_hives=sync_hives,
            sync_installation_keys=sync_installation_keys,
            sync_yara=sync_yara,
        )
        options.update(
            {
                "is_dry_run": bool(is_dry_run),
                "is_force": bool(is_force),
                "ignore_inaccessible": bool(ignore_inaccessible),
            }
        )
        params = extension_request_params(
            scoped_oid,
            "push",
            {"config": json.dumps(checked_config, sort_keys=True), "options": options},
        )
        return self._preview_mutation(
            operation="config.push",
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-infrastructure",
            resource_type="infrastructure_config",
            resource_id=scoped_oid,
            params=params,
            expected_effect="Push infrastructure configuration through ext-infrastructure.",
            reversibility="Restore from a prior config export, or use is_dry_run before applying.",
            side_effect_type="infrastructure_config_pushed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_exfil_rules(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "POST",
            f"service/{scoped_oid}/exfil",
            operation="exfil_rule.list",
            oid=scoped_oid,
            resource={"type": "exfil_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
        ).as_dict()

    def preview_create_exfil_watch(
        self,
        oid: str,
        name: str,
        event: str,
        value: str,
        operator: str,
        path: str | list[str],
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_watch",
            "name": safe_name,
            "event": require_token(event, "event"),
            "value": require_token(value, "value"),
            "operator": require_token(operator, "operator"),
            "path": require_exfil_path(path),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="exfil_watch.create",
            oid=oid,
            service="exfil",
            request_data=request_data,
            resource_type="exfil_watch",
            resource_id=safe_name,
            expected_effect=f"Create exfil watch rule {safe_name!r}.",
            reversibility="Delete the exfil watch rule if creation was unintended.",
            side_effect_type="exfil_watch_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_create_exfil_event(
        self,
        oid: str,
        name: str,
        events: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        checked_events = require_string_list(events, "events")
        if not checked_events:
            raise ValidationError("events are required")
        request_data: dict[str, Any] = {"action": "add_event_rule", "name": safe_name, "events": checked_events}
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="exfil_event.create",
            oid=oid,
            service="exfil",
            request_data=request_data,
            resource_type="exfil_event_rule",
            resource_id=safe_name,
            expected_effect=f"Create exfil event rule {safe_name!r}.",
            reversibility="Delete the exfil event rule if creation was unintended.",
            side_effect_type="exfil_event_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_exfil_event(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="exfil_event.delete",
            oid=oid,
            service="exfil",
            request_data={"action": "remove_event_rule", "name": safe_name},
            resource_type="exfil_event_rule",
            resource_id=safe_name,
            expected_effect=f"Delete exfil event rule {safe_name!r}.",
            reversibility="Recreate the exfil event rule from a known-good backup.",
            side_effect_type="exfil_event_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_exfil_watch(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="exfil_watch.delete",
            oid=oid,
            service="exfil",
            request_data={"action": "remove_watch", "name": safe_name},
            resource_type="exfil_watch",
            resource_id=safe_name,
            expected_effect=f"Delete exfil watch rule {safe_name!r}.",
            reversibility="Recreate the exfil watch rule from a known-good backup.",
            side_effect_type="exfil_watch_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_feedback_channels(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"hive/extension_config/{scoped_oid}/ext-feedback/data",
            operation="feedback.channel.list",
            oid=scoped_oid,
            resource={"type": "feedback_channel_collection", "id": scoped_oid},
        ).as_dict()

    def preview_set_feedback_channels(
        self,
        oid: str,
        channels: list[dict[str, Any]],
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        checked_channels = require_dict_list(channels, "channels", maximum=50)
        if checked_channels is None:
            raise ValidationError("channels are required")
        for channel in checked_channels:
            require_token(str(channel.get("name", "")), "channel.name")
            channel_type = str(channel.get("channel_type", ""))
            if channel_type not in {"web", "slack", "email", "telegram", "ms_teams"}:
                raise ValidationError("channel_type must be one of: web, slack, email, telegram, ms_teams")
        return self._preview_hive_set(
            operation="feedback.channel.set",
            oid=oid,
            hive_name="extension_config",
            name="ext-feedback",
            data={"channels": checked_channels},
            resource_type="feedback_channel_collection",
            enabled=None,
            tags=None,
            comment=None,
            expiry=None,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _feedback_request_data(
        self,
        *,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None,
        playbook_name: str | None,
    ) -> dict[str, Any]:
        destination = str(feedback_destination)
        if destination not in {"case", "playbook"}:
            raise ValidationError("feedback_destination must be case or playbook")
        data: dict[str, Any] = {
            "channel": require_token(channel, "channel"),
            "question": require_case_text(question, "question", maximum=4000, required=True),
            "feedback_destination": destination,
        }
        if destination == "case":
            if case_id is None:
                raise ValidationError("case_id is required when feedback_destination is case")
            data["case_id"] = require_case_number(case_id)
        if destination == "playbook":
            if playbook_name is None:
                raise ValidationError("playbook_name is required when feedback_destination is playbook")
            data["playbook_name"] = require_token(playbook_name, "playbook_name")
        return data

    def _preview_feedback_request(
        self,
        *,
        oid: str,
        action: str,
        operation: str,
        data: dict[str, Any],
        resource_id: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path="extension/request/ext-feedback",
            resource={"type": "feedback_request", "id": resource_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=extension_request_params(scoped_oid, action, data),
            data=None,
            json_body=None,
            expected_effect=f"Send ext-feedback {action} request to channel {data.get('channel')!r}.",
            reversibility="Feedback requests may notify external systems and cannot generally be withdrawn.",
            side_effects=[{"type": "feedback_request_sent", "resource": {"type": "feedback_request", "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_feedback_simple_approval(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        approved_content: dict[str, Any] | None = None,
        denied_content: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        timeout_choice: str | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if approved_content is not None:
            data["approved_content"] = require_dict(approved_content, "approved_content")
        if denied_content is not None:
            data["denied_content"] = require_dict(denied_content, "denied_content")
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
            if timeout_choice not in {"approved", "denied"}:
                raise ValidationError("timeout_choice must be approved or denied when timeout_seconds is set")
            data["timeout_choice"] = timeout_choice
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_simple_approval",
            operation="feedback.approval",
            data=data,
            resource_id=f"{data['channel']}:approval",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_feedback_acknowledgement(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        acknowledged_content: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if acknowledged_content is not None:
            data["acknowledged_content"] = require_dict(acknowledged_content, "acknowledged_content")
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_acknowledgement",
            operation="feedback.acknowledgement",
            data=data,
            resource_id=f"{data['channel']}:acknowledgement",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_feedback_question(
        self,
        oid: str,
        channel: str,
        question: str,
        feedback_destination: str,
        case_id: str | None = None,
        playbook_name: str | None = None,
        timeout_seconds: int | None = None,
        timeout_content: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        data = self._feedback_request_data(
            channel=channel,
            question=question,
            feedback_destination=feedback_destination,
            case_id=case_id,
            playbook_name=playbook_name,
        )
        if timeout_seconds is not None:
            data["timeout_seconds"] = require_seconds(timeout_seconds, "timeout_seconds", minimum=60, maximum=2_592_000)
            if timeout_content is None:
                raise ValidationError("timeout_content is required when timeout_seconds is set for a question")
        if timeout_content is not None:
            data["timeout_content"] = require_dict(timeout_content, "timeout_content")
        return self._preview_feedback_request(
            oid=oid,
            action="request_question",
            operation="feedback.question",
            data=data,
            resource_id=f"{data['channel']}:question",
            token_ttl_seconds=token_ttl_seconds,
        )

    def _hive_context(self, oid: str, hive_name: str, partition_key: str | None) -> tuple[str, str, str]:
        scoped_oid = require_oid(oid)
        safe_hive = require_hive_name(hive_name)
        partition = require_hive_partition(partition_key, scoped_oid)
        return scoped_oid, safe_hive, partition

    def _hive_record_params(
        self,
        *,
        data: Any | None = None,
        arl_url: str | None = None,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        data_required: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if data is not None:
            params["data"] = json.dumps(require_json_size(data, "data"))
        elif data_required:
            raise ValidationError("data is required")
        if arl_url is not None:
            params["arl"] = require_arl(arl_url)
        usr_mtd: dict[str, Any] = {}
        if enabled is not None:
            usr_mtd["enabled"] = require_bool_or_none(enabled, "enabled")
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            usr_mtd["tags"] = checked_tags
        if comment is not None:
            checked_comment = require_case_text(comment, "comment", maximum=1000, required=False)
            if checked_comment is not None:
                usr_mtd["comment"] = checked_comment
        if expiry is not None:
            usr_mtd["expiry"] = require_unix_seconds(expiry, "expiry")
        checked_ui_actions = require_dict_list(ui_actions, "ui_actions", maximum=50)
        if checked_ui_actions is not None:
            usr_mtd["ui_actions"] = checked_ui_actions
        if usr_mtd:
            params["usr_mtd"] = json.dumps(usr_mtd)
        if etag is not None:
            params["etag"] = require_token(etag, "etag")
        return params

    def _hive_record_resource(self, hive_name: str, partition: str, key: str) -> dict[str, Any]:
        return {"type": "hive_record", "id": f"{hive_name}:{partition}:{key}"}

    def _typed_hive_record_resource(self, resource_type: str, oid: str, key: str) -> dict[str, Any]:
        return {"type": resource_type, "id": key, "parent": {"type": "organization", "id": oid}}

    def list_hive_types(self) -> dict[str, Any]:
        return self._local_response(
            "hive.type.list",
            {"hive_types": list(_KNOWN_HIVE_TYPES)},
            resource={"type": "hive_type_collection", "id": "known"},
        )

    def list_hive_records(
        self,
        oid: str,
        hive_name: str,
        partition_key: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}",
            operation="hive.record.list",
            oid=scoped_oid,
            resource={"type": "hive_record_collection", "id": f"{safe_hive}:{partition}"},
            limit=bounded_limit,
        ).as_dict()

    def get_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        partition_key: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        return self._request(
            "GET",
            f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/data",
            operation="hive.record.get",
            oid=scoped_oid,
            resource=self._hive_record_resource(safe_hive, partition, safe_key),
        ).as_dict()

    def get_hive_record_metadata(
        self,
        oid: str,
        hive_name: str,
        key: str,
        partition_key: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        return self._request(
            "GET",
            f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/mtd",
            operation="hive.record.metadata.get",
            oid=scoped_oid,
            resource={"type": "hive_record_metadata", "id": f"{safe_hive}:{partition}:{safe_key}"},
        ).as_dict()

    def get_hive_schema(self, hive_name: str) -> dict[str, Any]:
        safe_hive = require_hive_name(hive_name)
        return self._request(
            "GET",
            f"hive/{quote(safe_hive, safe='')}/schema",
            operation="hive.schema.get",
            oid="-",
            resource={"type": "hive_schema", "id": safe_hive},
        ).as_dict()

    def validate_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        data: Any,
        partition_key: str | None = None,
        arl_url: str | None = None,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        return self._request(
            "POST",
            f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/validate",
            operation="hive.record.validate",
            oid=scoped_oid,
            resource=self._hive_record_resource(safe_hive, partition, safe_key),
            params=self._hive_record_params(
                data=data,
                arl_url=arl_url,
                enabled=enabled,
                tags=tags,
                comment=comment,
                expiry=expiry,
                etag=etag,
                ui_actions=ui_actions,
                data_required=True,
            ),
        ).as_dict()

    def preview_set_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        data: Any | None = None,
        partition_key: str | None = None,
        arl_url: str | None = None,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        params = self._hive_record_params(
            data=data,
            arl_url=arl_url,
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
        )
        if not params:
            raise ValidationError("at least one of data, arl_url, enabled, tags, comment, expiry, etag, or ui_actions is required")
        target = "data" if data is not None or arl_url is not None else "mtd"
        return self._create_mutation_preview(
            operation="hive.record.set",
            oid=scoped_oid,
            method="POST",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/{target}",
            resource=self._hive_record_resource(safe_hive, partition, safe_key),
            params=params,
            data=None,
            json_body=None,
            expected_effect=f"Create or update hive record {safe_hive}/{partition}/{safe_key}.",
            reversibility="Restore the prior hive record value or delete this record if it was newly created.",
            side_effects=[{"type": "hive_record_set", "resource": self._hive_record_resource(safe_hive, partition, safe_key)}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_delete_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        return self._create_mutation_preview(
            operation="hive.record.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}",
            resource=self._hive_record_resource(safe_hive, partition, safe_key),
            params=None,
            data=None,
            json_body=None,
            expected_effect=f"Delete hive record {safe_hive}/{partition}/{safe_key}.",
            reversibility="Recreate the hive record from a known-good backup if deletion was unintended.",
            side_effects=[{"type": "hive_record_deleted", "resource": self._hive_record_resource(safe_hive, partition, safe_key)}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_rename_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        new_name: str,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        safe_new_name = require_hive_record_key(new_name, "new_name")
        return self._create_mutation_preview(
            operation="hive.record.rename",
            oid=scoped_oid,
            method="POST",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/rename",
            resource=self._hive_record_resource(safe_hive, partition, safe_key),
            params={"new_name": safe_new_name},
            data=None,
            json_body=None,
            expected_effect=f"Rename hive record {safe_hive}/{partition}/{safe_key} to {safe_new_name}.",
            reversibility="Rename the record back to its previous key if no conflicting record exists.",
            side_effects=[
                {
                    "type": "hive_record_renamed",
                    "resource": self._hive_record_resource(safe_hive, partition, safe_key),
                    "new_name": safe_new_name,
                }
            ],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_set_hive_record_enabled(
        self,
        oid: str,
        hive_name: str,
        key: str,
        enabled: bool,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, partition_key)
        safe_key = require_hive_record_key(key)
        checked_enabled = require_bool_or_none(enabled, "enabled")
        metadata_result = self.get_hive_record_metadata(scoped_oid, safe_hive, safe_key, partition_key=partition)
        if not metadata_result.get("ok"):
            metadata_result["operation"] = "hive.record.enabled.set.preview"
            return metadata_result
        metadata = metadata_result.get("data") if isinstance(metadata_result.get("data"), dict) else {}
        usr_mtd = dict(metadata.get("usr_mtd") or {}) if isinstance(metadata, dict) else {}
        sys_mtd = metadata.get("sys_mtd") if isinstance(metadata, dict) else {}
        usr_mtd["enabled"] = checked_enabled
        params = {"usr_mtd": json.dumps(usr_mtd)}
        if isinstance(sys_mtd, dict) and sys_mtd.get("etag"):
            params["etag"] = require_token(str(sys_mtd["etag"]), "etag")
        return self._create_mutation_preview(
            operation="hive.record.enabled.set",
            oid=scoped_oid,
            method="POST",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/mtd",
            resource={"type": "hive_record_metadata", "id": f"{safe_hive}:{partition}:{safe_key}"},
            params=params,
            data=None,
            json_body=None,
            expected_effect=f"Set enabled={checked_enabled} on hive record {safe_hive}/{partition}/{safe_key}, preserving current metadata.",
            reversibility="Preview and confirm the opposite enabled value if this change was unintended.",
            side_effects=[{"type": "hive_record_metadata_set", "resource": self._hive_record_resource(safe_hive, partition, safe_key)}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def _list_typed_hive_records(
        self,
        oid: str,
        hive_name: str,
        operation: str,
        resource_type: str,
        limit: int,
    ) -> dict[str, Any]:
        result = self.list_hive_records(oid, hive_name, limit=limit)
        result["operation"] = operation
        if result.get("resource"):
            result["resource"] = {"type": f"{resource_type}_collection", "id": require_oid(oid)}
        return result

    def _get_typed_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        operation: str,
        resource_type: str,
    ) -> dict[str, Any]:
        safe_key = require_hive_record_key(key, "name")
        result = self.get_hive_record(oid, hive_name, safe_key)
        result["operation"] = operation
        if result.get("resource"):
            result["resource"] = self._typed_hive_record_resource(resource_type, require_oid(oid), safe_key)
        return result

    def _preview_set_typed_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        data: dict[str, Any],
        operation: str,
        resource_type: str,
        side_effect_type: str,
        *,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, None)
        safe_key = require_hive_record_key(key, "name")
        params = self._hive_record_params(
            data=data,
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
        )
        resource = self._typed_hive_record_resource(resource_type, scoped_oid, safe_key)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/data",
            resource=resource,
            params=params,
            data=None,
            json_body=None,
            expected_effect=f"Create or update {resource_type} {safe_key}.",
            reversibility=f"Restore the prior {resource_type} value or preview and confirm deletion if it was newly created.",
            side_effects=[{"type": side_effect_type, "resource": resource}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def _preview_delete_typed_hive_record(
        self,
        oid: str,
        hive_name: str,
        key: str,
        operation: str,
        resource_type: str,
        side_effect_type: str,
        *,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, None)
        safe_key = require_hive_record_key(key, "name")
        resource = self._typed_hive_record_resource(resource_type, scoped_oid, safe_key)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}",
            resource=resource,
            params=None,
            data=None,
            json_body=None,
            expected_effect=f"Delete {resource_type} {safe_key}.",
            reversibility=f"Recreate {resource_type} {safe_key} from a known-good backup if deletion was unintended.",
            side_effects=[{"type": side_effect_type, "resource": resource}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def _preview_set_typed_hive_record_enabled(
        self,
        oid: str,
        hive_name: str,
        key: str,
        enabled: bool,
        operation: str,
        resource_type: str,
        side_effect_type: str,
        *,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid, safe_hive, partition = self._hive_context(oid, hive_name, None)
        safe_key = require_hive_record_key(key, "name")
        checked_enabled = require_bool_or_none(enabled, "enabled")
        metadata_result = self.get_hive_record_metadata(scoped_oid, safe_hive, safe_key, partition_key=partition)
        if not metadata_result.get("ok"):
            metadata_result["operation"] = f"{operation}.preview"
            return metadata_result
        metadata = metadata_result.get("data") if isinstance(metadata_result.get("data"), dict) else {}
        usr_mtd = dict(metadata.get("usr_mtd") or {}) if isinstance(metadata, dict) else {}
        sys_mtd = metadata.get("sys_mtd") if isinstance(metadata, dict) else {}
        usr_mtd["enabled"] = checked_enabled
        params = {"usr_mtd": json.dumps(usr_mtd)}
        if isinstance(sys_mtd, dict) and sys_mtd.get("etag"):
            params["etag"] = require_token(str(sys_mtd["etag"]), "etag")
        resource = self._typed_hive_record_resource(resource_type, scoped_oid, safe_key)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"hive/{quote(safe_hive, safe='')}/{quote(partition, safe='')}/{quote(safe_key, safe='')}/mtd",
            resource=resource,
            params=params,
            data=None,
            json_body=None,
            expected_effect=f"Set enabled={checked_enabled} on {resource_type} {safe_key}, preserving current metadata.",
            reversibility="Preview and confirm the opposite enabled value if this change was unintended.",
            side_effects=[{"type": side_effect_type, "resource": resource}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def list_secrets(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "secret", "secret.list", "secret", limit)

    def get_secret(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "secret", name, "secret.get", "secret")

    def preview_set_secret(
        self,
        oid: str,
        name: str,
        secret_value: str,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        checked_secret = require_case_text(secret_value, "secret_value", maximum=200_000, required=True)
        assert checked_secret is not None
        return self._preview_set_typed_hive_record(
            oid,
            "secret",
            name,
            {"secret": checked_secret},
            "secret.set",
            "secret",
            "secret_set",
            tags=tags,
            comment=comment,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_secret(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "secret",
            name,
            "secret.delete",
            "secret",
            "secret_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_secret_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "secret",
            name,
            enabled,
            "secret.enabled.set",
            "secret",
            "secret_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_lookups(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "lookup", "lookup.list", "lookup", limit)

    def get_lookup(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "lookup", name, "lookup.get", "lookup")

    def preview_set_lookup(
        self,
        oid: str,
        name: str,
        lookup_data: dict[str, Any] | None = None,
        newline_content: str | None = None,
        yaml_content: str | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        provided = [
            value is not None
            for value in (
                lookup_data,
                newline_content,
                yaml_content,
            )
        ]
        if sum(provided) != 1:
            raise ValidationError("exactly one of lookup_data, newline_content, or yaml_content is required")
        data: dict[str, Any]
        if lookup_data is not None:
            checked_lookup_data = require_dict(lookup_data, "lookup_data")
            assert checked_lookup_data is not None
            data = {"lookup_data": checked_lookup_data}
        elif newline_content is not None:
            checked_newline_content = require_case_text(newline_content, "newline_content", maximum=200_000, required=True)
            assert checked_newline_content is not None
            data = {"newline_content": checked_newline_content}
        else:
            checked_yaml_content = require_case_text(yaml_content, "yaml_content", maximum=200_000, required=True)
            assert checked_yaml_content is not None
            data = {"yaml_content": checked_yaml_content}
        return self._preview_set_typed_hive_record(
            oid,
            "lookup",
            name,
            data,
            "lookup.set",
            "lookup",
            "lookup_set",
            tags=tags,
            comment=comment,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_lookup(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "lookup",
            name,
            "lookup.delete",
            "lookup",
            "lookup_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_lookup_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "lookup",
            name,
            enabled,
            "lookup.enabled.set",
            "lookup",
            "lookup_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def _preview_set_structured_hive_shortcut(
        self,
        oid: str,
        hive_name: str,
        name: str,
        data: dict[str, Any],
        operation: str,
        resource_type: str,
        side_effect_type: str,
        *,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        checked_data = require_dict(data, "data")
        assert checked_data is not None
        return self._preview_set_typed_hive_record(
            oid,
            hive_name,
            name,
            checked_data,
            operation,
            resource_type,
            side_effect_type,
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_cloud_adapters(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "cloud_sensor", "cloud_adapter.list", "cloud_adapter", limit)

    def get_cloud_adapter(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "cloud_sensor", name, "cloud_adapter.get", "cloud_adapter")

    def preview_set_cloud_adapter(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "cloud_sensor",
            name,
            data,
            "cloud_adapter.set",
            "cloud_adapter",
            "cloud_adapter_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_cloud_adapter(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "cloud_sensor",
            name,
            "cloud_adapter.delete",
            "cloud_adapter",
            "cloud_adapter_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_cloud_adapter_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "cloud_sensor",
            name,
            enabled,
            "cloud_adapter.enabled.set",
            "cloud_adapter",
            "cloud_adapter_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_external_adapters(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "external_adapter", "external_adapter.list", "external_adapter", limit)

    def get_external_adapter(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "external_adapter", name, "external_adapter.get", "external_adapter")

    def preview_set_external_adapter(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "external_adapter",
            name,
            data,
            "external_adapter.set",
            "external_adapter",
            "external_adapter_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_external_adapter(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "external_adapter",
            name,
            "external_adapter.delete",
            "external_adapter",
            "external_adapter_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_external_adapter_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "external_adapter",
            name,
            enabled,
            "external_adapter.enabled.set",
            "external_adapter",
            "external_adapter_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_playbooks(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "playbook", "playbook.list", "playbook", limit)

    def get_playbook(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "playbook", name, "playbook.get", "playbook")

    def preview_set_playbook(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "playbook",
            name,
            data,
            "playbook.set",
            "playbook",
            "playbook_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_playbook(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "playbook",
            name,
            "playbook.delete",
            "playbook",
            "playbook_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_playbook_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "playbook",
            name,
            enabled,
            "playbook.enabled.set",
            "playbook",
            "playbook_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_sops(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "sop", "sop.list", "sop", limit)

    def get_sop(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "sop", name, "sop.get", "sop")

    def preview_set_sop(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "sop",
            name,
            data,
            "sop.set",
            "sop",
            "sop_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_sop(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "sop",
            name,
            "sop.delete",
            "sop",
            "sop_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_sop_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "sop",
            name,
            enabled,
            "sop.enabled.set",
            "sop",
            "sop_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_org_notes(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "org_notes", "org_note.list", "org_note", limit)

    def get_org_note(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "org_notes", name, "org_note.get", "org_note")

    def preview_set_org_note(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "org_notes",
            name,
            data,
            "org_note.set",
            "org_note",
            "org_note_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_org_note(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "org_notes",
            name,
            "org_note.delete",
            "org_note",
            "org_note_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_org_note_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "org_notes",
            name,
            enabled,
            "org_note.enabled.set",
            "org_note",
            "org_note_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_ai_agents(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "ai_agent", "ai_agent.list", "ai_agent", limit)

    def get_ai_agent(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "ai_agent", name, "ai_agent.get", "ai_agent")

    def preview_set_ai_agent(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "ai_agent",
            name,
            data,
            "ai_agent.set",
            "ai_agent",
            "ai_agent_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_ai_agent(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "ai_agent",
            name,
            "ai_agent.delete",
            "ai_agent",
            "ai_agent_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_ai_agent_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "ai_agent",
            name,
            enabled,
            "ai_agent.enabled.set",
            "ai_agent",
            "ai_agent_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_ai_skills(self, oid: str, limit: int = 100) -> dict[str, Any]:
        return self._list_typed_hive_records(oid, "ai_skill", "ai_skill.list", "ai_skill", limit)

    def get_ai_skill(self, oid: str, name: str) -> dict[str, Any]:
        return self._get_typed_hive_record(oid, "ai_skill", name, "ai_skill.get", "ai_skill")

    def preview_set_ai_skill(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        ui_actions: list[dict[str, Any]] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_structured_hive_shortcut(
            oid,
            "ai_skill",
            name,
            data,
            "ai_skill.set",
            "ai_skill",
            "ai_skill_set",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            ui_actions=ui_actions,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_ai_skill(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_delete_typed_hive_record(
            oid,
            "ai_skill",
            name,
            "ai_skill.delete",
            "ai_skill",
            "ai_skill_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_ai_skill_enabled(
        self,
        oid: str,
        name: str,
        enabled: bool,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_set_typed_hive_record_enabled(
            oid,
            "ai_skill",
            name,
            enabled,
            "ai_skill.enabled.set",
            "ai_skill",
            "ai_skill_metadata_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def _extract_ai_memories(self, record: Any) -> dict[str, str]:
        if not isinstance(record, dict):
            return {}
        payload = record.get("data")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                return {}
        if not isinstance(payload, dict):
            return {}
        memories = payload.get("memories")
        if not isinstance(memories, dict):
            return {}
        return {str(key): value for key, value in memories.items() if isinstance(value, str)}

    def list_ai_memory_records(self, oid: str, partition_key: str | None = None, limit: int = 100) -> dict[str, Any]:
        result = self.list_hive_records(oid, "ai_memory", partition_key=partition_key, limit=limit)
        result["operation"] = "ai_memory.record.list"
        if result.get("resource"):
            result["resource"]["type"] = "ai_memory_record_collection"
        return result

    def get_ai_memory_record(self, oid: str, agent: str, partition_key: str | None = None) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        result = self.get_hive_record(oid, "ai_memory", safe_agent, partition_key=partition_key)
        result["operation"] = "ai_memory.record.get"
        if result.get("resource"):
            result["resource"]["type"] = "ai_memory_record"
        return result

    def list_ai_memories(self, oid: str, agent: str, partition_key: str | None = None) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        record = self.get_ai_memory_record(oid, safe_agent, partition_key=partition_key)
        if not record.get("ok"):
            record["operation"] = "ai_memory.list"
            return record
        memories = self._extract_ai_memories(record.get("data"))
        return self._local_response(
            "ai_memory.list",
            {"agent": safe_agent, "memories": memories},
            resource={"type": "ai_memory_collection", "id": safe_agent},
        )

    def get_ai_memory(self, oid: str, agent: str, memory_name: str, partition_key: str | None = None) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        safe_memory_name = require_hive_record_key(memory_name, "memory_name")
        memories_result = self.list_ai_memories(oid, safe_agent, partition_key=partition_key)
        if not memories_result.get("ok"):
            memories_result["operation"] = "ai_memory.get"
            return memories_result
        memories = memories_result.get("data", {}).get("memories", {})
        return self._local_response(
            "ai_memory.get",
            {"agent": safe_agent, "memory_name": safe_memory_name, "content": memories.get(safe_memory_name)},
            resource={"type": "ai_memory", "id": f"{safe_agent}:{safe_memory_name}"},
            state={"current": "present" if safe_memory_name in memories else "missing"},
        )

    def preview_set_ai_memory(
        self,
        oid: str,
        agent: str,
        memory_name: str,
        content: str,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        safe_memory_name = require_hive_record_key(memory_name, "memory_name")
        checked_content = require_case_text(content, "content", maximum=200_000, required=True)
        scoped_oid, _, partition = self._hive_context(oid, "ai_memory", partition_key)
        assert checked_content is not None
        return self._create_mutation_preview(
            operation="ai_memory.set",
            oid=scoped_oid,
            method="POST",
            path=f"hive/ai_memory/{quote(partition, safe='')}/{quote(safe_agent, safe='')}/data",
            resource={"type": "ai_memory", "id": f"{safe_agent}:{safe_memory_name}"},
            params={"data": json.dumps({"memories": {safe_memory_name: checked_content}})},
            data=None,
            json_body=None,
            expected_effect=f"Set ai_memory entry {safe_agent}/{safe_memory_name} through the hive partial-merge hook.",
            reversibility="Preview and confirm ai_memory.delete for the same memory entry if this was unintended.",
            side_effects=[{"type": "ai_memory_set", "resource": {"type": "ai_memory", "id": f"{safe_agent}:{safe_memory_name}"}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_delete_ai_memory(
        self,
        oid: str,
        agent: str,
        memory_name: str,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        safe_memory_name = require_hive_record_key(memory_name, "memory_name")
        scoped_oid, _, partition = self._hive_context(oid, "ai_memory", partition_key)
        return self._create_mutation_preview(
            operation="ai_memory.delete",
            oid=scoped_oid,
            method="POST",
            path=f"hive/ai_memory/{quote(partition, safe='')}/{quote(safe_agent, safe='')}/data",
            resource={"type": "ai_memory", "id": f"{safe_agent}:{safe_memory_name}"},
            params={"data": json.dumps({"memories": {safe_memory_name: None}})},
            data=None,
            json_body=None,
            expected_effect=f"Delete ai_memory entry {safe_agent}/{safe_memory_name} through the hive partial-merge hook.",
            reversibility="Set the memory entry again if deletion was unintended.",
            side_effects=[{"type": "ai_memory_deleted", "resource": {"type": "ai_memory", "id": f"{safe_agent}:{safe_memory_name}"}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def preview_delete_ai_memory_record(
        self,
        oid: str,
        agent: str,
        partition_key: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_agent = require_hive_record_key(agent, "agent")
        scoped_oid, _, partition = self._hive_context(oid, "ai_memory", partition_key)
        return self._create_mutation_preview(
            operation="ai_memory.record.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/ai_memory/{quote(partition, safe='')}/{quote(safe_agent, safe='')}",
            resource={"type": "ai_memory_record", "id": safe_agent},
            params=None,
            data=None,
            json_body=None,
            expected_effect=f"Delete entire ai_memory record {safe_agent}.",
            reversibility="Recreate the ai_memory record from a known-good backup if deletion was unintended.",
            side_effects=[{"type": "ai_memory_record_deleted", "resource": {"type": "ai_memory_record", "id": safe_agent}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def _ai_headers(self, oid: str) -> dict[str, str]:
        return {"X-LC-OID": require_oid(oid)}

    def _ai_request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        oid: str,
        resource: dict[str, Any],
        params: dict[str, Any] | None = None,
        limit: int = 100,
        side_effects: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            method,
            path,
            operation=operation,
            oid=scoped_oid,
            resource=resource,
            params=params,
            limit=limit,
            base_url=self.ai_root,
            extra_headers=self._ai_headers(scoped_oid),
            side_effects=side_effects,
        ).as_dict()

    def list_ai_sessions(
        self,
        oid: str,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit, maximum=200)
        params: dict[str, Any] = {"limit": bounded_limit}
        if status is not None:
            checked_status = str(status).lower()
            if checked_status not in _AI_SESSION_STATUSES:
                raise ValidationError("status must be running, ended, starting, or failed")
            params["status"] = checked_status
        if cursor is not None:
            params["cursor"] = require_token(cursor, "cursor")
        return self._ai_request(
            "GET",
            "v1/org/sessions",
            operation="ai.session.list",
            oid=scoped_oid,
            resource={"type": "ai_session_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        )

    def get_ai_session(self, oid: str, session_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_session_id = require_path_segment(session_id, "session_id")
        return self._ai_request(
            "GET",
            f"v1/org/sessions/{quote(safe_session_id, safe='')}",
            operation="ai.session.get",
            oid=scoped_oid,
            resource={"type": "ai_session", "id": safe_session_id, "parent": {"type": "organization", "id": scoped_oid}},
        )

    def get_ai_session_history(self, oid: str, session_id: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_session_id = require_path_segment(session_id, "session_id")
        bounded_limit = require_limit(limit)
        return self._ai_request(
            "GET",
            f"v1/org/sessions/{quote(safe_session_id, safe='')}/history",
            operation="ai.session.history",
            oid=scoped_oid,
            resource={"type": "ai_session_history", "id": safe_session_id, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def preview_terminate_ai_session(self, oid: str, session_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_session_id = require_path_segment(session_id, "session_id")
        return self._create_mutation_preview(
            operation="ai.session.terminate",
            oid=scoped_oid,
            method="DELETE",
            path=f"v1/org/sessions/{quote(safe_session_id, safe='')}",
            resource={"type": "ai_session", "id": safe_session_id, "parent": {"type": "organization", "id": scoped_oid}},
            base_url=self.ai_root,
            params=None,
            data=None,
            json_body=None,
            extra_headers=self._ai_headers(scoped_oid),
            expected_effect=f"Terminate AI session {safe_session_id}.",
            reversibility="Termination cannot be undone; create a new session if more AI work is needed.",
            side_effects=[{"type": "ai_session_terminated", "resource": {"type": "ai_session", "id": safe_session_id}}],
            token_ttl_seconds=require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900),
        )

    def list_ai_usage_identities(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._ai_request(
            "GET",
            "v1/org/usage/identities",
            operation="ai.usage.identity.list",
            oid=scoped_oid,
            resource={"type": "ai_usage_identity_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def get_ai_usage(self, oid: str, identity: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_identity = require_token(identity, "identity")
        bounded_limit = require_limit(limit)
        return self._ai_request(
            "GET",
            f"v1/org/usage/identities/{quote(safe_identity, safe='')}",
            operation="ai.usage.get",
            oid=scoped_oid,
            resource={"type": "ai_usage", "id": safe_identity, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def list_schemas(self, oid: str, platform: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params = {"platform": require_token(platform, "platform")} if platform else None
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/schema",
            operation="schema.list",
            oid=scoped_oid,
            resource={"type": "schema_collection", "id": scoped_oid},
            params=params,
            limit=bounded_limit,
        ).as_dict()

    def get_schema(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/schema/{quote(safe_name, safe='')}",
            operation="schema.get",
            oid=scoped_oid,
            resource={"type": "schema", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def get_ontology(self, oid: str | None = None, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        auth_oid = self._global_reference_auth_oid(oid)
        return self._request(
            "GET",
            "ontology",
            operation="ontology.get",
            oid=auth_oid,
            resource={"type": "ontology", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def list_event_types(self, oid: str | None = None, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        auth_oid = self._global_reference_auth_oid(oid)
        return self._request(
            "GET",
            "events",
            operation="event_type.list",
            oid=auth_oid,
            resource={"type": "event_type_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def get_mitre_report(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"mitre/{scoped_oid}",
            operation="mitre.get",
            oid=scoped_oid,
            resource={"type": "mitre_report", "id": scoped_oid},
        ).as_dict()

    def get_org_info(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}",
            operation="org.get",
            oid=scoped_oid,
            resource={"type": "organization", "id": scoped_oid},
        ).as_dict()

    def get_org_stats(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"usage/{scoped_oid}",
            operation="org.stats",
            oid=scoped_oid,
            resource={"type": "organization_stats", "id": scoped_oid},
        ).as_dict()

    def list_org_errors(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"errors/{scoped_oid}",
            operation="org.errors",
            oid=scoped_oid,
            resource={"type": "organization_error_collection", "id": scoped_oid},
        ).as_dict()

    def get_org_urls(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/url",
            operation="org.urls",
            oid=scoped_oid,
            resource={"type": "organization_urls", "id": scoped_oid},
            no_auth=True,
        ).as_dict()

    def get_runtime_metadata(
        self,
        oid: str,
        entity_type: str | None = None,
        entity_name: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        params: dict[str, Any] = {}
        if entity_type:
            params["entity_type"] = require_token(entity_type, "entity_type")
        if entity_name:
            params["entity_name"] = require_token(entity_name, "entity_name")
        return self._request(
            "GET",
            f"runtime_mtd/{scoped_oid}",
            operation="org.runtime_metadata",
            oid=scoped_oid,
            resource={"type": "runtime_metadata", "id": scoped_oid},
            params=params or None,
            limit=bounded_limit,
        ).as_dict()

    def get_quota_usage(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"quota_usage/{scoped_oid}",
            operation="org.quota_usage",
            oid=scoped_oid,
            resource={"type": "quota_usage", "id": scoped_oid},
        ).as_dict()

    def check_org_name(self, name: str) -> dict[str, Any]:
        safe_name = require_org_name(name)
        return self._request(
            "GET",
            "orgs/new",
            operation="org.name.check",
            oid="-",
            resource={"type": "organization_name", "id": safe_name},
            params={"name": safe_name},
        ).as_dict()

    def preview_create_org(
        self,
        name: str,
        location: str | None = None,
        template: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_org_name(name)
        params: dict[str, Any] = {"name": safe_name}
        if location:
            params["loc"] = require_token(location, "location")
        if template:
            params["template"] = require_token(template, "template")
        return self._preview_mutation(
            operation="org.create",
            oid="-",
            method="POST",
            path="orgs/new",
            resource_type="organization",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create organization {safe_name!r}.",
            reversibility="Delete the new organization if creation was unintended.",
            side_effect_type="org_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_org_config_value(self, oid: str, config_name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_path_segment(config_name, "config_name")
        return self._request(
            "GET",
            f"configs/{scoped_oid}/{quote(safe_name, safe='')}",
            operation="org.config.get",
            oid=scoped_oid,
            resource={"type": "organization_config_value", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_org_config_value(
        self,
        oid: str,
        config_name: str,
        value: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_path_segment(config_name, "config_name")
        safe_value = require_config_value(value)
        return self._preview_mutation(
            operation="org.config.set",
            oid=scoped_oid,
            method="POST",
            path=f"configs/{scoped_oid}/{quote(safe_name, safe='')}",
            resource_type="organization_config_value",
            resource_id=safe_name,
            params={"value": safe_value},
            expected_effect=f"Set org config value {safe_name!r}.",
            reversibility="Set the config value back to its prior value if needed.",
            side_effect_type="org_config_value_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_dismiss_org_error(self, oid: str, component: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_component = require_path_segment(component, "component")
        return self._preview_mutation(
            operation="org.error.dismiss",
            oid=scoped_oid,
            method="DELETE",
            path=f"errors/{scoped_oid}/{quote(safe_component, safe='')}",
            resource_type="organization_error",
            resource_id=safe_component,
            expected_effect=f"Dismiss org error component {safe_component!r}.",
            reversibility="Dismissal only affects the current error record; wait for the component to emit a new error if it recurs.",
            side_effect_type="org_error_dismissed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def get_org_delete_confirmation(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/delete",
            operation="org.delete.confirmation",
            oid=scoped_oid,
            resource={"type": "organization_delete_confirmation", "id": scoped_oid},
        ).as_dict()

    def preview_delete_org(self, oid: str, confirmation: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_confirmation = require_token(confirmation, "confirmation")
        return self._preview_mutation(
            operation="org.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/delete",
            resource_type="organization",
            resource_id=scoped_oid,
            params={"confirmation": safe_confirmation},
            expected_effect=f"Delete organization {scoped_oid}.",
            reversibility="Organization deletion is not generally reversible.",
            side_effect_type="org_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_set_org_quota(self, oid: str, quota: int, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_quota = require_quota(quota)
        return self._preview_mutation(
            operation="org.quota.set",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/quota",
            resource_type="organization_quota",
            resource_id=scoped_oid,
            params={"quota": safe_quota},
            expected_effect=f"Set organization sensor quota to {safe_quota}.",
            reversibility="Run another quota preview with the prior quota value.",
            side_effect_type="org_quota_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_rename_org(self, oid: str, new_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(new_name, "new_name")
        return self._preview_mutation(
            operation="org.rename",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/name",
            resource_type="organization",
            resource_id=scoped_oid,
            params={"name": safe_name},
            expected_effect=f"Rename organization {scoped_oid} to {safe_name!r}.",
            reversibility="Run another rename preview with the previous organization name.",
            side_effect_type="org_renamed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def get_billing_status(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/status",
            operation="billing.status",
            oid=scoped_oid,
            resource={"type": "billing_status", "id": scoped_oid},
        ).as_dict()

    def get_billing_details(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/details",
            operation="billing.details",
            oid=scoped_oid,
            resource={"type": "billing_details", "id": scoped_oid},
        ).as_dict()

    def get_billing_invoice_url(self, oid: str, year: int, month: int, fmt: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_year = require_invoice_year(year)
        safe_month = require_invoice_month(month)
        safe_fmt = require_invoice_format(fmt)
        params = {"format": safe_fmt} if safe_fmt else None
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/billing/invoice/{safe_year}/{safe_month:02d}",
            operation="billing.invoice_url",
            oid=scoped_oid,
            resource={"type": "billing_invoice", "id": f"{safe_year}-{safe_month:02d}", "parent": {"type": "organization", "id": scoped_oid}},
            params=params,
        ).as_dict()

    def list_billing_plans(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "plans",
            operation="billing.plans",
            oid="-",
            resource={"type": "billing_plan_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def list_groups(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "groups",
            operation="group.list",
            oid="-",
            resource={"type": "group_collection", "id": "-"},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_group(self, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="group.create",
            oid="-",
            method="POST",
            path="groups",
            resource_type="group",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Create group {safe_name!r}.",
            reversibility="Delete the group if it was created unintentionally.",
            side_effect_type="group_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_group(self, group_id: str) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        return self._request(
            "GET",
            f"groups/{quote(safe_group_id, safe='')}",
            operation="group.get",
            oid="-",
            resource={"type": "group", "id": safe_group_id},
        ).as_dict()

    def list_group_logs(self, group_id: str, limit: int = 100) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"groups/{quote(safe_group_id, safe='')}/logs",
            operation="group.logs",
            oid="-",
            resource={"type": "group_log_collection", "id": safe_group_id},
            limit=bounded_limit,
        ).as_dict()

    def preview_delete_group(self, group_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        return self._preview_mutation(
            operation="group.delete",
            oid="-",
            method="DELETE",
            path=f"groups/{quote(safe_group_id, safe='')}",
            resource_type="group",
            resource_id=safe_group_id,
            expected_effect=f"Delete group {safe_group_id}.",
            reversibility="Recreate the group and memberships from a known-good definition if deletion was unintended.",
            side_effect_type="group_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_group_member(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.member.add", "POST", group_id, email, "users", "group_member_added", token_ttl_seconds)

    def preview_remove_group_member(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.member.remove", "DELETE", group_id, email, "users", "group_member_removed", token_ttl_seconds)

    def preview_add_group_owner(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.owner.add", "POST", group_id, email, "owners", "group_owner_added", token_ttl_seconds)

    def preview_remove_group_owner(self, group_id: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_email_mutation("group.owner.remove", "DELETE", group_id, email, "owners", "group_owner_removed", token_ttl_seconds)

    def preview_set_group_permissions(self, group_id: str, permissions: list[str] | str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_permissions = require_permission_list(permissions)
        return self._preview_mutation(
            operation="group.permissions.set",
            oid="-",
            method="POST",
            path=f"groups/{quote(safe_group_id, safe='')}/permissions",
            resource_type="group_permissions",
            resource_id=safe_group_id,
            params={"perm": safe_permissions},
            expected_effect=f"Replace permissions on group {safe_group_id}.",
            reversibility="Run another permissions preview with the previous permission list.",
            side_effect_type="group_permissions_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_add_group_org(self, group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_org_mutation("group.org.add", "POST", group_id, member_oid, "group_org_added", token_ttl_seconds)

    def preview_remove_group_org(self, group_id: str, member_oid: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_group_org_mutation("group.org.remove", "DELETE", group_id, member_oid, "group_org_removed", token_ttl_seconds)

    def list_users(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/users",
            operation="user.list",
            oid=scoped_oid,
            resource={"type": "user_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_invite_user(self, oid: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        return self._preview_mutation(
            operation="user.invite",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/users",
            resource_type="user",
            resource_id=safe_email,
            params={"email": safe_email},
            expected_effect=f"Invite {safe_email} to organization {scoped_oid}.",
            reversibility="Remove the user from the org if the invitation was unintended.",
            side_effect_type="user_invited",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_remove_user(self, oid: str, email: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        return self._preview_mutation(
            operation="user.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/users",
            resource_type="user",
            resource_id=safe_email,
            params={"email": safe_email},
            expected_effect=f"Remove {safe_email} from organization {scoped_oid}.",
            reversibility="Invite the user again and restore permissions if removal was unintended.",
            side_effect_type="user_removed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_user_permissions(self, oid: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/users/permissions",
            operation="user.permission.list",
            oid=scoped_oid,
            resource={"type": "user_permission_collection", "id": scoped_oid},
        ).as_dict()

    def preview_add_user_permission(self, oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_permission = require_permission(permission)
        return self._preview_mutation(
            operation="user.permission.add",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/users/permissions",
            resource_type="user_permission",
            resource_id=f"{safe_email}:{safe_permission}",
            params={"email": safe_email, "perm": safe_permission},
            expected_effect=f"Grant {safe_permission} to {safe_email}.",
            reversibility="Preview and confirm user.permission.remove for the same permission.",
            side_effect_type="user_permission_added",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_remove_user_permission(self, oid: str, email: str, permission: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_permission = require_permission(permission)
        return self._preview_mutation(
            operation="user.permission.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/users/permissions",
            resource_type="user_permission",
            resource_id=f"{safe_email}:{safe_permission}",
            params={"email": safe_email, "perm": safe_permission},
            expected_effect=f"Revoke {safe_permission} from {safe_email}.",
            reversibility="Preview and confirm user.permission.add for the same permission.",
            side_effect_type="user_permission_removed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_set_user_role(self, oid: str, email: str, role: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_email = require_email(email)
        safe_role = require_org_role(role)
        return self._preview_mutation(
            operation="user.role.set",
            oid=scoped_oid,
            method="PUT",
            path=f"orgs/{scoped_oid}/users/role",
            resource_type="user_role",
            resource_id=safe_email,
            json_body={"email": safe_email, "role": safe_role},
            expected_effect=f"Replace {safe_email}'s permissions with role {safe_role}.",
            reversibility="Restore the previous explicit permissions or role from audit evidence.",
            side_effect_type="user_role_set",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_api_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/keys",
            operation="api_key.list",
            oid=scoped_oid,
            resource={"type": "api_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_api_key(
        self,
        oid: str,
        name: str,
        permissions: list[str] | str,
        ip_range: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        safe_permissions = require_permission_list(permissions)
        params: dict[str, Any] = {"key_name": safe_name, "perms": ",".join(safe_permissions)}
        if ip_range:
            params["allowed_ip_range"] = require_token(ip_range, "ip_range")
        return self._preview_mutation(
            operation="api_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/keys",
            resource_type="api_key",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create API key {safe_name!r}.",
            reversibility="Delete the API key by key hash if creation was unintended.",
            side_effect_type="api_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_api_key(self, oid: str, key_hash: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_key_hash = require_path_segment(key_hash, "key_hash")
        return self._preview_mutation(
            operation="api_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/keys",
            resource_type="api_key",
            resource_id=safe_key_hash,
            params={"key_hash": safe_key_hash},
            expected_effect=f"Delete API key {safe_key_hash}.",
            reversibility="Create a replacement API key with equivalent permissions if deletion was unintended.",
            side_effect_type="api_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_installation_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"installationkeys/{scoped_oid}",
            operation="installation_key.list",
            oid=scoped_oid,
            resource={"type": "installation_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def get_installation_key(self, oid: str, installation_key_id: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_iid = require_path_segment(installation_key_id, "installation_key_id")
        return self._request(
            "GET",
            f"installationkeys/{scoped_oid}/{quote(safe_iid, safe='')}",
            operation="installation_key.get",
            oid=scoped_oid,
            resource={"type": "installation_key", "id": safe_iid, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_create_installation_key(
        self,
        oid: str,
        description: str,
        tags: list[str] | str | None = None,
        use_public_ca: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_description = require_token(description, "description")
        params: dict[str, Any] = {
            "desc": safe_description,
            "use_public_root_ca": bool_param(bool(use_public_ca)),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags:
            params["tags"] = ",".join(checked_tags)
        return self._preview_mutation(
            operation="installation_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"installationkeys/{scoped_oid}",
            resource_type="installation_key",
            resource_id=safe_description,
            params=params,
            expected_effect=f"Create installation key {safe_description!r}.",
            reversibility="Delete the installation key if creation was unintended.",
            side_effect_type="installation_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_installation_key(self, oid: str, installation_key_id: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_iid = require_path_segment(installation_key_id, "installation_key_id")
        return self._preview_mutation(
            operation="installation_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"installationkeys/{scoped_oid}",
            resource_type="installation_key",
            resource_id=safe_iid,
            params={"iid": safe_iid},
            expected_effect=f"Delete installation key {safe_iid}.",
            reversibility="Create a replacement installation key if deletion was unintended.",
            side_effect_type="installation_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_outputs(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"outputs/{scoped_oid}",
            operation="output.list",
            oid=scoped_oid,
            resource={"type": "output_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_create_ingestion_key(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="ingestion_key.create",
            oid=scoped_oid,
            method="POST",
            path=f"insight/{scoped_oid}/ingestion_keys",
            resource_type="ingestion_key",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Create ingestion key {safe_name!r}.",
            reversibility="Delete the ingestion key if creation was unintended.",
            side_effect_type="ingestion_key_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_ingestion_key(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="ingestion_key.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"insight/{scoped_oid}/ingestion_keys",
            resource_type="ingestion_key",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Delete ingestion key {safe_name!r}.",
            reversibility="Create a replacement ingestion key if deletion was unintended.",
            side_effect_type="ingestion_key_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_create_output(
        self,
        oid: str,
        name: str,
        module: str,
        data_type: str,
        config: dict[str, Any] | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        params: dict[str, Any] = {
            "name": safe_name,
            "module": require_token(module, "module"),
            "type": require_token(data_type, "data_type"),
        }
        checked_config = require_dict(config, "config") or {}
        params.update(checked_config)
        return self._preview_mutation(
            operation="output.create",
            oid=scoped_oid,
            method="POST",
            path=f"outputs/{scoped_oid}",
            resource_type="output",
            resource_id=safe_name,
            params=params,
            expected_effect=f"Create output {safe_name!r}.",
            reversibility="Delete the output if creation was unintended.",
            side_effect_type="output_created",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_delete_output(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._preview_mutation(
            operation="output.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"outputs/{scoped_oid}",
            resource_type="output",
            resource_id=safe_name,
            params={"name": safe_name},
            expected_effect=f"Delete output {safe_name!r}.",
            reversibility="Recreate the output from its previous configuration if deletion was unintended.",
            side_effect_type="output_deleted",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_extension_subscriptions(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"orgs/{scoped_oid}/subscriptions",
            operation="extension.list_subscribed",
            oid=scoped_oid,
            resource={"type": "extension_subscription_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_subscribe_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.subscribe",
            oid=scoped_oid,
            method="POST",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Subscribe organization {scoped_oid} to extension {safe_name}.",
            reversibility="Preview and confirm extension.unsubscribe for the same extension.",
            side_effect_type="extension_subscribed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_unsubscribe_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.unsubscribe",
            oid=scoped_oid,
            method="DELETE",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Unsubscribe organization {scoped_oid} from extension {safe_name}.",
            reversibility="Preview and confirm extension.subscribe for the same extension.",
            side_effect_type="extension_unsubscribed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def preview_rekey_extension(self, oid: str, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.rekey",
            oid=scoped_oid,
            method="PATCH",
            path=f"orgs/{scoped_oid}/subscription/extension/{quote(safe_name, safe='')}",
            resource_type="extension_subscription",
            resource_id=safe_name,
            params={},
            expected_effect=f"Rotate the API key for extension subscription {safe_name}.",
            reversibility="Rekeying is not reversible; update dependent systems with the newly returned key material if applicable.",
            side_effect_type="extension_rekeyed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_available_extensions(self, limit: int = 100) -> dict[str, Any]:
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            "extension/definition",
            operation="extension.list_available",
            oid="-",
            resource={"type": "extension_definition_collection", "id": "-"},
            params={},
            limit=bounded_limit,
        ).as_dict()

    def get_extension(self, extension_name: str) -> dict[str, Any]:
        safe_name = require_extension_name(extension_name)
        return self._request(
            "GET",
            f"extension/definition/{quote(safe_name, safe='')}",
            operation="extension.get",
            oid="-",
            resource={"type": "extension_definition", "id": safe_name},
        ).as_dict()

    def preview_create_extension(
        self,
        extension_definition: dict[str, Any],
        extension_name: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_definition = require_dict(extension_definition, "extension_definition") or {}
        safe_name = self._extension_definition_id(safe_definition, extension_name)
        return self._preview_mutation(
            operation="extension.create",
            oid="-",
            method="POST",
            path="extension/definition",
            resource_type="extension_definition",
            resource_id=safe_name,
            params={},
            json_body=safe_definition,
            expected_effect=f"Create extension definition {safe_name}.",
            reversibility="Delete the extension definition if creation was unintended.",
            side_effect_type="extension_created",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_update_extension(
        self,
        extension_definition: dict[str, Any],
        extension_name: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_definition = require_dict(extension_definition, "extension_definition") or {}
        safe_name = self._extension_definition_id(safe_definition, extension_name)
        return self._preview_mutation(
            operation="extension.update",
            oid="-",
            method="PUT",
            path="extension/definition",
            resource_type="extension_definition",
            resource_id=safe_name,
            params={},
            json_body=safe_definition,
            expected_effect=f"Update extension definition {safe_name}.",
            reversibility="Restore the previous extension definition body if the update was unintended.",
            side_effect_type="extension_updated",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_extension(self, extension_name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_extension_name(extension_name)
        return self._preview_mutation(
            operation="extension.delete",
            oid="-",
            method="DELETE",
            path=f"extension/definition/{quote(safe_name, safe='')}",
            resource_type="extension_definition",
            resource_id=safe_name,
            expected_effect=f"Delete extension definition {safe_name}.",
            reversibility="Recreate the extension definition from a known-good body if deletion was unintended.",
            side_effect_type="extension_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def get_extension_schema(self, oid: str, extension_name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        return self._request(
            "GET",
            f"extension/schema/{quote(safe_name, safe='')}",
            operation="extension.schema.get",
            oid=scoped_oid,
            resource={"type": "extension_schema", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params={"oid": scoped_oid},
        ).as_dict()

    def preview_extension_request(
        self,
        oid: str,
        extension_name: str,
        action: str,
        data: dict[str, Any] | None = None,
        impersonate: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if impersonate:
            raise ValidationError("impersonate is not supported because it would expose a JWT in preview data")
        scoped_oid = require_oid(oid)
        safe_name = require_extension_name(extension_name)
        safe_action = require_token(action, "action")
        safe_data = require_dict(data, "data") or {}
        return self._preview_mutation(
            operation="extension.request",
            oid=scoped_oid,
            method="POST",
            path=f"extension/request/{quote(safe_name, safe='')}",
            resource_type="extension_request",
            resource_id=f"{safe_name}:{safe_action}",
            params=extension_request_params(scoped_oid, safe_action, safe_data),
            expected_effect=f"Call extension {safe_name} action {safe_action}.",
            reversibility="Extension request side effects are action-specific; inspect the extension action documentation before confirming.",
            side_effect_type="extension_request_executed",
            token_ttl_seconds=token_ttl_seconds,
            parent_oid=scoped_oid,
        )

    def list_vulnerability_cves(
        self,
        oid: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            include_enrichment=include_enrichment,
            filter_via_state=filter_via_state,
        )
        return self._extension_request(
            scoped_oid,
            "query_cves",
            data,
            operation="vulnerability.cve.list",
            resource={"type": "vulnerability_cve_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def get_vulnerability_cve(
        self,
        oid: str,
        cve: str,
        include_enrichment: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {"cve_id": require_cve(cve)}
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        return self._extension_request(
            scoped_oid,
            "query_cve",
            data,
            operation="vulnerability.cve.get",
            resource={"type": "vulnerability_cve", "id": data["cve_id"], "parent": {"type": "organization", "id": scoped_oid}},
        )

    def list_vulnerability_cve_hosts(
        self,
        oid: str,
        cve: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        filter_via_state: bool | None = None,
        normalized_package_name: str | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_cve = require_cve(cve)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            filter_via_state=filter_via_state,
        )
        data["cve"] = safe_cve
        if normalized_package_name:
            data["normalized_package_name"] = require_token(normalized_package_name, "normalized_package_name")
        return self._extension_request(
            scoped_oid,
            "query_cve_vuln_hosts",
            data,
            operation="vulnerability.cve.hosts",
            resource={"type": "vulnerability_host_collection", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def list_vulnerability_cve_packages(
        self,
        oid: str,
        cve: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        include_enrichment: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        safe_cve = require_cve(cve)
        data: dict[str, Any] = {"cve": safe_cve, "limit": bounded_limit}
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        if sort_by is not None:
            data["sort_by"] = require_token(sort_by, "sort_by")
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        return self._extension_request(
            scoped_oid,
            "query_cve_vuln_packages",
            data,
            operation="vulnerability.cve.packages",
            resource={"type": "vulnerability_package_collection", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def list_vulnerability_endpoints(
        self,
        oid: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            filter_via_state=filter_via_state,
        )
        return self._extension_request(
            scoped_oid,
            "query_endpoints",
            data,
            operation="vulnerability.endpoint.list",
            resource={"type": "vulnerability_endpoint_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def list_vulnerability_host_packages(
        self,
        oid: str,
        sensor_id: str,
        cursor: str | None = None,
        limit: int = 100,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
        rollup_subpackages: bool | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        bounded_limit = require_limit(limit)
        data = self._vulnerability_query(
            cursor=cursor,
            limit=bounded_limit,
            sort_by=sort_by,
            sort_asc=sort_asc,
            filters=filters,
            search=search,
            include_tags=include_tags,
            include_enrichment=include_enrichment,
            filter_via_state=filter_via_state,
        )
        data["sid"] = safe_sensor_id
        if rollup_subpackages is not None:
            data["rollup_subpackages"] = require_bool_or_none(rollup_subpackages, "rollup_subpackages")
        return self._extension_request(
            scoped_oid,
            "query_host_vuln_packages",
            data,
            operation="vulnerability.host.packages",
            resource={"type": "vulnerability_package_collection", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        )

    def get_vulnerability_dashboard(self, oid: str, sort_asc: bool | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {}
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        return self._extension_request(
            scoped_oid,
            "query_dashboard",
            data,
            operation="vulnerability.dashboard",
            resource={"type": "vulnerability_dashboard", "id": scoped_oid},
        )

    def list_vulnerability_resolutions(
        self,
        oid: str,
        scope: str | None = None,
        resolutions: list[str] | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        data: dict[str, Any] = {"limit": bounded_limit}
        if scope is not None:
            checked_scope = str(scope).lower()
            if checked_scope not in _VULN_SCOPES:
                raise ValidationError("scope must be org or host")
            data["scope"] = checked_scope
        checked_resolutions = require_vuln_resolutions(resolutions)
        if checked_resolutions is not None:
            data["resolutions"] = checked_resolutions
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        return self._extension_request(
            scoped_oid,
            "list_finding_resolutions",
            data,
            operation="vulnerability.resolution.list",
            resource={"type": "vulnerability_resolution_collection", "id": scoped_oid},
            limit=bounded_limit,
        )

    def list_vulnerability_snapshots(
        self,
        oid: str,
        days: int = 30,
        severities: list[str] | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        data: dict[str, Any] = {"days": require_days(days)}
        checked_severities = require_vuln_severities(severities)
        if checked_severities is not None:
            data["severities"] = checked_severities
        return self._extension_request(
            scoped_oid,
            "query_daily_snapshots",
            data,
            operation="vulnerability.snapshot.list",
            resource={"type": "vulnerability_snapshot_collection", "id": scoped_oid},
        )

    def get_vulnerability_epss_history(self, oid: str, cve: str, days: int = 90) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_cve = require_cve(cve)
        data = {"cve": safe_cve, "days": require_days(days)}
        return self._extension_request(
            scoped_oid,
            "query_epss_history",
            data,
            operation="vulnerability.epss_history",
            resource={"type": "vulnerability_epss_history", "id": safe_cve, "parent": {"type": "organization", "id": scoped_oid}},
        )

    def list_artifact_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/artifacts/rules",
            operation="artifact_rule.list",
            oid=scoped_oid,
            resource={"type": "artifact_rule_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def preview_set_artifact_rule(
        self,
        oid: str,
        name: str,
        platforms: list[str] | str,
        patterns: list[str] | str,
        is_delete_after: bool = False,
        retention_days: int = 30,
        tags: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        body: dict[str, Any] = {
            "name": safe_name,
            "platforms": require_string_list(platforms, "platforms") or [],
            "patterns": require_string_list(patterns, "patterns") or [],
            "is_delete_after": bool(is_delete_after),
            "days_retention": require_retention_days(retention_days) or 30,
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            body["tags"] = checked_tags
        return self._create_mutation_preview(
            operation="artifact_rule.set",
            oid=scoped_oid,
            method="POST",
            path=f"insight/{scoped_oid}/artifacts/rules",
            resource={"type": "artifact_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=body,
            expected_effect=f"Create or update artifact collection rule {safe_name!r}.",
            reversibility="Restore the previous artifact rule body or delete the rule if it was newly created.",
            side_effects=[{"type": "artifact_rule_set", "resource": {"type": "artifact_rule", "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def preview_delete_artifact_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="artifact_rule.delete",
            oid=scoped_oid,
            method="DELETE",
            path=f"insight/{scoped_oid}/artifacts/rules",
            resource={"type": "artifact_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params={"name": safe_name},
            data=None,
            json_body=None,
            expected_effect=f"Delete artifact collection rule {safe_name!r}.",
            reversibility="Recreate the artifact rule from a known-good definition if deletion was unintended.",
            side_effects=[{"type": "artifact_rule_deleted", "resource": {"type": "artifact_rule", "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def list_ingestion_keys(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"insight/{scoped_oid}/ingestion_keys",
            operation="ingestion_key.list",
            oid=scoped_oid,
            resource={"type": "ingestion_key_collection", "id": scoped_oid},
            limit=bounded_limit,
        ).as_dict()

    def list_logging_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/logging",
            operation="logging_rule.list",
            oid=scoped_oid,
            resource={"type": "logging_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def preview_set_logging_rule(
        self,
        oid: str,
        name: str,
        patterns: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        retention_days: int | None = None,
        delete_after: bool = False,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "patterns": require_string_list(patterns, "patterns") or [],
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = checked_platforms
        checked_retention = require_retention_days(retention_days)
        if checked_retention is not None:
            request_data["days_retention"] = str(checked_retention)
        if delete_after:
            request_data["is_delete_after"] = "true"
        return self._preview_service_request(
            operation="logging_rule.set",
            oid=oid,
            service="logging",
            request_data=request_data,
            resource_type="logging_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update logging rule {safe_name!r}.",
            reversibility="Restore the prior logging rule or delete this rule if it was newly created.",
            side_effect_type="logging_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_logging_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="logging_rule.delete",
            oid=oid,
            service="logging",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="logging_rule",
            resource_id=safe_name,
            expected_effect=f"Delete logging rule {safe_name!r}.",
            reversibility="Recreate the logging rule from a known-good definition if deletion was unintended.",
            side_effect_type="logging_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_dr_rules(self, oid: str, namespace: str | None = None, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_namespace = require_dr_namespace(namespace)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/dr-{safe_namespace}/{scoped_oid}",
            operation="dr_rule.list",
            oid=scoped_oid,
            resource={"type": "dr_rule_collection", "id": f"dr-{safe_namespace}", "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def get_dr_rule(self, oid: str, name: str, namespace: str | None = None) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_namespace = require_dr_namespace(namespace)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"hive/dr-{safe_namespace}/{scoped_oid}/{quote(safe_name, safe='')}/data",
            operation="dr_rule.get",
            oid=scoped_oid,
            resource={"type": "dr_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_dr_rule(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        namespace: str | None = None,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_namespace = require_dr_namespace(namespace)
        return self._preview_hive_set(
            operation="dr_rule.set",
            oid=oid,
            hive_name=f"dr-{safe_namespace}",
            name=name,
            data=data,
            resource_type="dr_rule",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_dr_rule(self, oid: str, name: str, namespace: str | None = None, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_namespace = require_dr_namespace(namespace)
        return self._preview_hive_delete(
            operation="dr_rule.delete",
            oid=oid,
            hive_name=f"dr-{safe_namespace}",
            name=name,
            resource_type="dr_rule",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_fp_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "GET",
            f"hive/fp/{scoped_oid}",
            operation="fp_rule.list",
            oid=scoped_oid,
            resource={"type": "fp_rule_collection", "id": "fp", "parent": {"type": "organization", "id": scoped_oid}},
            limit=bounded_limit,
        ).as_dict()

    def get_fp_rule(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "GET",
            f"hive/fp/{scoped_oid}/{quote(safe_name, safe='')}/data",
            operation="fp_rule.get",
            oid=scoped_oid,
            resource={"type": "fp_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
        ).as_dict()

    def preview_set_fp_rule(
        self,
        oid: str,
        name: str,
        data: dict[str, Any],
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._preview_hive_set(
            operation="fp_rule.set",
            oid=oid,
            hive_name="fp",
            name=name,
            data=data,
            resource_type="fp_rule",
            enabled=enabled,
            tags=tags,
            comment=comment,
            expiry=expiry,
            etag=etag,
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_fp_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        return self._preview_hive_delete(
            operation="fp_rule.delete",
            oid=oid,
            hive_name="fp",
            name=name,
            resource_type="fp_rule",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_integrity_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/integrity",
            operation="integrity_rule.list",
            oid=scoped_oid,
            resource={"type": "integrity_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def get_integrity_rule(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        result = self._request(
            "POST",
            f"service/{scoped_oid}/integrity",
            operation="integrity_rule.get",
            oid=scoped_oid,
            resource={"type": "integrity_rule", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params({"action": "list_rules"}),
        ).as_dict()
        if result.get("ok") and isinstance(result.get("data"), dict):
            rules = result["data"]
            if safe_name in rules:
                result["data"] = rules[safe_name]
                result["meta"]["summary"] = summarize_data(result["data"])
            else:
                result["ok"] = False
                result["data"] = None
                result["error"] = {
                    "code": "resource_not_found",
                    "class": "not_found",
                    "message": f"Integrity rule {safe_name!r} was not found.",
                    "retryable": False,
                    "same_input_retryable": False,
                    "suggested_next_actions": ["Call lc_list_integrity_rules to inspect available rule names."],
                }
                result["meta"]["summary"] = {"shape": "empty"}
        return result

    def preview_set_integrity_rule(
        self,
        oid: str,
        name: str,
        patterns: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "patterns": require_string_list(patterns, "patterns") or [],
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = checked_tags
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = checked_platforms
        return self._preview_service_request(
            operation="integrity_rule.set",
            oid=oid,
            service="integrity",
            request_data=request_data,
            resource_type="integrity_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update integrity rule {safe_name!r}.",
            reversibility="Restore the prior integrity rule or delete this rule if it was newly created.",
            side_effect_type="integrity_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_integrity_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="integrity_rule.delete",
            oid=oid,
            service="integrity",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="integrity_rule",
            resource_id=safe_name,
            expected_effect=f"Delete integrity rule {safe_name!r}.",
            reversibility="Recreate the integrity rule from a known-good definition if deletion was unintended.",
            side_effect_type="integrity_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def validate_usp_mapping(
        self,
        oid: str,
        platform: str,
        mapping: dict[str, Any] | None = None,
        mappings: list[dict[str, Any]] | None = None,
        text_input: str | None = None,
        json_input: dict[str, Any] | list[dict[str, Any]] | None = None,
        hostname: str | None = None,
        indexing: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        body: dict[str, Any] = {"platform": require_token(platform, "platform")}
        checked_mapping = require_dict(mapping, "mapping")
        if checked_mapping is not None:
            body["mapping"] = checked_mapping
        checked_mappings = require_dict_list(mappings, "mappings", maximum=100)
        if checked_mappings is not None:
            body["mappings"] = checked_mappings
        if text_input is not None:
            if not isinstance(text_input, str) or len(text_input.encode()) > 100_000 or "\x00" in text_input:
                raise ValidationError("text_input must be a string under 100000 bytes without NUL bytes")
            body["text_input"] = text_input
        if json_input is not None:
            if isinstance(json_input, dict):
                body["json_input"] = [require_json_size(json_input, "json_input")]
            elif isinstance(json_input, list) and all(isinstance(item, dict) for item in json_input):
                body["json_input"] = require_json_size(json_input, "json_input")
            else:
                raise ValidationError("json_input must be an object or list of objects")
        if hostname is not None:
            body["hostname"] = require_token(hostname, "hostname")
        checked_indexing = require_dict(indexing, "indexing")
        if checked_indexing is not None:
            body["indexing"] = checked_indexing
        require_json_size(body, "USP validation payload")
        return self._request(
            "POST",
            f"usp/validate/{scoped_oid}",
            operation="usp.validate",
            oid=scoped_oid,
            resource={"type": "usp_validation", "id": scoped_oid},
            json_body=body,
        ).as_dict()

    def list_yara_rules(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_rule.list",
            oid=scoped_oid,
            resource={"type": "yara_rule_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_rules"}),
            limit=bounded_limit,
        ).as_dict()

    def preview_yara_scan(
        self,
        oid: str,
        sensor_id: str,
        rule: str,
        timeout_seconds: int | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_sensor_id = require_oid(sensor_id)
        if not isinstance(rule, str) or not rule.strip() or len(rule.encode()) > 200_000 or "\x00" in rule:
            raise ValidationError("rule must be a non-empty YARA source string under 200000 bytes")
        request_data: dict[str, Any] = {"action": "scan", "sid": safe_sensor_id, "rule": rule}
        if timeout_seconds is not None:
            request_data["timeout"] = str(require_seconds(timeout_seconds, "timeout_seconds", minimum=1, maximum=3600))
        return self._preview_service_request(
            operation="yara.scan",
            oid=oid,
            service="yara",
            request_data=request_data,
            resource_type="yara_scan",
            resource_id=safe_sensor_id,
            expected_effect=f"Run an ad-hoc YARA scan on sensor {safe_sensor_id}.",
            reversibility="YARA scan execution is not reversible; inspect returned job/results and take compensating action if needed.",
            side_effect_type="yara_scan_started",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_set_yara_rule(
        self,
        oid: str,
        name: str,
        sources: list[str] | str,
        tags: list[str] | str | None = None,
        platforms: list[str] | str | None = None,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        request_data: dict[str, Any] = {
            "action": "add_rule",
            "name": safe_name,
            "sources": json.dumps(require_string_list(sources, "sources") or []),
        }
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            request_data["tags"] = json.dumps(checked_tags)
        checked_platforms = require_string_list(platforms, "platforms")
        if checked_platforms is not None:
            request_data["platforms"] = json.dumps(checked_platforms)
        return self._preview_service_request(
            operation="yara_rule.set",
            oid=oid,
            service="yara",
            request_data=request_data,
            resource_type="yara_rule",
            resource_id=safe_name,
            expected_effect=f"Create or update YARA rule {safe_name!r}.",
            reversibility="Restore the prior YARA rule or delete this rule if it was newly created.",
            side_effect_type="yara_rule_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_yara_rule(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="yara_rule.delete",
            oid=oid,
            service="yara",
            request_data={"action": "remove_rule", "name": safe_name},
            resource_type="yara_rule",
            resource_id=safe_name,
            expected_effect=f"Delete YARA rule {safe_name!r}.",
            reversibility="Recreate the YARA rule from a known-good definition if deletion was unintended.",
            side_effect_type="yara_rule_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_yara_sources(self, oid: str, limit: int = 100) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        bounded_limit = require_limit(limit)
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_source.list",
            oid=scoped_oid,
            resource={"type": "yara_source_collection", "id": scoped_oid},
            params=service_request_params({"action": "list_sources"}),
            limit=bounded_limit,
        ).as_dict()

    def get_yara_source(self, oid: str, name: str) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        return self._request(
            "POST",
            f"service/{scoped_oid}/yara",
            operation="yara_source.get",
            oid=scoped_oid,
            resource={"type": "yara_source", "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params({"action": "get_source", "name": safe_name}),
        ).as_dict()

    def preview_set_yara_source(self, oid: str, name: str, source: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        if not isinstance(source, str) or not source.strip() or len(source.encode()) > 200_000 or "\x00" in source:
            raise ValidationError("source must be a non-empty YARA source string under 200000 bytes")
        return self._preview_service_request(
            operation="yara_source.set",
            oid=oid,
            service="yara",
            request_data={"action": "add_source", "name": safe_name, "source": source},
            resource_type="yara_source",
            resource_id=safe_name,
            expected_effect=f"Create or update YARA source {safe_name!r}.",
            reversibility="Restore the prior YARA source or delete this source if it was newly created.",
            side_effect_type="yara_source_set",
            token_ttl_seconds=token_ttl_seconds,
        )

    def preview_delete_yara_source(self, oid: str, name: str, token_ttl_seconds: int = 300) -> dict[str, Any]:
        safe_name = require_token(name, "name")
        return self._preview_service_request(
            operation="yara_source.delete",
            oid=oid,
            service="yara",
            request_data={"action": "remove_source", "name": safe_name},
            resource_type="yara_source",
            resource_id=safe_name,
            expected_effect=f"Delete YARA source {safe_name!r}.",
            reversibility="Recreate the YARA source from a known-good definition if deletion was unintended.",
            side_effect_type="yara_source_deleted",
            token_ttl_seconds=token_ttl_seconds,
        )

    def list_pending_mutations(self) -> dict[str, Any]:
        self._prune_expired_mutations()
        now = time.time()
        previews = [self._preview_data(mutation, now) for mutation in self._pending_mutations.values()]
        return ToolResponse(
            ok=True,
            operation="mutation.pending.list",
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "mutation_preview_collection", "id": "local"},
            state={"current": "ready"},
            data={"previews": previews},
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "object", "previews_count": len(previews)}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def cancel_mutation(self, confirmation_token: str) -> dict[str, Any]:
        token = require_confirmation_token(confirmation_token)
        self._prune_expired_mutations()
        mutation = self._pending_mutations.pop(token, None)
        if mutation is None:
            return self._mutation_token_error(
                "mutation.cancel",
                token,
                "mutation_preview_not_found",
                "No active mutation preview exists for that confirmation token.",
            )
        return ToolResponse(
            ok=True,
            operation="mutation.cancel",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=mutation.resource,
            state={"previous": "pending", "current": "cancelled"},
            data={"cancelled_operation": mutation.operation, "confirmation_token": token},
            side_effects=[{"type": "local_preview_deleted", "resource": mutation.resource}],
            warnings=[],
            meta={"summary": {"cancelled": True, "operation": mutation.operation}, "truncated": False},
            observed_at=observed_at(),
        ).as_dict()

    def preview_add_sensor_tag(
        self,
        oid: str,
        sensor_id: str,
        tag: str,
        ttl_seconds: int = 0,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_tag = require_token(tag, "tag")
        ttl = require_ttl_seconds(ttl_seconds)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        data = {"tags": safe_tag, "ttl": ttl}
        return self._create_mutation_preview(
            operation="sensor.tag.add",
            oid=scoped_oid,
            method="POST",
            path=f"{safe_sensor_id}/tags",
            resource={
                "type": "sensor_tag",
                "id": safe_tag,
                "parent": {"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            },
            params=data,
            data=None,
            json_body=None,
            expected_effect=f"Add tag {safe_tag!r} to sensor {safe_sensor_id}.",
            reversibility="Remove the same tag from the sensor. TTL 0 means no automatic expiry.",
            side_effects=[
                {
                    "type": "sensor_tag_added",
                    "resource": {"type": "sensor", "id": safe_sensor_id},
                    "tag": safe_tag,
                    "ttl_seconds": ttl,
                }
            ],
            token_ttl_seconds=token_ttl,
        )

    def preview_remove_sensor_tag(
        self,
        oid: str,
        sensor_id: str,
        tag: str,
        token_ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        safe_tag = require_token(tag, "tag")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation="sensor.tag.remove",
            oid=scoped_oid,
            method="DELETE",
            path=f"{safe_sensor_id}/tags",
            resource={
                "type": "sensor_tag",
                "id": safe_tag,
                "parent": {"type": "sensor", "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            },
            params={"tag": safe_tag},
            data=None,
            json_body=None,
            expected_effect=f"Remove tag {safe_tag!r} from sensor {safe_sensor_id}.",
            reversibility="Add the same tag back to the sensor if removal was unintended.",
            side_effects=[
                {
                    "type": "sensor_tag_removed",
                    "resource": {"type": "sensor", "id": safe_sensor_id},
                    "tag": safe_tag,
                }
            ],
            token_ttl_seconds=token_ttl,
        )

    def confirm_mutation(self, confirmation_token: str) -> dict[str, Any]:
        token = require_confirmation_token(confirmation_token)
        self._prune_expired_mutations()
        mutation = self._pending_mutations.pop(token, None)
        if mutation is None:
            return self._mutation_token_error(
                "mutation.confirm",
                token,
                "mutation_preview_not_found",
                "No active mutation preview exists for that confirmation token.",
            )
        response = self._request(
            mutation.method,
            mutation.path,
            operation="mutation.confirm",
            oid=mutation.oid,
            resource=mutation.resource,
            base_url=mutation.base_url,
            params=mutation.params,
            data=mutation.data,
            json_body=mutation.json_body,
            extra_headers=mutation.extra_headers,
            side_effects=mutation.side_effects,
        ).as_dict()
        response["data"] = {
            "confirmed_operation": mutation.operation,
            "confirmed_preview": self._preview_data(mutation, time.time(), include_token=False),
            "result": response.get("data"),
        }
        response["meta"]["summary"]["confirmed_operation"] = mutation.operation
        return response

    def _vulnerability_query(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        sort_by: str | None = None,
        sort_asc: bool | None = None,
        filters: dict[str, list[str]] | None = None,
        search: dict[str, Any] | None = None,
        include_tags: bool | None = None,
        include_enrichment: bool | None = None,
        filter_via_state: bool | None = None,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if cursor is not None:
            data["cursor"] = require_token(cursor, "cursor")
        if limit is not None:
            data["limit"] = limit
        if sort_by is not None:
            data["sort_by"] = require_token(sort_by, "sort_by")
        if sort_asc is not None:
            data["sort_asc"] = require_bool_or_none(sort_asc, "sort_asc")
        checked_filters = require_vuln_filters(filters)
        if checked_filters is not None:
            data["filters"] = checked_filters
        checked_search = require_vuln_search(search)
        if checked_search is not None:
            data["search"] = checked_search
        if include_tags is not None:
            data["include_tags"] = require_bool_or_none(include_tags, "include_tags")
        if include_enrichment is not None:
            data["include_enrichment"] = require_bool_or_none(include_enrichment, "include_enrichment")
        if filter_via_state is not None:
            data["filter_via_state"] = require_bool_or_none(filter_via_state, "filter_via_state")
        return data

    def _extension_request(
        self,
        oid: str,
        action: str,
        data: dict[str, Any],
        *,
        operation: str,
        resource: dict[str, Any],
        limit: int = 100,
    ) -> dict[str, Any]:
        result = self._request(
            "POST",
            "extension/request/ext-vulnerability-reporting",
            operation=operation,
            oid=oid,
            resource=resource,
            params=extension_request_params(oid, action, data),
            limit=limit,
        ).as_dict()
        payload = result.get("data")
        if result.get("ok") and isinstance(payload, dict) and "data" in payload:
            unwrapped, truncated = bound_output(payload["data"], limit)
            result["data"] = unwrapped
            result["meta"]["truncated"] = bool(result["meta"].get("truncated") or truncated)
            result["meta"]["summary"] = summarize_data(unwrapped)
            if truncated:
                result["meta"]["suggested_next_actions"] = [
                    "Repeat with a lower limit, narrower filters, or a pagination cursor."
                ]
        return result

    def _request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        oid: str | None = None,
        resource: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        limit: int = 100,
        base_url: str | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        no_auth: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> ToolResponse:
        started = time.time()
        request_id = f"req_{uuid.uuid4().hex}"
        root = (base_url or f"{self.api_root}/v1").rstrip("/")
        url = f"{root}/{path.lstrip('/')}"
        headers = {"User-Agent": "limacharlie-mcp/0.1.0"}
        try:
            if not no_auth:
                token_oid = oid or os.environ.get("LC_OID")
                token = self._get_jwt(token_oid)
                headers["Authorization"] = f"Bearer {token}"
            if extra_headers:
                headers.update(extra_headers)
            response = self.http.request(
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                json=json_body,
                timeout=self.timeout_seconds,
            )
            duration_ms = int((time.time() - started) * 1000)
        except (httpx.HTTPError, TimeoutError) as exc:
            duration_ms = int((time.time() - started) * 1000)
            self._audit(operation, oid, method, url, params, None, duration_ms, 0, str(exc)[:500])
            return ToolResponse(
                ok=False,
                operation=operation,
                data=None,
                error=classify_error(None, None, f"LimaCharlie API request failed: {exc}"),
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )
        except ValidationError as exc:
            raise exc
        except Exception as exc:
            duration_ms = int((time.time() - started) * 1000)
            self._audit(operation, oid, method, url, params, None, duration_ms, 0, str(exc)[:500])
            return ToolResponse(
                ok=False,
                operation=operation,
                data=None,
                error=classify_error(None, None, str(exc)),
                meta={"duration_ms": duration_ms, "summary": {"shape": "empty"}, "truncated": False},
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )

        raw_text = response.text or ""
        parsed_response = self._parse_response(response)
        data = redact_sensitive(normalize_api_data(parsed_response))
        safe_excerpt = redacted_response_excerpt(data, raw_text)
        self._audit(operation, oid, method, url, params, response.status_code, duration_ms, len(raw_text), safe_excerpt)
        meta = {
            "duration_ms": duration_ms,
            "status_code": response.status_code,
            "truncated": False,
        }
        if response.status_code < 200 or response.status_code >= 300:
            meta["summary"] = summarize_data(data)
            return ToolResponse(
                ok=False,
                operation=operation,
                data=data,
                error=classify_error(response.status_code, data, safe_excerpt),
                meta=meta,
                request_id=request_id,
                resource=resource,
                observed_at=observed_at(),
            )
        data, truncated = bound_output(data, limit)
        meta["truncated"] = truncated
        meta["summary"] = summarize_data(data)
        if truncated:
            meta["suggested_next_actions"] = ["Repeat with a narrower query window or smaller selector scope."]
        return ToolResponse(
            ok=True,
            operation=operation,
            data=data,
            meta=meta,
            request_id=request_id,
            resource=resource,
            side_effects=side_effects or [],
            observed_at=observed_at(),
        )

    def _local_response(
        self,
        operation: str,
        data: Any,
        *,
        resource: dict[str, Any] | None = None,
        state: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        bounded, truncated = bound_output(data, limit)
        return ToolResponse(
            ok=True,
            operation=operation,
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state=state or {},
            data=bounded,
            side_effects=side_effects or [],
            warnings=warnings or [],
            meta={"summary": summarize_data(bounded), "truncated": truncated},
            observed_at=observed_at(),
        ).as_dict()

    def _sensor_state_preview(
        self,
        *,
        operation: str,
        oid: str,
        sensor_id: str,
        method: str,
        path_suffix: str,
        resource_type: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_sensor_id = require_oid(sensor_id)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method=method,
            path=f"{safe_sensor_id}/{path_suffix}",
            resource={"type": resource_type, "id": safe_sensor_id, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"{expected_effect} Target sensor: {safe_sensor_id}.",
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": "sensor", "id": safe_sensor_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_mutation(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource_type: str,
        resource_id: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_body: Any | None = None,
        parent_oid: str | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        resource: dict[str, Any] = {"type": resource_type, "id": resource_id}
        if parent_oid is not None:
            resource["parent"] = {"type": "organization", "id": parent_oid}
        return self._create_mutation_preview(
            operation=operation,
            oid=oid,
            method=method,
            path=path,
            resource=resource,
            base_url=base_url,
            params=params,
            data=data,
            json_body=json_body,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_group_email_mutation(
        self,
        operation: str,
        method: str,
        group_id: str,
        email: str,
        path_suffix: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_email = require_email(email)
        return self._preview_mutation(
            operation=operation,
            oid="-",
            method=method,
            path=f"groups/{quote(safe_group_id, safe='')}/{path_suffix}",
            resource_type=operation.rsplit(".", 1)[0].replace(".", "_"),
            resource_id=f"{safe_group_id}:{safe_email}",
            params={"member_email": safe_email},
            expected_effect=f"{operation} for {safe_email} on group {safe_group_id}.",
            reversibility="Apply the opposite group membership or ownership operation if this was unintended.",
            side_effect_type=side_effect_type,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _preview_group_org_mutation(
        self,
        operation: str,
        method: str,
        group_id: str,
        member_oid: str,
        side_effect_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        safe_group_id = require_path_segment(group_id, "group_id")
        safe_member_oid = require_oid(member_oid)
        return self._preview_mutation(
            operation=operation,
            oid="-",
            method=method,
            path=f"groups/{quote(safe_group_id, safe='')}/orgs",
            resource_type="group_org_membership",
            resource_id=f"{safe_group_id}:{safe_member_oid}",
            params={"oid": safe_member_oid},
            expected_effect=f"{operation} for org {safe_member_oid} on group {safe_group_id}.",
            reversibility="Apply the opposite group org membership operation if this was unintended.",
            side_effect_type=side_effect_type,
            token_ttl_seconds=token_ttl_seconds,
        )

    def _extension_definition_id(self, extension_definition: dict[str, Any], extension_name: str | None) -> str:
        if extension_name is not None:
            return require_extension_name(extension_name)
        raw_name = extension_definition.get("name") or extension_definition.get("extension_name") or extension_definition.get("id")
        if raw_name is None:
            return "extension_definition"
        return require_extension_name(str(raw_name))

    def _hive_set_params(
        self,
        data: dict[str, Any],
        *,
        enabled: bool | None = None,
        tags: list[str] | str | None = None,
        comment: str | None = None,
        expiry: int | None = None,
        etag: str | None = None,
    ) -> dict[str, Any]:
        require_dict(data, "data")
        params: dict[str, Any] = {"data": json.dumps(data)}
        usr_mtd: dict[str, Any] = {}
        if enabled is not None:
            usr_mtd["enabled"] = require_bool_or_none(enabled, "enabled")
        checked_tags = require_string_list(tags, "tags")
        if checked_tags is not None:
            usr_mtd["tags"] = checked_tags
        if comment is not None:
            if not isinstance(comment, str) or len(comment) > 1000 or "\x00" in comment:
                raise ValidationError("comment must be a string under 1000 characters without NUL bytes")
            usr_mtd["comment"] = comment
        if expiry is not None:
            usr_mtd["expiry"] = require_unix_seconds(expiry, "expiry")
        if usr_mtd:
            params["usr_mtd"] = json.dumps(usr_mtd)
        if etag is not None:
            params["etag"] = require_token(etag, "etag")
        return params

    def _preview_hive_set(
        self,
        *,
        operation: str,
        oid: str,
        hive_name: str,
        name: str,
        data: dict[str, Any],
        resource_type: str,
        enabled: bool | None,
        tags: list[str] | str | None,
        comment: str | None,
        expiry: int | None,
        etag: str | None,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"hive/{hive_name}/{scoped_oid}/{quote(safe_name, safe='')}/data",
            resource={"type": resource_type, "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            params=self._hive_set_params(data, enabled=enabled, tags=tags, comment=comment, expiry=expiry, etag=etag),
            data=None,
            json_body=None,
            expected_effect=f"Create or update {resource_type} {safe_name!r} in hive {hive_name}.",
            reversibility="Restore the prior hive record value or delete this record if it was newly created.",
            side_effects=[{"type": f"{resource_type}_set", "resource": {"type": resource_type, "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_hive_delete(
        self,
        *,
        operation: str,
        oid: str,
        hive_name: str,
        name: str,
        resource_type: str,
        token_ttl_seconds: int,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        safe_name = require_token(name, "name")
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="DELETE",
            path=f"hive/{hive_name}/{scoped_oid}/{quote(safe_name, safe='')}",
            resource={"type": resource_type, "id": safe_name, "parent": {"type": "organization", "id": scoped_oid}},
            data=None,
            json_body=None,
            expected_effect=f"Delete {resource_type} {safe_name!r} from hive {hive_name}.",
            reversibility="Recreate the hive record from a known-good backup if deletion was unintended.",
            side_effects=[{"type": f"{resource_type}_deleted", "resource": {"type": resource_type, "id": safe_name}}],
            token_ttl_seconds=token_ttl,
        )

    def _preview_service_request(
        self,
        *,
        operation: str,
        oid: str,
        service: str,
        request_data: dict[str, Any],
        resource_type: str,
        resource_id: str,
        expected_effect: str,
        reversibility: str,
        side_effect_type: str,
        token_ttl_seconds: int,
        is_async: bool = False,
    ) -> dict[str, Any]:
        scoped_oid = require_oid(oid)
        token_ttl = require_seconds(token_ttl_seconds, "token_ttl_seconds", minimum=30, maximum=900)
        return self._create_mutation_preview(
            operation=operation,
            oid=scoped_oid,
            method="POST",
            path=f"service/{scoped_oid}/{service}",
            resource={"type": resource_type, "id": resource_id, "parent": {"type": "organization", "id": scoped_oid}},
            params=service_request_params(request_data, is_async=is_async),
            data=None,
            json_body=None,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=[{"type": side_effect_type, "resource": {"type": resource_type, "id": resource_id}}],
            token_ttl_seconds=token_ttl,
        )

    def _create_mutation_preview(
        self,
        *,
        operation: str,
        oid: str,
        method: str,
        path: str,
        resource: dict[str, Any],
        data: dict[str, Any] | None,
        json_body: Any | None,
        expected_effect: str,
        reversibility: str,
        side_effects: list[dict[str, Any]],
        token_ttl_seconds: int,
        params: dict[str, Any] | None = None,
        base_url: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self._prune_expired_mutations()
        token = f"mut_{uuid.uuid4().hex}"
        mutation = PendingMutation(
            token=token,
            expires_at=time.time() + token_ttl_seconds,
            operation=operation,
            oid=oid,
            method=method,
            path=path,
            resource=resource,
            base_url=base_url,
            params=params,
            data=data,
            json_body=json_body,
            extra_headers=extra_headers,
            expected_effect=expected_effect,
            reversibility=reversibility,
            side_effects=side_effects,
        )
        self._pending_mutations[token] = mutation
        preview = self._preview_data(mutation, time.time())
        return ToolResponse(
            ok=True,
            operation=f"{operation}.preview",
            request_id=f"req_{uuid.uuid4().hex}",
            resource=resource,
            state={"current": "pending_confirmation"},
            data=preview,
            side_effects=[],
            warnings=["No LimaCharlie change has been made. Call lc_confirm_mutation with confirmation_token to execute."],
            meta={
                "summary": {
                    "preview_operation": operation,
                    "expires_in_seconds": preview["expires_in_seconds"],
                    "requires_confirmation": True,
                },
                "truncated": False,
            },
            observed_at=observed_at(),
        ).as_dict()

    def _preview_data(self, mutation: PendingMutation, now: float, *, include_token: bool = True) -> dict[str, Any]:
        root = (mutation.base_url or f"{self.api_root}/v1").rstrip("/")
        preview = {
            "operation": mutation.operation,
            "http_method": mutation.method,
            "endpoint": f"{root.rstrip('/')}/{mutation.path.lstrip('/')}",
            "oid": mutation.oid,
            "resource": mutation.resource,
            "params": redact_preview_data(mutation.params),
            "data": redact_preview_data(mutation.data),
            "json_body": redact_preview_data(mutation.json_body),
            "headers": redact_preview_data(mutation.extra_headers),
            "expected_effect": mutation.expected_effect,
            "reversibility": mutation.reversibility,
            "expected_side_effects": mutation.side_effects,
            "expires_in_seconds": max(0, int(mutation.expires_at - now)),
        }
        if include_token:
            preview["confirmation_token"] = mutation.token
        return preview

    def _prune_expired_mutations(self) -> None:
        now = time.time()
        expired = [token for token, mutation in self._pending_mutations.items() if mutation.expires_at <= now]
        for token in expired:
            self._pending_mutations.pop(token, None)

    def _mutation_token_error(self, operation: str, token: str, code: str, message: str) -> dict[str, Any]:
        return ToolResponse(
            ok=False,
            operation=operation,
            request_id=f"req_{uuid.uuid4().hex}",
            resource={"type": "mutation_preview", "id": token},
            state={"current": "not_found"},
            data=None,
            side_effects=[],
            warnings=[],
            meta={"summary": {"shape": "empty"}, "truncated": False},
            observed_at=observed_at(),
            error={
                "code": code,
                "class": "not_found",
                "message": message,
                "retryable": False,
                "same_input_retryable": False,
                "suggested_next_actions": [
                    "Create a new preview for the intended mutation.",
                    "Confirm the new token before it expires.",
                ],
            },
        ).as_dict()

    @staticmethod
    def _download_targets(targets: dict[tuple[str, str], str]) -> list[dict[str, str]]:
        return [
            {
                "platform": platform,
                "arch": arch,
                "url": f"https://downloads.limacharlie.io/{path}",
            }
            for (platform, arch), path in sorted(targets.items())
        ]

    def _search_body(
        self,
        oid: str,
        query: str,
        start: int,
        end: int,
        stream: str | None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "oid": oid,
            "query": query,
            "startTime": str(int(start)),
            "endTime": str(int(end)),
        }
        safe_stream = require_search_stream(stream)
        if safe_stream:
            body["stream"] = safe_stream
        return body

    def _search_root(self, oid: str) -> str:
        cached = self._search_roots.get(oid)
        if cached:
            return cached
        result = self.get_org_urls(oid)
        url = ""
        if result.get("ok") and isinstance(result.get("data"), dict):
            urls = result["data"]
            value = urls.get("search") or urls.get("search_api")
            if isinstance(value, str):
                url = value
        if not url:
            url = "https://search.limacharlie.io"
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        root = url.rstrip("/")
        if not root.endswith("/v1"):
            root = f"{root}/v1"
        self._search_roots[oid] = root
        return root

    def _replay_root(self, oid: str) -> str:
        result = self.get_org_urls(oid)
        url = ""
        if result.get("ok") and isinstance(result.get("data"), dict):
            value = result["data"].get("replay")
            if isinstance(value, str):
                url = value
        if not url:
            url = "replay.limacharlie.io"
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _finalize_search_poll(self, result: dict[str, Any], query_id: str, limit: int) -> None:
        data = result.get("data")
        if not isinstance(data, dict):
            result["state"] = {"current": "unknown", "terminal": False, "query_id": query_id}
            return
        results = data.get("results")
        next_token = None
        total_rows_seen = 0
        rows_returned = 0
        truncated = False
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                token = item.get("nextToken") or item.get("next_token")
                if token:
                    next_token = str(token)
                rows = item.get("rows")
                if isinstance(rows, list):
                    total_rows_seen += len(rows)
                    remaining = max(limit - rows_returned, 0)
                    if len(rows) > remaining:
                        item["rows"] = rows[:remaining]
                        truncated = True
                    rows_returned += len(item["rows"])
                    if rows_returned >= limit:
                        truncated = truncated or total_rows_seen > rows_returned
        completed = bool(data.get("completed"))
        if completed and next_token:
            current = "ready_for_next_page"
            terminal = False
        elif completed:
            current = "succeeded"
            terminal = True
        else:
            current = "running"
            terminal = False
        result["state"] = {
            "current": current,
            "terminal": terminal,
            "query_id": query_id,
            "next_poll_in_ms": data.get("nextPollInMs"),
            "checkpoint": {
                "next_token": next_token,
                "rows_returned": rows_returned,
                "rows_seen_before_bounding": total_rows_seen,
                "resume_tool": "lc_poll_search_query" if next_token else None,
            },
        }
        result["meta"]["summary"] = summarize_data(data)
        result["meta"]["summary"]["search_state"] = current
        result["meta"]["summary"]["query_id"] = query_id
        result["meta"]["summary"]["rows_returned"] = rows_returned
        result["meta"]["truncated"] = bool(result["meta"].get("truncated") or truncated)
        if result["meta"]["truncated"]:
            result["meta"]["suggested_next_actions"] = [
                "Repeat with a lower limit, narrower query, or continue from checkpoint.next_token."
            ]
        elif next_token:
            result["meta"]["suggested_next_actions"] = [
                "Call lc_poll_search_query with checkpoint.next_token to retrieve the next page."
            ]
        elif not completed:
            result["meta"]["suggested_next_actions"] = [
                "Wait for next_poll_in_ms, then call lc_poll_search_query again with the same query_id."
            ]

    def _get_jwt(self, oid: str | None, *, force_refresh: bool = False) -> str:
        scoped_oid = "-" if oid == "-" else require_oid(oid or "")
        cached = self._tokens.get(scoped_oid)
        now = time.time()
        if cached and not force_refresh and cached.expires_at - 60 > now:
            return cached.value
        api_key = self._resolve_api_key()
        if not api_key:
            raise RuntimeError("LimaCharlie API credentials are required; configure Vault, LC_API_KEY, or LC_USER_API_KEY")

        data: dict[str, Any] = {"oid": scoped_oid, "secret": api_key}
        if self._uses_user_api_key() and self.uid:
            data["uid"] = self.uid
        response = self.http.request(
            "POST",
            self.jwt_root,
            data=data,
            timeout=self.timeout_seconds,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"JWT exchange failed with status {response.status_code}: {response.text[:300]}")
        payload = self._parse_response(response)
        token = payload.get("jwt") or payload.get("token")
        if not token:
            raise RuntimeError("JWT exchange response did not include a jwt field")
        expires_in = int(payload.get("expires_in") or payload.get("ttl") or 3000)
        self._tokens[scoped_oid] = Token(value=token, expires_at=now + expires_in)
        return token

    @staticmethod
    def _parse_response(response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            return response.json()
        text = response.text
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def _audit(
        self,
        operation: str,
        oid: str | None,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        status_code: int | None,
        duration_ms: int,
        response_bytes: int,
        response_excerpt: str,
    ) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
            "oid": oid,
            "method": method,
            "url": redact_text(url),
            "params": redact_preview_data(params or {}),
            "status_code": status_code,
            "duration_ms": duration_ms,
            "response_bytes": response_bytes,
            "response_excerpt": redact_text(response_excerpt),
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")


def client_from_env() -> LimaCharlieAPI:
    return LimaCharlieAPI()
