# LimaCharlie MCP

Standalone local MCP server for LimaCharlie investigation, administration, and
content-review workflows.

This project is a controllable alternative to the hosted LimaCharlie MCP
endpoint. It uses LimaCharlie API surfaces directly, requires explicit
organization scope for org data, records a local audit line for each tool call,
and starts with a broad read-only tool surface.

## Why This Exists

The official LimaCharlie docs describe:

- a hosted HTTP MCP endpoint at `https://mcp.limacharlie.io/mcp`,
- OAuth, JWT, and org API key authentication options,
- CLI and SDK helper surfaces layered on top of the same APIs.

This server is different: it runs locally over stdio, exchanges an org API key
for short-lived LimaCharlie JWTs, refreshes those JWTs automatically, and calls
the APIs directly. That avoids shelling out to the CLI and keeps the MCP
implementation small and reviewable.

## Tool Surface

The server exposes one combined MCP with cataloged suites. The split is visible
in `lc_tool_catalog` and can later become separate server entrypoints without
renaming tools.

### Platform

| Tool | Purpose |
| --- | --- |
| `lc_tool_catalog` | Describe tools, inputs, bounds, side effects, and intended use cases. |
| `lc_auth_whoami` | Show current API identity, optionally scoped to an org or permission check. |
| `lc_auth_status` | Show credential mode and cached JWT freshness without exposing secrets. |
| `lc_auth_refresh` | Force a local JWT refresh from configured API-key credentials. |
| `lc_list_orgs` | List organizations available to the authenticated API key. |

### Investigation

| Tool | Purpose |
| --- | --- |
| `lc_list_sensors` | List sensors for an explicit org, optionally filtered by selector. |
| `lc_get_sensor` | Fetch one sensor by sensor ID. |
| `lc_list_online_sensors` | List currently online sensors or online counts for an org. |
| `lc_list_sensor_events` | List one bounded page of events for a sensor and time window. |
| `lc_get_sensor_event_overview` | Fetch event timeline overview before pulling full events. |
| `lc_get_event` | Fetch one event by atom. |
| `lc_list_child_events` | Fetch child events for a parent atom. |
| `lc_get_event_retention` | Inspect retained event counts for a time window. |
| `lc_list_detections` | List one bounded page of detections for an explicit org and time window. |
| `lc_get_detection` | Fetch one detection by detection ID. |
| `lc_search_ioc` | Search Insight prevalence or locations for an IOC/object. |
| `lc_list_artifacts` | List artifacts for an org, sensor, time window, or cursor. |
| `lc_get_artifact_url` | Request original artifact payload or signed export URL. |
| `lc_list_jobs` | List service jobs for an explicit org and time window. |
| `lc_get_job` | Fetch one service job. |
| `lc_wait_job` | Poll one service job until terminal state or bounded timeout. |
| `lc_list_audit_logs` | List one bounded page of audit logs for a time window. |
| `lc_list_tags` | List tags observed across sensors in an org. |
| `lc_find_sensors_by_tag` | Find sensors with a specific tag. |
| `lc_find_sensors_by_hostname` | Find sensors by hostname prefix. |
| `lc_list_cases` | List cases for an explicit org. |
| `lc_get_case` | Fetch one case by case number. |

### Administration

| Tool | Purpose |
| --- | --- |
| `lc_get_org_info` | Fetch org inventory and quota metadata. |
| `lc_get_org_stats` | Fetch org usage statistics. |
| `lc_list_org_errors` | List current org component errors. |
| `lc_get_org_urls` | Fetch service URLs for sensors, adapters, webhooks, replay, and related connectivity. |
| `lc_get_runtime_metadata` | Fetch runtime metadata, optionally filtered by entity type/name. |
| `lc_get_quota_usage` | Fetch enforced quota usage for capacity checks. |
| `lc_list_groups` | List organization groups accessible to the authenticated identity. |
| `lc_get_group` | Fetch one organization group definition. |
| `lc_list_group_logs` | List audit logs for one organization group. |
| `lc_list_users` | List org users. |
| `lc_list_user_permissions` | List org user permission mappings. |
| `lc_list_api_keys` | List org API key metadata. |
| `lc_list_installation_keys` | List installation key metadata. |
| `lc_get_installation_key` | Fetch one installation key. |
| `lc_list_outputs` | List configured output integrations. |
| `lc_list_extension_subscriptions` | List extension subscriptions for an org. |
| `lc_list_available_extensions` | List globally available extension definitions. |
| `lc_get_extension` | Fetch one extension definition. |
| `lc_get_extension_schema` | Fetch extension schema for an org context. |
| `lc_list_ingestion_keys` | List ingestion key metadata. |

### Content Review

| Tool | Purpose |
| --- | --- |
| `lc_list_schemas` | List event schemas for an org. |
| `lc_get_schema` | Fetch one event schema. |
| `lc_get_ontology` | Fetch LimaCharlie ontology/event definitions. |
| `lc_list_event_types` | List available event types. |
| `lc_get_mitre_report` | Fetch MITRE ATT&CK coverage data. |
| `lc_list_artifact_rules` | List artifact collection rules. |
| `lc_list_logging_rules` | List logging collection rules. |
| `lc_list_dr_rules` | List D&R rules from a hive namespace. |
| `lc_get_dr_rule` | Fetch one D&R rule from a hive namespace. |
| `lc_list_fp_rules` | List false-positive rules. |
| `lc_get_fp_rule` | Fetch one false-positive rule. |
| `lc_list_yara_rules` | List YARA scanning rules. |
| `lc_list_yara_sources` | List YARA source names. |
| `lc_get_yara_source` | Fetch one YARA source. |

### Response

| Tool | Purpose |
| --- | --- |
| `lc_list_pending_mutations` | List local mutation previews that can still be confirmed. |
| `lc_preview_add_sensor_tag` | Preview adding a tag to one sensor, optionally with TTL. |
| `lc_preview_remove_sensor_tag` | Preview removing a tag from one sensor. |
| `lc_confirm_mutation` | Execute the exact typed mutation bound to a preview token. |
| `lc_cancel_mutation` | Cancel a pending local mutation preview without calling LimaCharlie. |

Sensor tag mutation is available only through the preview/confirm contract.
Other writes remain gated until they have typed preview/confirm tools. That
includes tasking, isolation, users, keys, D&R writes, extension subscriptions,
outputs, and case updates.

## Agent Experience Contract

Every tool returns the same envelope:

```json
{
  "ok": true,
  "operation": "sensor.list",
  "request_id": "req_...",
  "resource": {"type": "sensor_collection", "id": "<oid>"},
  "state": {},
  "data": {},
  "side_effects": [],
  "warnings": [],
  "meta": {
    "status_code": 200,
    "duration_ms": 42,
    "truncated": false,
    "summary": {"sensors_count": 12}
  },
  "observed_at": "2026-06-18T23:00:00Z"
}
```

Errors use structured classes and retryability:

```json
{
  "ok": false,
  "operation": "sensor.list",
  "error": {
    "code": "forbidden",
    "class": "policy",
    "message": "missing permission",
    "retryable": false,
    "same_input_retryable": false,
    "suggested_next_actions": [
      "Verify LC_API_KEY and org scope.",
      "Check the required LimaCharlie permission for this operation."
    ]
  },
  "side_effects": []
}
```

The design follows the AX rule that after each tool call an agent should know
what happened, what changed, what proves it, and what to do next.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

Set stable API-key credentials. Users do not need to generate or paste JWTs;
the MCP server handles LimaCharlie JWT exchange and refresh in memory.

```bash
export LC_API_KEY="your-org-api-key"
```

Org-scoped tools always require an explicit `oid`. Discovery tools
(`lc_list_orgs`, unscoped `lc_auth_whoami`) use LimaCharlie's minimal JWT org
placeholder internally.

## MCP Client Config

Example stdio config:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp",
      "env": {
        "LC_API_KEY": "your-organization-api-key"
      }
    }
  }
}
```

After starting the server, call `lc_auth_status`. If credentials are configured
correctly, call `lc_auth_refresh` only when you want to force a new JWT after
credential rotation or auth troubleshooting.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `LC_API_KEY` | required | LimaCharlie API key used for JWT exchange. |
| `LC_UID` | unset | Optional user ID for user-scoped API keys. |
| `LC_API_ROOT` | `https://api.limacharlie.io` | LimaCharlie API root. |
| `LC_JWT_ROOT` | `https://jwt.limacharlie.io` | JWT exchange root. |
| `LC_CASES_API_ROOT` | `https://cases.limacharlie.io` | Cases API root. |
| `LC_MCP_TIMEOUT_SECONDS` | `30` | Per-command timeout. |
| `LC_MCP_AUDIT_LOG` | platform cache dir | JSONL audit log path. |

The audit log records timestamp, purpose, org ID, HTTP method, URL, query
parameters, status code, duration, and output size. It does not record
credentials or authorization headers.

See [docs/onboarding-auth.md](docs/onboarding-auth.md) for the onboarding,
auth, and reauth flow.

## Development

```bash
python -m pytest tests/ -q
```

The tests do not require LimaCharlie credentials or network access.

## Documentation Boundary

User-facing setup and auth docs live in this repo. Internal coverage matrices,
AX reviews, tool contracts, implementation plans, and work tracking live in the
[LimaCharlie MCP Notion space](https://app.notion.com/p/384bc6319c93816d92f3db88b86f8f19).

## References

- LimaCharlie docs: https://docs.limacharlie.io/
- AI assistant setup: https://docs.limacharlie.io/6-developer-guide/mcp-server/
- Python SDK docs: https://docs.limacharlie.io/6-developer-guide/sdks/python-sdk-v4/
- API key docs: https://docs.limacharlie.io/7-administration/access/api-keys/
- Onboarding and auth: [docs/onboarding-auth.md](docs/onboarding-auth.md)
