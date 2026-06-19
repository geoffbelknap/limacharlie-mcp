# LimaCharlie MCP Surface Map

This map is the implementation checklist for a full-featured, API-only
LimaCharlie MCP. The first rule is that agent-facing tools must be narrow,
bounded, and auditable. Raw API passthrough is not the target shape.

## Implemented Read Suites

### Platform

| Surface | Tools |
| --- | --- |
| Tool discovery | `lc_tool_catalog` |
| Identity and permissions | `lc_auth_whoami`, `lc_auth_status`, `lc_auth_refresh` |
| Org discovery | `lc_list_orgs` |

### Investigation

| Surface | Tools |
| --- | --- |
| Sensors | `lc_list_sensors`, `lc_get_sensor`, `lc_find_sensors_by_tag`, `lc_find_sensors_by_hostname` |
| Events | `lc_list_sensor_events`, `lc_get_sensor_event_overview`, `lc_get_event`, `lc_list_child_events`, `lc_get_event_retention` |
| Detections | `lc_list_detections`, `lc_get_detection` |
| Audit logs | `lc_list_audit_logs` |
| IOCs and Insight objects | `lc_search_ioc` |
| Artifacts | `lc_list_artifacts`, `lc_get_artifact_url` |
| Jobs | `lc_list_jobs`, `lc_get_job`, `lc_wait_job` |
| Tags | `lc_list_tags`, `lc_find_sensors_by_tag` |
| Cases | `lc_list_cases`, `lc_get_case` |

### Administration

| Surface | Tools |
| --- | --- |
| Org inventory | `lc_get_org_info`, `lc_get_org_stats`, `lc_list_org_errors` |
| Users and permissions | `lc_list_users`, `lc_list_user_permissions` |
| API keys | `lc_list_api_keys` |
| Installation keys | `lc_list_installation_keys`, `lc_get_installation_key` |
| Ingestion keys | `lc_list_ingestion_keys` |
| Outputs | `lc_list_outputs` |
| Extensions | `lc_list_extension_subscriptions`, `lc_list_available_extensions`, `lc_get_extension`, `lc_get_extension_schema` |

### Content Review

| Surface | Tools |
| --- | --- |
| Schemas and ontology | `lc_list_schemas`, `lc_get_schema`, `lc_get_ontology`, `lc_list_event_types` |
| MITRE coverage | `lc_get_mitre_report` |
| Artifact rules | `lc_list_artifact_rules` |
| Logging rules | `lc_list_logging_rules` |
| D&R rules | `lc_list_dr_rules`, `lc_get_dr_rule` |
| False-positive rules | `lc_list_fp_rules`, `lc_get_fp_rule` |
| YARA | `lc_list_yara_rules`, `lc_list_yara_sources`, `lc_get_yara_source` |

## Planned Read Coverage

These should stay read-only and bounded:

- Online sensor status and sensor export helpers.
- IP lookup helpers.
- Lookup, playbook, SOP, payload, and safe secret metadata inventory.
- Cloud sensor, exfil, replay, vulnerability, billing, and download inventory.
- Safe extension-specific read actions.
- Search workflows with resumable job/checkpoint status.
- AI memory/session/skill inventory if the API surface is stable enough.

## Planned Mutation Coverage

Mutating workflows must use preview/confirm tools. The preview call should
return the exact HTTP method, endpoint, target org, target resource, expected
effect, reversibility notes, and a short-lived confirmation token. The confirm
call should execute only that exact preview.

Mutation candidates:

- Endpoint tasking.
- Network isolation, seal, delete, and version controls.
- Sensor tag mutation.
- User, group, permission, API key, installation key, ingestion key, and output
  management.
- D&R, YARA, false-positive, lookup, secret, playbook, SOP, and payload writes.
- Extension subscribe, unsubscribe, rekey, and request actions.
- Case creation and updates.
- Artifact collection rule writes.
- Error dismissal and org setting changes.

## Agent Experience Requirements

Every new tool must preserve the current AX contract:

- Stable response envelope with `ok`, `operation`, `request_id`, `resource`,
  `data`, `side_effects`, `meta.summary`, and `observed_at`.
- Structured error object with retryability and suggested next actions.
- Explicit org scope for org data.
- Explicit bounds for lists, history reads, and paginated operations.
- No CLI shell-out and no raw API tunnel.
- Local audit log with no credentials or authorization headers.

## Test Requirements

Each new endpoint needs fake-HTTP unit coverage for:

- URL path and HTTP method.
- Query/body parameters.
- AX envelope shape.
- Error envelope preservation.
- Output bounding/truncation when relevant.
- Compressed LimaCharlie history payload decoding when relevant.
