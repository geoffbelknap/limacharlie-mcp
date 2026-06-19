# SDK Coverage Matrix

This matrix tracks progress toward a full-featured, API-only LimaCharlie MCP.
Status values:

- `implemented`: useful read coverage exists.
- `partial`: some important coverage exists, but SDK surface remains.
- `planned-read`: next safe read-only coverage candidate.
- `preview-confirm`: mutating or sensitive workflow that needs preview/confirm.
- `deferred`: not a good first-class MCP surface yet.

| SDK module | Status | Current MCP coverage | Remaining work |
| --- | --- | --- | --- |
| `ai.py` | planned-read | None | Sessions, usage, auth status, generated outputs; mutations/session control need review. |
| `ai_memory.py` | planned-read | None | List/get memory records; writes need preview/confirm. |
| `ai_session.py` | deferred | None | Attachment model needs workflow design. |
| `api_keys.py` | partial | `lc_list_api_keys` | Create/delete keys require preview/confirm and secret-handling policy. |
| `arl.py` | planned-read | None | ARL get/read tool. |
| `artifacts.py` | partial | `lc_list_artifacts`, `lc_get_artifact_url`, `lc_list_artifact_rules` | Upload and rule writes require preview/confirm. |
| `billing.py` | planned-read | None | Billing status/details/plans/invoice URL reads. |
| `cases.py` | partial | `lc_list_cases`, `lc_get_case` | Case notes, detections, entities, telemetry, updates, merge, create. Writes need preview/confirm. |
| `configs.py` | preview-confirm | None | Fetch is read-safe; push writes need preview/confirm. |
| `downloads.py` | planned-read | None | Target listing and binary download metadata; actual binary fetch needs artifact handling. |
| `dr_rules.py` | partial | `lc_list_dr_rules`, `lc_get_dr_rule` | Create/update/delete/validate require preview/confirm. |
| `exfil.py` | planned-read | None | List exfil rules. Create/delete need preview/confirm. |
| `extensions.py` | partial | `lc_list_extension_subscriptions`, `lc_list_available_extensions`, `lc_get_extension`, `lc_get_extension_schema` | Subscribe/unsubscribe/rekey/request need typed tools and preview/confirm where mutating. |
| `feedback.py` | planned-read | None | Channel listing. Approval/question requests need workflow design. |
| `firehose.py` | deferred | None | Streaming client should be separate from bounded stdio tools. |
| `fp_rules.py` | partial | `lc_list_fp_rules`, `lc_get_fp_rule` | Create/delete need preview/confirm. |
| `groups.py` | planned-read | None | List/get/logs reads. Membership/permission mutations need preview/confirm. |
| `hive.py` | partial | D&R and FP hives only | Typed read tools for lookup, secret metadata, SOP/playbook/payload hives; writes need preview/confirm. |
| `ingestion_keys.py` | partial | `lc_list_ingestion_keys` | Create/delete need preview/confirm. |
| `insight.py` | partial | `lc_search_ioc` | Batch search and Insight-enabled status. |
| `installation_keys.py` | partial | `lc_list_installation_keys`, `lc_get_installation_key` | Create/delete need preview/confirm. |
| `integrity.py` | planned-read | None | List/get integrity rules. Create/delete need preview/confirm. |
| `jobs.py` | implemented | `lc_list_jobs`, `lc_get_job`, `lc_wait_job` | Delete job, if needed, requires preview/confirm. |
| `logging_rules.py` | partial | `lc_list_logging_rules` | Get is client-side from list; create/delete need preview/confirm. |
| `organization.py` | partial | Org info, stats, errors, schemas, ontology, event types, MITRE, users, permissions, API keys, installation keys, ingestion keys, outputs, extensions, tags, hostname search, audit logs | Configs, URLs, runtime metadata, groups, services, online sensors, export sensors, quotas/name/error dismissal need additional read or preview/confirm tools. |
| `outputs.py` | partial | `lc_list_outputs` | Create/delete need preview/confirm and secret-handling policy. |
| `payloads.py` | planned-read | None | List/download metadata; upload/delete need preview/confirm. |
| `replay.py` | planned-read | None | Validate and scan reads; run may need preview/confirm depending side effects. |
| `search.py` | planned-read | None | Validate/estimate/execute with resumable job/checkpoint handling. |
| `sensor.py` | partial | Sensor list/get, events, overview, event by atom, children, retention, tag/hostname search | Tags on one sensor, online status/wait, tasking, isolate/rejoin, seal/unseal, delete, version controls. Mutations need preview/confirm. |
| `spout.py` | deferred | None | Streaming client should be separate from bounded stdio tools. |
| `users.py` | partial | `lc_list_users`, `lc_list_user_permissions` | Invite/remove/permissions/role require preview/confirm. |
| `usp.py` | planned-read | None | USP validation tool. |
| `vulnerability.py` | planned-read | None | CVE/host/package/dashboard reads. Resolution writes need preview/confirm. |
| `yara.py` | partial | `lc_list_yara_rules`, `lc_list_yara_sources`, `lc_get_yara_source` | Scan may be executable; add/delete rules/sources need preview/confirm. |

## Near-Term Read Tranches

1. Groups, online sensors, org runtime metadata, org URLs, and service listing.
2. Vulnerability extension reads.
3. Search validate/estimate/execute with job/checkpoint state.
4. Billing/download/payload/exfil/integrity reads.
5. AI session and memory inventory after reviewing response shape and privacy.

## Mutation Tranche

Do not add writes one by one as direct MCP tools. Build preview/confirm first,
then add typed mutation families:

1. Low-risk metadata mutations such as tags and case notes.
2. Content mutations such as D&R, FP, YARA, logging, artifact rules.
3. Administration mutations such as users, keys, outputs, extensions.
4. Endpoint actions such as tasking, isolation, seal, version, and deletion.
