# Geoff's LimaCharlie MCP

A local MCP for LimaCharlie setup, administration, investigations, and tuning.

This is an alternative to the LimaCharlie hosted MCP. It uses LimaCharlie API surfaces directly, requires explicit
scope for data, records a local audit lines for each tool call, and can start adding value even with just read-only access.

## Why?

_Doesn't LimaCharlie already have an MCP?_
Yes.

_Is something wrong with the LimaCharlie MCP?_
Nope. 

_Then... why?_
I love LimaCharlie, I had some free time, and wanted something that made LimaCharlie more accessible to people who dont live in 

The official LimaCharlie docs describe:

- a hosted HTTP MCP endpoint at `https://mcp.limacharlie.io/mcp`,
- OAuth, JWT, and org API key authentication options,
- CLI and SDK helper surfaces layered on top of the same APIs.

This server is different: it runs locally over stdio, exchanges an org API key
for short-lived LimaCharlie JWTs, refreshes those JWTs automatically, and calls
the APIs directly. That avoids shelling out to the CLI and keeps the MCP
implementation small and reviewable.

## Install From Geoff's Plugins

The easiest agent-facing install path is the `geoffs-plugins` marketplace:

```bash
/plugin marketplace add geoffbelknap/geoffs-plugins
/plugin install limacharlie-mcp@geoffs-plugins
```

The plugin handles running the MCP server. Configure auth once before calling
LimaCharlie tools.

By default, the setup uses a managed local [Vault](https://github.com/hashicorp/vault) so the long-lived
LimaCharlie API key is not accidentally stored in chat history, `.env` files, MCP client
configuration, or audit logs. The MCP uses that protected key to mint
short-lived LimaCharlie JWTs when tools need API access.

## First-Time Auth Setup

You need two values from LimaCharlie: an organization ID and an organization
API key.

1. Open [LimaCharlie](https://app.limacharlie.io/), login, and choose your organization.
2. Copy the org ID from the URL: `app.limacharlie.io/orgs/<org-id>/...`.
3. Open a terminal on the host running your MCP, swap in your Org ID (where is says paste-your-org-id-here) and run this

```bash
uvx --from git+https://github.com/geoffbelknap/limacharlie-mcp \
  limacharlie-mcp-configure \
  --oid "paste-your-org-id-here"
```
4. Go back to your browser and head to `Organization Settings` -> `Access Management` -> `REST API`.
5. Click `Create API Key` and select permissions for the workflows you want.

   For first run plus read-only posture review, start with:

   ```text
   org.get
   sensor.list
   sensor.get
   insight.list
   insight.det.get
   insight.evt.get
   insight.stat
   audit.get
   output.list
   dr.list
   dr.list.managed
   fp.ctrl
   yara.get
   lookup.get
   ikey.list
   ingestkey.ctrl
   user.ctrl
   apikey.ctrl
   job.get
   replicant.get
   replicant.task
   ```

   `replicant.task` is needed for complete service-backed content review, such
   as listing rules managed through LimaCharlie services.

   Add mutation permissions only when you intend to use response, admin, or
   content-editing workflows. (Don't bother adding `live_stream.ctrl`; this MCP does not
   expose live firehose or streaming telemetry tools. Spraying high pressure random telemetry at an AI is great for burning tokens, but it ain't going ot make you more secure.)   
7. Create your key and copy the secret from the LimaCharlie dashboard
8. Switch back to the terminal and paste the secret into the hiddne prompt (it wont end up in history).

Then start a new with your favorite AI tool (Claude, Codex, Copilot, Cursor, ehatever), with the plugin enabled and ask:
"Check my LimaCharlie MCP auth status." The agent should confirm credentials
are configured without showing secrets.

For screenshots, permissions, user API key mode, advanced deployment, and
troubleshooting, see [Onboarding And Auth](docs/onboarding-auth.md).

## Tool Surface

The implementation covers LimaCharlie broadly, but normal agent sessions should
use a focused profile instead of loading every tool into context. Each profile
uses the same API client, auth model, audit log, response envelope, and
preview/confirm mutation contract.

| Command | Profile | Intended use |
| --- | --- | --- |
| `limacharlie-mcp-core` | `core` | Auth, org discovery, runtime status, schemas, ontology, event types, and download references. |
| `limacharlie-mcp-fleet` | `fleet` | Sensor onboarding, installation keys, tags, online state, and fleet maintenance. |
| `limacharlie-mcp-admin` | `admin` | Organizations, users, groups, API keys, billing, outputs, extensions, and org configuration. |
| `limacharlie-mcp-content` | `content` | D&R, false positives, YARA, Hive content, lookups, playbooks, SOPs, and content governance. |
| `limacharlie-mcp-detect` | `detect` | Bounded detection triage, events, cases, IOC lookups, audit, search, artifacts, and jobs. |
| `limacharlie-mcp-contain` | `contain` | Endpoint containment, response tasking, reliable tasks, job cancellation, and supporting evidence. |
| `limacharlie-mcp-evict` | `evict` | Response tasking plus content/YARA surfaces used to remove adversary footholds. |
| `limacharlie-mcp-recover` | `recover` | Post-incident recovery verification plus guarded rejoin, unseal, tasking, tagging, spotcheck, and case-update previews. |
| `limacharlie-mcp-review` | `review` | Read-only posture review, operational/admin issue discovery, detection tuning, content coverage, case backlog, and access hygiene. |
| `limacharlie-mcp` | `full-dev` | Full developer surface for parity work and audits. Not recommended for normal agent sessions. |

You can also run `limacharlie-mcp` with `LC_MCP_PROFILE` set to one of those
profile names. Call `lc_tool_catalog` after startup to see the active profile,
available profiles, and the filtered operation catalog.

## Skills Pack

The repo includes an initial Codex skills pack in `skills/` for agent workflows
that should use these MCP profiles:

| Skill | Workflow |
| --- | --- |
| `limacharlie-auth-onboarding` | Auth setup, reauth, UID/OID confusion, and secret-safe smoke tests. |
| `limacharlie-posture-review` | Bounded expert review across fleet, content, access, outputs, cases, and detection noise. |
| `limacharlie-detection-tuning` | Evidence-led noisy-alert and missing-alert tuning. |
| `limacharlie-detect-triage` | Detection, case, event, IOC, search, artifact, and vulnerability triage. |
| `limacharlie-contain-response` | Guarded containment with preview/confirm endpoint actions. |
| `limacharlie-evict-response` | Evidence-backed adversary eviction and durable content/action changes. |
| `limacharlie-recover-verify` | Post-incident restoration and recurrence checks. |

This MCP intentionally does not expose live telemetry streaming, spout, or
firehose tools. Historical event, detection, audit, search, replay, and
spotcheck workflows remain bounded by explicit limits, cursors, selectors, and
time windows. Use LimaCharlie outputs, storage, SIEM pipelines, or purpose-built
stream processors for operational telemetry streams instead of sending an
unbounded firehose into an LLM.

### Platform

| Tool | Purpose |
| --- | --- |
| `lc_tool_catalog` | Describe tools, inputs, bounds, side effects, and intended use cases. |
| `lc_auth_whoami` | Show current API identity, optionally scoped to an org or permission check. |
| `lc_auth_status` | Show credential mode and cached JWT freshness without exposing secrets. |
| `lc_auth_refresh` | Force a local JWT refresh from configured API-key credentials. |
| `lc_list_orgs` | List organizations available to the authenticated API key. |
| `lc_list_sensor_download_targets` | List supported sensor installer URLs without downloading binaries. |
| `lc_list_adapter_download_targets` | List supported adapter binary URLs without downloading binaries. |

### Review And Tuning

These tools aggregate bounded reads into compact findings for recurring posture
review, noisy-alert triage, and operational hygiene checks. They do not mutate
LimaCharlie state and they keep source records summarized instead of returning
entire detections, cases, or rule bodies.

| Tool | Purpose |
| --- | --- |
| `lc_review_org_posture` | Aggregate fleet, outputs, access, content, cases, org errors, and optional detection-noise findings. |
| `lc_review_fleet_health` | Summarize sensor, online-sensor, and tag evidence for fleet health. |
| `lc_review_detection_noise` | Summarize bounded detection volume, concentration, and related case sample evidence for a time window. |
| `lc_review_content_coverage` | Summarize D&R, false positive, logging, integrity, YARA, and MITRE coverage evidence. |
| `lc_review_case_backlog` | Summarize case backlog, status distribution, severity distribution, and dashboard evidence. |
| `lc_review_output_health` | Summarize outputs, extension subscriptions, and feedback channel evidence. |
| `lc_review_access_hygiene` | Summarize users, permissions, groups, and organization API key metadata. |

### Investigation

| Tool | Purpose |
| --- | --- |
| `lc_list_sensors` | List sensors for an explicit org, optionally filtered by selector. |
| `lc_get_sensor` | Fetch one sensor by sensor ID. |
| `lc_list_online_sensors` | List currently online sensors or online counts for an org. |
| `lc_wait_sensor_online` | Poll one sensor until it is online or a bounded timeout expires. |
| `lc_list_sensor_events` | List one bounded page of events for a sensor and time window. |
| `lc_get_sensor_event_overview` | Fetch event timeline overview before pulling full events. |
| `lc_get_event` | Fetch one event by atom. |
| `lc_list_child_events` | Fetch child events for a parent atom. |
| `lc_get_event_retention` | Inspect retained event counts for a time window. |
| `lc_list_detections` | List one bounded page of detections for an explicit org and time window. |
| `lc_get_detection` | Fetch one detection by detection ID. |
| `lc_search_ioc` | Search Insight prevalence or locations for an IOC/object. |
| `lc_batch_search_iocs` | Batch Insight prevalence or location lookups for bounded IOC groups. |
| `lc_get_object_information` | Lookup one object through Insight with enrichment-oriented naming. |
| `lc_get_insight_status` | Check whether Insight retention appears enabled. |
| `lc_validate_search_query` | Validate LCQL through the org search service before estimation or execution. |
| `lc_estimate_search_query` | Estimate LCQL cost for an explicit time window. |
| `lc_execute_search_query` | Start a paginated LCQL search and return a query ID. |
| `lc_poll_search_query` | Poll one bounded LCQL result page and return checkpoint state. |
| `lc_cancel_search_query` | Cancel a running LCQL search job. |
| `lc_list_saved_queries` | List saved LCQL queries stored in the query hive. |
| `lc_get_saved_query` | Fetch one saved LCQL query by name. |
| `lc_preview_set_saved_query` | Preview creating or updating one saved LCQL query. |
| `lc_preview_delete_saved_query` | Preview deleting one saved LCQL query. |
| `lc_execute_saved_query` | Load a saved query and start a paginated LCQL search job. |
| `lc_list_artifacts` | List artifacts for an org, sensor, time window, or cursor. |
| `lc_get_artifact_url` | Request original artifact payload or signed export URL. |
| `lc_list_payloads` | List payload metadata without downloading payload bytes. |
| `lc_get_payload_download_url` | Request payload metadata including a signed download URL when returned. |
| `lc_preview_payload_upload_url` | Preview requesting a signed payload upload URL. |
| `lc_preview_delete_payload` | Preview deleting a payload. |
| `lc_get_arl` | Resolve a LimaCharlie authenticated resource locator. |
| `lc_list_jobs` | List service jobs for an explicit org and time window. |
| `lc_get_job` | Fetch one service job. |
| `lc_wait_job` | Poll one service job until terminal state or bounded timeout. |
| `lc_list_vulnerability_cves` | List CVE rollups from the Vulnerability Reporting extension. |
| `lc_get_vulnerability_cve` | Fetch one CVE detail record, optionally with enrichment. |
| `lc_list_vulnerability_cve_hosts` | List endpoints affected by one CVE. |
| `lc_list_vulnerability_cve_packages` | List package/version pairs affected by one CVE. |
| `lc_list_vulnerability_endpoints` | List endpoints with vulnerability counts. |
| `lc_list_vulnerability_host_packages` | List vulnerable packages and CVEs on one sensor. |
| `lc_get_vulnerability_dashboard` | Fetch vulnerability dashboard graph data. |
| `lc_list_vulnerability_resolutions` | List stored finding resolution overlays. |
| `lc_list_vulnerability_snapshots` | List daily open-finding counts. |
| `lc_get_vulnerability_epss_history` | Fetch EPSS score history for one CVE. |
| `lc_list_audit_logs` | List one bounded page of audit logs for a time window. |
| `lc_list_tags` | List tags observed across sensors in an org. |
| `lc_list_sensor_tags` | List tags applied to one sensor. |
| `lc_find_sensors_by_tag` | Find sensors with a specific tag. |
| `lc_find_sensors_by_hostname` | Find sensors by hostname prefix. |
| `lc_export_sensors` | Export the full sensor manifest for an org. |
| `lc_preview_set_sensor_version` | Preview changing org sensor version policy. |
| `lc_list_available_services` | List services/replicants available to an org. |
| `lc_preview_service_request` | Preview a generic non-impersonated service request. |
| `lc_fetch_config` | Fetch org IaC configuration through ext-infrastructure. |
| `lc_preview_push_config` | Preview pushing org IaC configuration through ext-infrastructure. |
| `lc_list_cases` | List cases for an explicit org with filters and pagination. |
| `lc_get_case` | Fetch one case by case number. |
| `lc_preview_create_case` | Preview creating a case through ext-cases. |
| `lc_preview_update_case` | Preview updating case status, severity, assignment, classification, summary, conclusion, or tags. |
| `lc_preview_add_case_note` | Preview adding a case note. |
| `lc_preview_update_case_note_visibility` | Preview changing case note stakeholder visibility. |
| `lc_preview_bulk_update_cases` | Preview bulk-updating up to 200 cases. |
| `lc_preview_merge_cases` | Preview merging source cases into a target case. |
| `lc_list_case_detections` | List detections linked to a case. |
| `lc_preview_add_case_detection` | Preview linking a detection to a case. |
| `lc_preview_remove_case_detection` | Preview removing a detection link from a case. |
| `lc_list_case_entities` | List entities/IOCs attached to a case. |
| `lc_search_case_entities` | Search case entities across an org. |
| `lc_preview_add_case_entity` | Preview adding an entity/IOC to a case. |
| `lc_preview_update_case_entity` | Preview updating an entity note or verdict. |
| `lc_preview_remove_case_entity` | Preview removing an entity from a case. |
| `lc_list_case_telemetry` | List telemetry references linked to a case. |
| `lc_preview_add_case_telemetry` | Preview linking telemetry to a case. |
| `lc_preview_update_case_telemetry` | Preview updating telemetry note or verdict. |
| `lc_preview_remove_case_telemetry` | Preview removing telemetry from a case. |
| `lc_list_case_artifacts` | List forensic artifacts linked to a case. |
| `lc_preview_add_case_artifact` | Preview adding a forensic artifact reference to a case. |
| `lc_preview_remove_case_artifact` | Preview removing a forensic artifact reference from a case. |
| `lc_export_case` | Export a case with detections, entities, telemetry, and artifacts. |
| `lc_get_cases_report_summary` | Fetch Cases report summary metrics. |
| `lc_get_cases_dashboard_counts` | Fetch Cases dashboard counts. |
| `lc_get_cases_config` | Fetch Cases configuration. |
| `lc_preview_set_cases_config` | Preview replacing Cases configuration. |
| `lc_list_case_assignees` | List unique case assignees for an org. |
| `lc_list_case_orgs` | List ext-cases orgs accessible to the caller. |
| `lc_preview_set_case_tags` | Preview replacing all tags on a case. |
| `lc_preview_add_case_tags` | Preview adding tags through an exact replacement list. |
| `lc_preview_remove_case_tags` | Preview removing tags through an exact replacement list. |

### Administration

| Tool | Purpose |
| --- | --- |
| `lc_get_org_info` | Fetch org inventory and quota metadata. |
| `lc_get_org_stats` | Fetch org usage statistics. |
| `lc_list_org_errors` | List current org component errors. |
| `lc_get_org_urls` | Fetch service URLs for sensors, adapters, webhooks, replay, and related connectivity. |
| `lc_get_runtime_metadata` | Fetch runtime metadata, optionally filtered by entity type/name. |
| `lc_get_quota_usage` | Fetch enforced quota usage for capacity checks. |
| `lc_check_org_name` | Check whether an organization name is available. |
| `lc_preview_create_org` | Preview creating a new organization. |
| `lc_get_org_config_value` | Fetch one organization config value. |
| `lc_preview_set_org_config_value` | Preview setting one organization config value. |
| `lc_preview_dismiss_org_error` | Preview dismissing one organization component error. |
| `lc_get_org_delete_confirmation` | Request the LimaCharlie org delete confirmation token. |
| `lc_preview_delete_org` | Preview deleting an organization with a confirmation token. |
| `lc_preview_set_org_quota` | Preview setting an org sensor quota. |
| `lc_preview_rename_org` | Preview renaming an org. |
| `lc_get_billing_status` | Fetch current billing status. |
| `lc_get_billing_details` | Fetch detailed billing information. |
| `lc_get_billing_invoice_url` | Fetch an invoice URL for a specific billing month. |
| `lc_list_billing_plans` | List available billing plans. |
| `lc_list_groups` | List organization groups accessible to the authenticated identity. |
| `lc_preview_create_group` | Preview creating an organization group. |
| `lc_get_group` | Fetch one organization group definition. |
| `lc_preview_delete_group` | Preview deleting an organization group. |
| `lc_list_group_logs` | List audit logs for one organization group. |
| `lc_preview_add_group_member` | Preview adding a group member. |
| `lc_preview_remove_group_member` | Preview removing a group member. |
| `lc_preview_add_group_owner` | Preview adding a group owner. |
| `lc_preview_remove_group_owner` | Preview removing a group owner. |
| `lc_preview_set_group_permissions` | Preview replacing group permissions. |
| `lc_preview_add_group_org` | Preview adding an org to a group. |
| `lc_preview_remove_group_org` | Preview removing an org from a group. |
| `lc_list_users` | List org users. |
| `lc_preview_invite_user` | Preview inviting a user to an org. |
| `lc_preview_remove_user` | Preview removing a user from an org. |
| `lc_list_user_permissions` | List org user permission mappings. |
| `lc_preview_add_user_permission` | Preview granting one user permission. |
| `lc_preview_remove_user_permission` | Preview revoking one user permission. |
| `lc_preview_set_user_role` | Preview setting a user's predefined role. |
| `lc_list_api_keys` | List org API key metadata. |
| `lc_preview_create_api_key` | Preview creating an org API key. |
| `lc_preview_delete_api_key` | Preview deleting an org API key. |
| `lc_list_installation_keys` | List installation key metadata. |
| `lc_get_installation_key` | Fetch one installation key. |
| `lc_preview_create_installation_key` | Preview creating an installation key. |
| `lc_preview_delete_installation_key` | Preview deleting an installation key. |
| `lc_list_outputs` | List configured output integrations. |
| `lc_preview_create_ingestion_key` | Preview creating an ingestion key. |
| `lc_preview_delete_ingestion_key` | Preview deleting an ingestion key. |
| `lc_preview_create_output` | Preview creating an output integration. |
| `lc_preview_delete_output` | Preview deleting an output integration. |
| `lc_list_extension_subscriptions` | List extension subscriptions for an org. |
| `lc_preview_subscribe_extension` | Preview subscribing an org to an extension. |
| `lc_preview_unsubscribe_extension` | Preview unsubscribing an org from an extension. |
| `lc_preview_rekey_extension` | Preview rotating an extension subscription key. |
| `lc_list_available_extensions` | List globally available extension definitions. |
| `lc_get_extension` | Fetch one extension definition. |
| `lc_preview_create_extension` | Preview creating an extension definition. |
| `lc_preview_update_extension` | Preview updating an extension definition. |
| `lc_preview_delete_extension` | Preview deleting an extension definition. |
| `lc_get_extension_schema` | Fetch extension schema for an org context. |
| `lc_preview_extension_request` | Preview a generic extension request. |
| `lc_list_ingestion_keys` | List ingestion key metadata. |
| `lc_list_ai_sessions` | List org-scoped AI sessions for governance and cost visibility. |
| `lc_get_ai_session` | Fetch one org-scoped AI session. |
| `lc_get_ai_session_history` | Fetch bounded history for one org-scoped AI session. |
| `lc_preview_terminate_ai_session` | Preview terminating a running AI session. |
| `lc_list_ai_usage_identities` | List API key identities with AI-session usage data. |
| `lc_get_ai_usage` | Fetch bounded token and cost usage for one AI identity. |

### Content Review

| Tool | Purpose |
| --- | --- |
| `lc_list_schemas` | List event schemas for an org. |
| `lc_get_schema` | Fetch one event schema. |
| `lc_get_ontology` | Fetch LimaCharlie ontology/event definitions. |
| `lc_list_event_types` | List available event types. |
| `lc_get_mitre_report` | Fetch MITRE ATT&CK coverage data. |
| `lc_list_artifact_rules` | List artifact collection rules. |
| `lc_preview_set_artifact_rule` | Preview creating or updating an artifact collection rule. |
| `lc_preview_delete_artifact_rule` | Preview deleting an artifact collection rule. |
| `lc_list_logging_rules` | List logging collection rules. |
| `lc_preview_set_logging_rule` | Preview creating or updating a logging collection rule. |
| `lc_preview_delete_logging_rule` | Preview deleting a logging collection rule. |
| `lc_validate_replay_rule` | Validate a D&R rule through Replay using dry-run evaluation. |
| `lc_replay_scan_events` | Dry-run a D&R rule against explicit events. |
| `lc_replay_dry_run` | Dry-run a D&R rule against historical data without creating detections. |
| `lc_list_dr_rules` | List D&R rules from the general or managed namespace. |
| `lc_get_dr_rule` | Fetch one D&R rule from the general or managed namespace. |
| `lc_preview_set_dr_rule` | Preview creating or updating a D&R rule. |
| `lc_preview_delete_dr_rule` | Preview deleting a D&R rule. |
| `lc_list_fp_rules` | List false-positive rules. |
| `lc_get_fp_rule` | Fetch one false-positive rule. |
| `lc_preview_set_fp_rule` | Preview creating or updating a false-positive rule. |
| `lc_preview_delete_fp_rule` | Preview deleting a false-positive rule. |
| `lc_list_integrity_rules` | List integrity monitoring rules. |
| `lc_get_integrity_rule` | Fetch one integrity monitoring rule. |
| `lc_preview_set_integrity_rule` | Preview creating or updating an integrity monitoring rule. |
| `lc_preview_delete_integrity_rule` | Preview deleting an integrity monitoring rule. |
| `lc_validate_usp_mapping` | Validate USP mapping/input configuration. |
| `lc_list_hive_types` | List known LimaCharlie Hive type names. |
| `lc_list_hive_records` | List records from a Hive partition. |
| `lc_get_hive_record` | Fetch one Hive record data payload. |
| `lc_get_hive_record_metadata` | Fetch one Hive record metadata payload. |
| `lc_get_hive_schema` | Fetch the JSON Schema for a typed Hive. |
| `lc_validate_hive_record` | Validate a Hive record without saving it. |
| `lc_preview_set_hive_record` | Preview creating or updating a generic Hive record. |
| `lc_preview_delete_hive_record` | Preview deleting a generic Hive record. |
| `lc_preview_rename_hive_record` | Preview renaming a generic Hive record. |
| `lc_preview_set_hive_record_enabled` | Preview toggling a Hive record's enabled metadata. |
| `lc_list_secrets` | List secret Hive records without exposing secret values. |
| `lc_get_secret` | Fetch one secret Hive record with sensitive fields redacted. |
| `lc_preview_set_secret` | Preview creating or updating a secret Hive record. |
| `lc_preview_delete_secret` | Preview deleting a secret Hive record. |
| `lc_preview_set_secret_enabled` | Preview toggling a secret Hive record's enabled metadata. |
| `lc_list_lookups` | List lookup Hive records. |
| `lc_get_lookup` | Fetch one lookup Hive record. |
| `lc_preview_set_lookup` | Preview creating or updating a lookup Hive record. |
| `lc_preview_delete_lookup` | Preview deleting a lookup Hive record. |
| `lc_preview_set_lookup_enabled` | Preview toggling a lookup Hive record's enabled metadata. |
| `lc_list_cloud_adapters` | List cloud adapter Hive records. |
| `lc_get_cloud_adapter` | Fetch one cloud adapter Hive record. |
| `lc_preview_set_cloud_adapter` | Preview creating or updating a cloud adapter Hive record. |
| `lc_preview_delete_cloud_adapter` | Preview deleting a cloud adapter Hive record. |
| `lc_preview_set_cloud_adapter_enabled` | Preview toggling a cloud adapter Hive record's enabled metadata. |
| `lc_list_external_adapters` | List external adapter Hive records. |
| `lc_get_external_adapter` | Fetch one external adapter Hive record. |
| `lc_preview_set_external_adapter` | Preview creating or updating an external adapter Hive record. |
| `lc_preview_delete_external_adapter` | Preview deleting an external adapter Hive record. |
| `lc_preview_set_external_adapter_enabled` | Preview toggling an external adapter Hive record's enabled metadata. |
| `lc_list_playbooks` | List playbook Hive records. |
| `lc_get_playbook` | Fetch one playbook Hive record. |
| `lc_preview_set_playbook` | Preview creating or updating a playbook Hive record. |
| `lc_preview_delete_playbook` | Preview deleting a playbook Hive record. |
| `lc_preview_set_playbook_enabled` | Preview toggling a playbook Hive record's enabled metadata. |
| `lc_list_sops` | List SOP Hive records. |
| `lc_get_sop` | Fetch one SOP Hive record. |
| `lc_preview_set_sop` | Preview creating or updating an SOP Hive record. |
| `lc_preview_delete_sop` | Preview deleting an SOP Hive record. |
| `lc_preview_set_sop_enabled` | Preview toggling an SOP Hive record's enabled metadata. |
| `lc_list_org_notes` | List organization-note Hive records. |
| `lc_get_org_note` | Fetch one organization-note Hive record. |
| `lc_preview_set_org_note` | Preview creating or updating an organization-note Hive record. |
| `lc_preview_delete_org_note` | Preview deleting an organization-note Hive record. |
| `lc_preview_set_org_note_enabled` | Preview toggling an organization-note Hive record's enabled metadata. |
| `lc_list_ai_agents` | List AI agent Hive records. |
| `lc_get_ai_agent` | Fetch one AI agent Hive record. |
| `lc_preview_set_ai_agent` | Preview creating or updating an AI agent Hive record. |
| `lc_preview_delete_ai_agent` | Preview deleting an AI agent Hive record. |
| `lc_preview_set_ai_agent_enabled` | Preview toggling an AI agent Hive record's enabled metadata. |
| `lc_list_ai_skills` | List AI skill Hive records. |
| `lc_get_ai_skill` | Fetch one AI skill Hive record. |
| `lc_preview_set_ai_skill` | Preview creating or updating an AI skill Hive record. |
| `lc_preview_delete_ai_skill` | Preview deleting an AI skill Hive record. |
| `lc_preview_set_ai_skill_enabled` | Preview toggling an AI skill Hive record's enabled metadata. |
| `lc_list_ai_memory_records` | List ai_memory Hive records. |
| `lc_get_ai_memory_record` | Fetch the full ai_memory record for an agent. |
| `lc_list_ai_memories` | List memory entries for an ai_memory agent record. |
| `lc_get_ai_memory` | Fetch one memory entry from an ai_memory agent record. |
| `lc_preview_set_ai_memory` | Preview setting one ai_memory entry. |
| `lc_preview_delete_ai_memory` | Preview deleting one ai_memory entry. |
| `lc_preview_delete_ai_memory_record` | Preview deleting an entire ai_memory agent record. |
| `lc_list_yara_rules` | List YARA scanning rules. |
| `lc_preview_yara_scan` | Preview running an ad-hoc YARA scan on one sensor. |
| `lc_preview_set_yara_rule` | Preview creating or updating a YARA scanning rule. |
| `lc_preview_delete_yara_rule` | Preview deleting a YARA scanning rule. |
| `lc_list_yara_sources` | List YARA source names. |
| `lc_get_yara_source` | Fetch one YARA source. |
| `lc_preview_set_yara_source` | Preview creating or updating a YARA source. |
| `lc_preview_delete_yara_source` | Preview deleting a YARA source. |
| `lc_list_exfil_rules` | List exfil prevention rules. |
| `lc_preview_create_exfil_watch` | Preview creating an exfil watch rule. |
| `lc_preview_create_exfil_event` | Preview creating an exfil event rule. |
| `lc_preview_delete_exfil_event` | Preview deleting an exfil event rule. |
| `lc_preview_delete_exfil_watch` | Preview deleting an exfil watch rule. |
| `lc_list_feedback_channels` | List ext-feedback channel configuration. |
| `lc_preview_set_feedback_channels` | Preview replacing ext-feedback channel configuration. |
| `lc_preview_feedback_simple_approval` | Preview sending an external approval request through ext-feedback. |
| `lc_preview_feedback_acknowledgement` | Preview sending an external acknowledgement request through ext-feedback. |
| `lc_preview_feedback_question` | Preview sending an external free-form question through ext-feedback. |

### Response

| Tool | Purpose |
| --- | --- |
| `lc_list_pending_mutations` | List local mutation previews that can still be confirmed. |
| `lc_preview_sensor_task` | Preview tasking one sensor. |
| `lc_preview_spotcheck_run` | Preview running a fleet-wide spotcheck task. |
| `lc_get_sensor_isolation_status` | Check whether one sensor is currently network-isolated. |
| `lc_preview_isolate_sensor` | Preview isolating one sensor from the network. |
| `lc_preview_rejoin_sensor` | Preview removing network isolation from one sensor. |
| `lc_get_sensor_seal_status` | Check whether one sensor is currently sealed. |
| `lc_preview_seal_sensor` | Preview sealing one sensor against uninstall. |
| `lc_preview_unseal_sensor` | Preview unsealing one sensor. |
| `lc_preview_delete_sensor` | Preview deleting one sensor record. |
| `lc_preview_delete_job` | Preview deleting one service job record. |
| `lc_list_reliable_tasks` | List pending reliable-tasking extension tasks for an org. |
| `lc_preview_reliable_task` | Preview queueing one reliable task through ext-reliable-tasking. |
| `lc_preview_delete_reliable_task` | Preview cancelling one pending reliable task through ext-reliable-tasking. |
| `lc_preview_add_sensor_tag` | Preview adding a tag to one sensor, optionally with TTL. |
| `lc_preview_remove_sensor_tag` | Preview removing a tag from one sensor. |
| `lc_confirm_mutation` | Execute the exact typed mutation bound to a preview token. |
| `lc_cancel_mutation` | Cancel a pending local mutation preview without calling LimaCharlie. |

Mutations are available only through the preview/confirm contract. Current
typed previews cover sensor response actions, job deletion, sensor tags,
sensor version policy, case lifecycle/investigation/config/tag changes,
administration writes, extension/service/config-sync/feedback requests,
generic Hive records, AI-memory records, payload metadata, spotcheck requests,
and artifact/logging/D&R/false-positive/integrity/YARA/exfil content changes.
Live telemetry streaming, spout, and firehose surfaces are intentionally
unsupported. Remaining multi-request helper surfaces stay gated until they have
typed preview/confirm tools or bounded read contracts with request-shape tests.

Credential-shaped upstream fields such as API keys, JWTs, secrets, passwords,
and private/client keys are redacted from MCP responses and audit excerpts.
Local preview confirmation tokens remain visible in preview responses because
they are required to execute the explicit confirmation step.

Broad AI-generation and chat wrappers are not a default parity target. This MCP
focuses on deterministic LimaCharlie administration, investigation, content,
response, feedback, and evidence workflows. AI-adjacent coverage is limited to
auditable state, memory, session governance, and usage visibility with cost and
credential guardrails.

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

LCQL search follows a bounded lifecycle:

1. `lc_validate_search_query`
2. `lc_estimate_search_query`
3. `lc_execute_search_query`
4. `lc_poll_search_query` until `state.terminal` is true or
   `state.checkpoint.next_token` is exhausted
5. `lc_cancel_search_query` when a running query is no longer needed

`lc_poll_search_query` returns at most the requested result rows per poll and
puts resume state under `state.checkpoint`, so agents can continue explicitly
without hiding pagination in a long-running tool call.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

Configure credentials with the short checklist near the top of this README.
Advanced deployment options live in [Deployment](docs/deployment.md).

Org-scoped tools always require an explicit `oid`. Discovery tools
(`lc_list_orgs`, unscoped `lc_auth_whoami`) use LimaCharlie's minimal JWT org
placeholder internally.

## MCP Client Config

Example stdio config using the default config file:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp"
    }
  }
}
```

If you store the nonsecret config somewhere else, pass just one environment
variable:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp",
      "env": {
        "LC_MCP_CONFIG": "/path/to/limacharlie-mcp-config.json"
      }
    }
  }
}
```

After starting the server, ask your agent to check LimaCharlie MCP auth status.
It should confirm credentials are configured without showing secrets. Only ask
for an auth refresh after credential rotation or auth troubleshooting.

For first-time setup, read [Onboarding And Auth](docs/onboarding-auth.md)
before creating keys. LimaCharlie organization API keys and user API keys come
from different UI locations and should be kept in separate MCP variables.
Run `limacharlie-mcp-auth-doctor` to validate the selected auth mode before
connecting the MCP to an agent client.

The audit log records timestamp, purpose, org ID, HTTP method, URL, query
parameters, status code, duration, and output size. It does not record
credentials or authorization headers.

See [docs/onboarding-auth.md](docs/onboarding-auth.md) for the onboarding,
auth, and reauth flow. See [docs/deployment.md](docs/deployment.md) for
advanced deployment and MCP client config templates.

## Development

```bash
python -m pytest tests/ -q
```

The tests do not require LimaCharlie credentials or network access.

Run the category parity audit before claiming new LimaCharlie API/SDK coverage
or adding a new tool family:

```bash
python tools/parity/audit_parity.py --fetch-current-docs --format markdown
```

Run the full local readiness gate before release or handoff:

```bash
scripts/readiness-check.sh
```


## References

- LimaCharlie docs: https://docs.limacharlie.io/
- AI assistant setup: https://docs.limacharlie.io/6-developer-guide/mcp-server/
- Python SDK docs: https://docs.limacharlie.io/6-developer-guide/sdks/python-sdk-v4/
- API key docs: https://docs.limacharlie.io/7-administration/access/api-keys/
- Onboarding and auth: [docs/onboarding-auth.md](docs/onboarding-auth.md)
- Deployment: [docs/deployment.md](docs/deployment.md)
