from __future__ import annotations

from dataclasses import dataclass
from typing import Any


DEFAULT_PROFILE = "full-dev"
ACTION_OPERATION_PREFIXES = ("action.",)


@dataclass(frozen=True)
class ProfileDefinition:
    name: str
    title: str
    description: str
    best_for: tuple[str, ...] = ()
    common_workflows: tuple[str, ...] = ()
    start_with: tuple[str, ...] = ()
    safety_model: str = ""
    include_suites: frozenset[str] = frozenset()
    include_actions: frozenset[str] | None = None
    include_operations: frozenset[str] = frozenset()
    include_operation_prefixes: tuple[str, ...] = ()
    include_tools: frozenset[str] = frozenset()
    read_only_all_suites: bool = False
    full_surface: bool = False


CORE_OPERATION_PREFIXES = (
    "auth.",
    "tool.",
    "download.",
    "schema.",
    "ontology.",
    "event_type.",
)
CORE_OPERATIONS = frozenset({"org.list", "permission.explain"})

REVIEW_OPERATIONS = CORE_OPERATIONS | frozenset(
    {
        "api_key.list",
        "artifact_rule.list",
        "audit.list",
        "billing.details",
        "billing.plans",
        "billing.status",
        "case.assignees.list",
        "case.config.get",
        "case.dashboard",
        "case.get",
        "case.list",
        "case.org.list",
        "case.report",
        "cloud_adapter.get",
        "cloud_adapter.list",
        "config.fetch",
        "detection.get",
        "detection.list",
        "dr_rule.get",
        "dr_rule.list",
        "exfil_rule.list",
        "extension.get",
        "extension.list_available",
        "extension.list_subscribed",
        "extension.schema.get",
        "external_adapter.get",
        "external_adapter.list",
        "feedback.channel.list",
        "fp_rule.get",
        "fp_rule.list",
        "group.get",
        "group.list",
        "group.logs",
        "hive.record.get",
        "hive.record.list",
        "hive.record.metadata.get",
        "hive.record.validate",
        "hive.schema.get",
        "hive.type.list",
        "ingestion_key.list",
        "installation_key.get",
        "installation_key.list",
        "integrity_rule.get",
        "integrity_rule.list",
        "lookup.get",
        "lookup.list",
        "mitre.get",
        "org.errors",
        "org.get",
        "org.quota_usage",
        "org.runtime_metadata",
        "org.stats",
        "org.urls",
        "output.list",
        "playbook.get",
        "playbook.list",
        "saved_query.get",
        "saved_query.list",
        "schema.get",
        "schema.list",
        "secret.list",
        "sensor.get",
        "sensor.hostname_search",
        "sensor.list",
        "sensor.online.list",
        "sensor.tag.list",
        "service.list",
        "sop.get",
        "sop.list",
        "tag.list",
        "tag.sensor_search",
        "user.list",
        "user.permission.list",
        "vulnerability.cve.get",
        "vulnerability.cve.hosts",
        "vulnerability.cve.list",
        "vulnerability.cve.packages",
        "vulnerability.dashboard",
        "vulnerability.endpoint.list",
        "vulnerability.epss_history",
        "vulnerability.host.packages",
        "vulnerability.resolution.list",
        "vulnerability.snapshot.list",
        "yara_rule.list",
        "yara_source.get",
        "yara_source.list",
        "review.access_hygiene",
        "review.case_backlog",
        "review.content_coverage",
        "review.detection_noise",
        "review.fleet_health",
        "review.org_posture",
        "review.output_health",
    }
)

RECOVER_OPERATIONS = CORE_OPERATIONS | frozenset(
    {
        "artifact.list",
        "case.artifact.list",
        "case.detection.list",
        "case.entity.list",
        "case.entity.search",
        "case.get",
        "case.list",
        "case.note.add.preview",
        "case.tag.add.preview",
        "case.tag.remove.preview",
        "case.tag.set.preview",
        "case.telemetry.list",
        "case.update.preview",
        "detection.get",
        "detection.list",
        "dr_rule.get",
        "dr_rule.list",
        "event.get",
        "event.list",
        "event.overview",
        "extension.list_subscribed",
        "fp_rule.get",
        "fp_rule.list",
        "integrity_rule.get",
        "integrity_rule.list",
        "job.get",
        "job.list",
        "job.wait",
        "logging_rule.list",
        "action.cancel",
        "action.confirm",
        "action.pending.list",
        "org.errors",
        "org.get",
        "org.stats",
        "org.urls",
        "output.list",
        "reliable_task.delete.preview",
        "reliable_task.list",
        "reliable_task.send.preview",
        "schema.get",
        "schema.list",
        "sensor.get",
        "sensor.hostname_search",
        "sensor.isolation_status.get",
        "sensor.list",
        "sensor.online.list",
        "sensor.rejoin.preview",
        "sensor.seal_status.get",
        "sensor.tag.add.preview",
        "sensor.tag.list",
        "sensor.tag.remove.preview",
        "sensor.task.preview",
        "sensor.unseal.preview",
        "sensor.wait_online",
        "service.list",
        "spotcheck.run.preview",
        "tag.list",
        "tag.sensor_search",
        "yara.scan.preview",
        "yara_rule.list",
        "yara_source.get",
        "yara_source.list",
    }
)


PROFILE_DEFINITIONS: dict[str, ProfileDefinition] = {
    "full-dev": ProfileDefinition(
        name="full-dev",
        title="Full developer surface",
        description="All registered LimaCharlie MCP tools. Use for parity development and audits, not normal agent sessions.",
        best_for=("parity audits", "catalog inspection", "development validation"),
        common_workflows=("Compare MCP coverage to LimaCharlie API surfaces.", "Inspect operation contracts while developing new tools."),
        start_with=("lc_tool_catalog",),
        safety_model="Includes all tools. Use focused profiles for normal agent sessions.",
        full_surface=True,
    ),
    "core": ProfileDefinition(
        name="core",
        title="Core auth and reference",
        description="Authentication, org discovery, runtime status, schemas, ontology, event types, and download target references.",
        best_for=("auth setup checks", "schema/reference lookup", "minimal smoke tests"),
        common_workflows=("Check MCP auth status.", "Inspect available profiles.", "Look up schema and ontology references."),
        start_with=("lc_auth_status", "lc_auth_whoami", "lc_tool_catalog"),
        safety_model="Read-only local/auth/reference surface.",
        include_suites=frozenset({"platform"}),
        include_operations=CORE_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "fleet": ProfileDefinition(
        name="fleet",
        title="Fleet onboarding and maintenance",
        description="Sensor discovery, onboarding keys, tags, download targets, version policy, and bounded fleet health reads.",
        best_for=("sensor onboarding", "fleet inventory", "endpoint maintenance"),
        common_workflows=("List sensors and online state.", "Find sensors by hostname or tag.", "Prepare fleet maintenance safe actions."),
        start_with=("lc_list_sensors", "lc_list_online_sensors", "lc_find_sensors_by_hostname"),
        safety_model="Read-first fleet tools with preview/confirm for changes.",
        include_suites=frozenset({"platform"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.wait_online",
                "sensor.online.list",
                "sensor.tag.list",
                "sensor.hostname_search",
                "sensor.export",
                "sensor.version.set.preview",
                "tag.list",
                "tag.sensor_search",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ("installation_key.",) + ACTION_OPERATION_PREFIXES,
    ),
    "admin": ProfileDefinition(
        name="admin",
        title="Organization administration",
        description="Organizations, users, groups, API keys, billing, outputs, extensions, and org-level configuration.",
        best_for=("org administration", "access hygiene", "API key and output management"),
        common_workflows=("Review users, groups, and API keys.", "Inspect billing, outputs, and extensions.", "Prepare org config safe actions."),
        start_with=("lc_get_org_info", "lc_list_users", "lc_list_api_keys"),
        safety_model="Administrative writes require safe action preview and confirmation.",
        include_suites=frozenset({"platform", "administration"}),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ACTION_OPERATION_PREFIXES,
    ),
    "content": ProfileDefinition(
        name="content",
        title="Detection and content maintenance",
        description="D&R, false positives, YARA, Hive content, lookups, secrets references, playbooks, SOPs, and content governance.",
        best_for=("detection content maintenance", "rule review", "lookup and YARA management"),
        common_workflows=("List and inspect D&R, FP, and YARA content.", "Validate rules before proposing changes.", "Prepare content safe actions."),
        start_with=("lc_list_dr_rules", "lc_list_fp_rules", "lc_list_yara_rules"),
        safety_model="Content writes require safe action preview and confirmation.",
        include_suites=frozenset({"platform", "content"}),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ACTION_OPERATION_PREFIXES,
    ),
    "detect": ProfileDefinition(
        name="detect",
        title="Detect and investigate",
        description="Bounded detection, event, case, IOC, search, audit, artifact, payload, vulnerability, and job reads.",
        best_for=("investigation", "evidence gathering", "case triage"),
        common_workflows=("List detections in a time window.", "Pull bounded sensor events.", "Search indicators and case evidence."),
        start_with=("lc_list_detections", "lc_get_detection", "lc_list_sensor_events"),
        safety_model="Read/execute investigation surface. Search execution starts bounded server-side jobs.",
        include_suites=frozenset({"platform", "investigation"}),
        include_actions=frozenset({"read", "execute"}),
        include_operations=CORE_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "contain": ProfileDefinition(
        name="contain",
        title="Contain affected systems",
        description="Endpoint containment previews, response tasking, reliable tasking, job cancellation, and supporting sensor/case evidence.",
        best_for=("containment", "endpoint isolation", "response task preparation"),
        common_workflows=("Verify affected sensors.", "Preview isolate/rejoin or response tasking.", "Confirm only after human approval."),
        start_with=("lc_get_sensor", "lc_get_sensor_isolation_status", "lc_preview_isolate_sensor"),
        safety_model="Containment actions require explicit preview and lc_confirm_action.",
        include_suites=frozenset({"platform", "response"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.isolation_status.get",
                "sensor.seal_status.get",
                "sensor.wait_online",
                "sensor.online.list",
                "detection.list",
                "detection.get",
                "case.list",
                "case.get",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ACTION_OPERATION_PREFIXES,
    ),
    "evict": ProfileDefinition(
        name="evict",
        title="Evict adversary footholds",
        description="Response tasking plus content and YARA surfaces used to remove persistence and unsafe artifacts through preview/confirm.",
        best_for=("eviction", "cleanup tasking", "persistence removal support"),
        common_workflows=("Gather evidence from detections/cases.", "Preview tasking or content changes.", "Verify cleanup progress."),
        start_with=("lc_get_sensor", "lc_preview_sensor_task", "lc_list_yara_rules"),
        safety_model="Eviction tasking and content changes require safe action confirmation.",
        include_suites=frozenset({"platform", "response", "content"}),
        include_operations=CORE_OPERATIONS
        | frozenset(
            {
                "sensor.list",
                "sensor.get",
                "sensor.wait_online",
                "detection.list",
                "detection.get",
                "case.list",
                "case.get",
            }
        ),
        include_operation_prefixes=CORE_OPERATION_PREFIXES + ACTION_OPERATION_PREFIXES,
    ),
    "recover": ProfileDefinition(
        name="recover",
        title="Recover and verify",
        description="Post-incident recovery verification plus guarded rejoin, unseal, tasking, spotcheck, tagging, and case-update previews.",
        best_for=("recovery verification", "restore endpoint access", "post-incident checks"),
        common_workflows=("Verify telemetry and output health.", "Preview rejoin/unseal after containment.", "Update recovery case evidence."),
        start_with=("lc_get_sensor", "lc_wait_sensor_online", "lc_preview_rejoin_sensor"),
        safety_model="Recovery changes require safe action confirmation; verification reads stay bounded.",
        include_suites=frozenset({"platform"}),
        include_operations=RECOVER_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
    "review": ProfileDefinition(
        name="review",
        title="Posture review and tuning",
        description="Read-only assessment for org posture, fleet health, detection quality, content coverage, case backlog, output health, and access hygiene.",
        best_for=("org posture review", "access hygiene", "detection tuning triage"),
        common_workflows=("Review org posture.", "Review detection noise for a time window.", "Review access, output, and content health."),
        start_with=("lc_review_org_posture", "lc_review_fleet_health", "lc_review_detection_noise"),
        safety_model="Read-only review profile. Suggested fixes should become safe actions in another profile.",
        include_suites=frozenset({"platform", "review"}),
        include_actions=frozenset({"read", "validate"}),
        include_operations=REVIEW_OPERATIONS,
        include_operation_prefixes=CORE_OPERATION_PREFIXES,
    ),
}


def available_profiles() -> tuple[str, ...]:
    return tuple(PROFILE_DEFINITIONS)


def normalize_profile(profile: str | None) -> str:
    selected = (profile or DEFAULT_PROFILE).strip().lower()
    if selected in {"full", "all", "dev"}:
        selected = "full-dev"
    if selected not in PROFILE_DEFINITIONS:
        allowed = ", ".join(available_profiles())
        raise ValueError(f"Unknown LimaCharlie MCP profile {profile!r}. Expected one of: {allowed}.")
    return selected


def profile_catalog(catalog: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, definition in PROFILE_DEFINITIONS.items():
        operations = filter_operation_catalog(catalog, name)
        tools = tool_names_for_profile(catalog, name)
        result[name] = {
            "title": definition.title,
            "description": definition.description,
            "best_for": list(definition.best_for),
            "common_workflows": list(definition.common_workflows),
            "start_with": [tool for tool in definition.start_with if tool in tools],
            "safety_model": definition.safety_model,
            "operation_count": len(operations),
            "tool_count": len(tools),
            "permission_summary": operation_permission_summary(operations),
        }
    return result


def operation_permission_summary(catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required: set[str] = set()
    recommended: set[str] = set()
    required_for_safe_actions: set[str] = set()
    dynamic_operations: list[str] = []
    unknown_operations: list[str] = []

    for operation, spec in catalog.items():
        permissions = spec.get("permissions", {})
        if not isinstance(permissions, dict):
            unknown_operations.append(operation)
            continue
        required.update(_string_values(permissions.get("required")))
        recommended.update(_string_values(permissions.get("recommended")))
        required_for_safe_actions.update(_string_values(permissions.get("required_for_confirm")))
        mode = permissions.get("mode")
        if mode == "dynamic":
            dynamic_operations.append(operation)
        elif mode == "unknown":
            unknown_operations.append(operation)

    return {
        "required": sorted(required),
        "recommended": sorted(recommended),
        "required_for_safe_actions": sorted(required_for_safe_actions),
        "dynamic_operation_count": len(dynamic_operations),
        "dynamic_operations_sample": sorted(dynamic_operations)[:10],
        "unknown_operation_count": len(unknown_operations),
        "unknown_operations_sample": sorted(unknown_operations)[:10],
    }


def operation_action_summary(catalog: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in catalog.values():
        action = str(spec.get("action", "unknown"))
        counts[action] = counts.get(action, 0) + 1
    return dict(sorted(counts.items()))


def operation_suite_summary(catalog: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in catalog.values():
        suite = str(spec.get("suite", "unknown"))
        counts[suite] = counts.get(suite, 0) + 1
    return dict(sorted(counts.items()))


def _string_values(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str) and value}


def filter_operation_catalog(catalog: dict[str, dict[str, Any]], profile: str | None) -> dict[str, dict[str, Any]]:
    selected = normalize_profile(profile)
    return {operation: spec for operation, spec in catalog.items() if operation_in_profile(operation, spec, selected)}


def tool_names_for_profile(catalog: dict[str, dict[str, Any]], profile: str | None) -> set[str]:
    operations = filter_operation_catalog(catalog, profile)
    return {str(spec["tool"]) for spec in operations.values()}


def operation_in_profile(operation: str, spec: dict[str, Any], profile: str | None) -> bool:
    selected = normalize_profile(profile)
    definition = PROFILE_DEFINITIONS[selected]
    if definition.full_surface:
        return True

    suite = str(spec.get("suite", ""))
    action = str(spec.get("action", ""))
    tool = str(spec.get("tool", ""))

    if operation in definition.include_operations or tool in definition.include_tools:
        return _action_allowed(action, definition)
    if operation.startswith(definition.include_operation_prefixes):
        return _action_allowed(action, definition)
    if definition.read_only_all_suites and action in {"read", "validate"}:
        return True
    if suite in definition.include_suites:
        return _action_allowed(action, definition)
    return False


def _action_allowed(action: str, definition: ProfileDefinition) -> bool:
    return definition.include_actions is None or action in definition.include_actions
