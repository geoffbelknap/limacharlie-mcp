# Tool Contract

This server exposes a deliberately bounded MCP surface for LimaCharlie
investigation, administration, and content-review workflows. It should cover
the platform broadly, but it should not become a raw API passthrough.

## Design Rules

- Every org-scoped tool requires an explicit `oid`.
- Every listing tool accepts a bounded `limit` or returns one explicit page.
- Every historical read requires explicit `start` and `end` unix timestamps
  unless it is continuing from a server-provided cursor.
- Every tool returns `operation`, `request_id`, `resource`, `side_effects`,
  `meta.summary`, and `observed_at`.
- Errors return `error.code`, `error.class`, `retryable`,
  `same_input_retryable`, and `suggested_next_actions`.
- API calls are executed with structured HTTP requests, never through a shell.
- The audit log is written by the local wrapper before data is returned to the
  MCP client.
- `lc_tool_catalog` is the discovery entry point for agents. Update it and
  [surface-map.md](surface-map.md) before adding new tools.
- Read tools should be grouped under `platform`, `investigation`,
  `administration`, or `content` in the operation catalog.

## Future Write Tools

The following categories should not be added as one-shot tools:

- endpoint tasking,
- sensor isolation or deletion,
- tag mutation,
- D&R rule writes,
- false-positive writes,
- YARA writes,
- case updates,
- output or adapter configuration.
- extension subscription or rekeying.

If added later, use a two-step contract:

1. `preview_*` returns the exact HTTP method, endpoint, target org, target
   resource, and expected effect.
2. `confirm_*` executes only when passed a short-lived confirmation token
   produced by the preview call.
