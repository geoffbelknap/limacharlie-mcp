# AX Review

Static review using the `ax-optimization-review` skill from the AX Optimizer
plugin.

## Summary

The MCP is agent-usable for bounded read workflows. It has a compact operation
catalog, stable result envelopes, explicit org scope, local audit logging, and
structured errors. The main issue found during this review was that validation
failures could escape the MCP server as tool exceptions instead of returning
the same agent-readable error envelope. That has been fixed at the server
boundary.

Current AX maturity: **30 / 33**.

Interpretation: strong AX for most read workflows. The remaining work is mostly
mutation safety and trajectory tests.

## Score

| Area | Score | Notes |
| --- | ---: | --- |
| Discovery and documentation | 3 | `lc_tool_catalog`, README, auth onboarding, surface map, and AX review exist. |
| Operation design | 3 | Tools are specific and suite-scoped; no raw API tunnel. |
| Input schemas | 3 | Bounds/enums exist in code and catalog; generated FastMCP schema coverage is tested for representative tools. |
| Output schemas | 3 | Stable AX envelope with operation, request ID, resource, data, side effects, warnings, summaries, truncation, and timestamp. |
| Error semantics | 3 | HTTP errors and MCP input validation return structured classes, retryability, and next actions. |
| State and lifecycle | 2 | `lc_wait_job` adds bounded polling and normalized terminal states; other async surfaces may need similar helpers later. |
| Identity and correlation | 3 | Explicit org scope, parent resources, request IDs, observed timestamps, and audit entries. |
| Side effects and cleanup | 2 | Read-only tools correctly report no side effects; mutation preview/confirm is not implemented. |
| MCP tool quality | 3 | Tool names are specific and operational; large historical payloads are bounded and decoded. |
| Policy and approval handling | 1 | Planned but not implemented for mutations. |
| Trajectory test coverage | 1 | Unit coverage exists; model trajectory/eval harness coverage is not implemented. |

## Findings

### Fixed: Validation Errors Escaped The AX Envelope

Severity: high.

Area: error.

Evidence: client methods raise `ValidationError` before calling the shared
HTTP wrapper. MCP tools previously returned those calls directly.

Agent impact: an agent receiving a JSON-RPC/tool exception cannot reliably
distinguish invalid input from server failure, cannot read retryability, and
may retry the same bad input.

Fix: `server.py` now wraps tool calls with `_call(...)`, catches
`ValidationError`, and returns `error.class: input` using the same AX envelope.

Acceptance test: `tests/test_server.py` verifies invalid `oid` and missing
artifact time window both return `ok: false`, `error.class: input`,
`same_input_retryable: false`, and no side effects.

### Fixed: Runtime MCP Schema Export Is Verified

Severity: medium.

Area: schema.

Evidence: the code relies on FastMCP function signatures.

Agent impact: a future signature change could silently weaken required fields
or optional defaults.

Fix: `tests/test_server.py` lists generated FastMCP tools and verifies schema
requirements/defaults for representative tools.

Acceptance test: a test fails if `lc_list_sensor_events` loses required
`oid`, `sensor_id`, `start`, or `end`, or if `lc_wait_job` loses required
`oid` and `job_id`.

### Mutation Safety Is Still A Design, Not Code

Severity: medium.

Area: policy.

Evidence: `docs/tool-contract.md` and `docs/surface-map.md` require
preview/confirm for writes, but no implementation exists.

Agent impact: the MCP cannot yet safely perform endpoint tasking, isolation,
rule edits, key management, extension subscription changes, or case updates.

Recommended fix: implement a generic preview token store only for named,
typed mutation tools. Do not add raw method/path execution.

Acceptance test: preview returns method, endpoint, resource, expected effect,
reversibility, confirmation token, and side effects; confirm executes only the
matching preview and rejects altered inputs.

### Fixed: Job Lifecycle Wait Helper Is Implemented

Severity: medium.

Area: lifecycle.

Evidence: jobs can be listed and fetched.

Agent impact: agents need a bounded way to wait for async job completion.

Fix: `lc_wait_job` polls with explicit timeout and interval bounds and
normalizes states such as `pending`, `running`, `succeeded`, `failed`, and
`unknown`.

Acceptance test: fake job responses prove the wait stops on terminal state,
returns attempt count, and includes normalized state.

### Trajectory Tests Are Not Yet Present

Severity: medium.

Area: eval.

Evidence: unit tests cover envelopes and paths, but there are no model
trajectory tests from the microagent AX harness patterns.

Agent impact: schema correctness does not prove agents can discover, recover,
track resources, and stop at policy boundaries.

Recommended fix: add a small eval fixture set for discovery, happy path,
multi-resource tracking, error recovery, unsupported mutation, and policy
boundary scenarios.

Acceptance test: trajectories record tool calls, final answer evidence,
retries, token use, and residue.

## Next Roadmap

1. Add audit-log read tools and tag/schema/MITRE read coverage.
2. Implement preview/confirm infrastructure for the first narrow mutation
   category.
3. Add AX trajectory tests using fake LimaCharlie responses before any live
   credential tests.
