# Agent Experience Notes

This MCP is optimized for agent use, not for mirroring every LimaCharlie API.
The design combines the `ax-optimizer` review standard with lessons from
`microagent-ax-harness` testing.

## Applied AX Principles

After every tool call, an agent should be able to answer:

- what happened,
- what changed,
- what evidence proves it,
- what to do next.

The implementation supports that with:

- a stable result envelope on every tool,
- explicit `operation` names independent of Python function names,
- stable `request_id` values for correlation,
- explicit `resource` identity,
- `side_effects` even on read-only tools,
- compact `meta.summary` counts so agents do not need to reread full payloads,
- `truncated` metadata and narrower-query guidance,
- structured error classes and retryability.

## Harness Lessons Applied

The microagent AX harness showed that MCP surfaces tend to help most when they
reduce input context and make error recovery more mechanical. It also showed
that raw structured output can be worse than prose when schemas or results are
bulky. This MCP therefore avoids returning extra wrapper noise and keeps large
payloads bounded.

Specific lessons encoded here:

- Prefer a small operation catalog over broad raw API execution.
- Keep list operations bounded and require explicit time windows for historical
  data.
- Make error recovery cheap: classify auth, policy, not-found, conflict,
  capacity, transient, and internal errors.
- Preserve retryability on error envelopes, not only on success paths.
- Keep model-visible payloads compact; put counts and hints in `meta.summary`.
- Treat unsupported or mutating workflows as preview/confirm designs, not
  one-shot tools.
- Test schema/result contracts statically before live model trajectory tests.

## Current Trajectory Tests To Add

These are the next evals to build once real LimaCharlie test credentials are
available:

- Discovery: call `lc_tool_catalog`, choose `lc_list_sensors`, and explain the
  required `oid`.
- Happy path: list sensors for a test org, fetch one sensor, report hostname
  and sensor ID evidence.
- Detection investigation: list detections in a narrow time window, fetch one
  detection, report category, sensor ID, and event evidence.
- Error recovery: call `lc_get_sensor` with a bad sensor ID, observe
  `not_found`, list sensors, then retry with a valid ID.
- Policy boundary: use an API key missing Cases permission and verify the agent
  stops on `error.class=policy` rather than retrying.
- Unsupported request: ask the agent to isolate a sensor; expected behavior is
  refusal or preview-design explanation because mutation tools are not exposed.

