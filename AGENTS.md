# LimaCharlie MCP

Standalone MCP server for LimaCharlie. This project is intentionally not tied
to any external product runtime or schema.

## Scope

- Build a local MCP server for LimaCharlie investigation workflows.
- Prefer bounded, explicit tools over broad raw API exposure.
- Keep organization scope explicit. Tools that operate on org data must require
  an `oid` argument.
- Do not store or log API keys, JWTs, OAuth tokens, or personal credentials.
- Use LimaCharlie API surfaces directly. Do not shell out to the CLI for MCP
  tool implementation.
- Treat Vault as the default deployment credential provider. Prefer Vault
  references over raw environment API keys in runtime design and user-facing
  setup docs.
- Do not expose live telemetry streaming, spout, or firehose tools. This MCP is
  not a SIEM ingestion path and should not encourage streaming unbounded
  telemetry into an LLM.

## Safety Rules

- Read-only tools are the default.
- Response actions, D&R writes, sensor isolation, tag mutation, deletion, and
  config changes need an explicit preview/confirm design before implementation.
- Every tool call should leave an auditable local trace.
- Tool outputs must be bounded by limits or explicit time windows.
- Historical telemetry reads must stay bounded by explicit limits and time
  windows. Live telemetry streaming and firehose registration are intentionally
  unsupported.

## Documentation Boundary

- Keep user-facing setup, auth, operation, and troubleshooting docs in this
  repo.
- Keep internal implementation plans, AX reviews, coverage matrices, tool
  contracts, and work tracking in the LimaCharlie MCP Notion space:
  https://app.notion.com/p/384bc6319c93816d92f3db88b86f8f19
- Do not add internal roadmap or process notes under `docs/`.

## Agent Experience Rules

- Preserve the standard response envelope: `ok`, `operation`, `request_id`,
  `resource`, `state`, `data`, `side_effects`, `warnings`, `meta`, and
  `observed_at`.
- Preserve structured errors with `code`, `class`, `message`, retryability, and
  suggested next actions.
- Update `lc_tool_catalog` whenever a tool is added or changed.
- Prefer small purpose-built tools over raw API escape hatches.
- Keep model-visible payloads compact; add counts and hints in `meta.summary`.
- Add tests for success and error envelopes when changing tool behavior.

## Validation

Run:

```bash
python -m pytest tests/ -q
```

Tests use fake HTTP execution and must not call the real LimaCharlie service.
