# Geoff's LimaCharlie MCP

A local MCP for LimaCharlie setup, administration, investigations, and tuning.

This is an alternative to the LimaCharlie hosted MCP. It uses LimaCharlie API
surfaces directly, requires explicit scope for data, records a local audit line
for each tool call, and can start adding value even with just read-only access.

## Why?

_Doesn't LimaCharlie already have an MCP?_
Yes.

_Is something wrong with the LimaCharlie MCP?_
Nope.

_Then... why?_
I love LimaCharlie, I had some free time, and wanted something that made
LimaCharlie more accessible to people who dont live in the dark realm of EDR
internals.

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

By default, setup uses a managed local
[Vault](https://github.com/hashicorp/vault) so the long-lived LimaCharlie API
key is not accidentally stored in chat history, `.env` files, MCP client
configuration, or audit logs. The MCP uses that protected key to mint
short-lived LimaCharlie JWTs when tools need API access.

## First-Time Auth Setup

You need two values from LimaCharlie: an organization ID and a temporary
bootstrap API key.

1. Open [LimaCharlie](https://app.limacharlie.io/), login, and choose your
   organization.
2. Copy the org ID from the URL: `app.limacharlie.io/orgs/<org-id>/...`.
3. Open a terminal on the host running your MCP, swap in your org ID where it
   says `paste-your-org-id-here`, and run this:

```bash
uvx --from git+https://github.com/geoffbelknap/limacharlie-mcp \
  limacharlie-mcp-configure \
  --oid "paste-your-org-id-here" \
  --provision-runtime-key
```

4. The command will print a temporary bootstrap key name and stop at a hidden
   `LimaCharlie API key secret` prompt. Leave it waiting there.
5. Go back to your browser and head to `Organization Settings` -> `Access
   Management` -> `REST API`.
6. Click `Create API Key`, name it exactly what the command printed, and give
   it only:

   ```text
   org.get
   apikey.ctrl
   ```

   The setup command uses this temporary key to create one dedicated runtime key
   named `limacharlie-mcp-runtime`, stores that runtime key in local Vault, and
   verifies it. It does not print either secret.

   Don't bother adding `live_stream.ctrl`; this MCP does not expose live
   firehose or streaming telemetry tools. Spraying high pressure random
   telemetry at an AI is great for burning tokens, but it ain't going to make
   you more secure.
7. Create your bootstrap key and copy the secret from the LimaCharlie dashboard.
8. Switch back to the terminal and paste the secret into the hidden prompt. It
   will not end up in your shell history.
9. After setup verifies the runtime key, delete the printed bootstrap key from
   LimaCharlie. The runtime key is already stored in Vault.

Then start a new chat with your favorite AI tool, with the plugin enabled, and
ask:

```text
Check my LimaCharlie MCP auth status.
```

The agent should confirm credentials are configured without showing secrets.

For screenshots, permissions, user API key mode, advanced deployment, and
troubleshooting, see [Onboarding And Auth](docs/onboarding-auth.md).

## What You Can Ask It To Do

Start with one of these:

- "Check my LimaCharlie MCP auth status."
- "Show me which LimaCharlie MCP profile and tools are available."
- "Review my LimaCharlie org posture."
- "List my LimaCharlie sensors."
- "Triage this LimaCharlie detection."
- "Help me tune noisy LimaCharlie detections."

The MCP is split into focused profiles so normal agent sessions do not need to
load every tool at once:

| Profile | Intended use |
| --- | --- |
| `core` | Auth, org discovery, runtime status, schemas, ontology, and downloads. |
| `fleet` | Sensor onboarding, installation keys, tags, online state, and fleet maintenance. |
| `admin` | Organizations, users, groups, API keys, billing, outputs, extensions, and org configuration. |
| `content` | D&R, false positives, YARA, Hive content, lookups, playbooks, SOPs, and content governance. |
| `detect` | Bounded detection triage, events, cases, IOC lookups, audit, search, artifacts, and jobs. |
| `contain` | Endpoint containment, response tasking, reliable tasks, job cancellation, and supporting evidence. |
| `evict` | Response tasking plus content/YARA workflows used to remove adversary footholds. |
| `recover` | Post-incident recovery verification and restoration previews. |
| `review` | Read-only posture review, tuning, content coverage, case backlog, and access hygiene. |

Ask the agent to call `lc_tool_catalog` when you want the current profile's
exact tool list.

## Safety Model

This MCP is meant to help an agent work carefully, not turn LimaCharlie into an
unbounded data pump.

- Tools use bounded reads with explicit org scope, limits, cursors, selectors,
  or time windows.
- Response and administration changes use preview/confirm flows.
- API keys, JWTs, Vault tokens, and secret values are not returned in tool
  responses or audit excerpts.
- Live telemetry streaming, spout, and firehose surfaces are intentionally not
  exposed. Use LimaCharlie outputs, storage, SIEM pipelines, or purpose-built
  stream processors for operational telemetry streams.

## More Help

- First-time setup, screenshots, user API keys, and reauth:
  [Onboarding And Auth](docs/onboarding-auth.md)
- Advanced operator deployment and MCP client config:
  [Deployment](docs/deployment.md)
- LimaCharlie docs: <https://docs.limacharlie.io/>
- LimaCharlie API key docs:
  <https://docs.limacharlie.io/7-administration/access/api-keys/>
