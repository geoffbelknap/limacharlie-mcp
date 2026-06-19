---
name: limacharlie-evict-response
description: Evict adversary footholds using LimaCharlie evidence, response tasking, YARA, D&R, false-positive, integrity, logging, and content workflows. Use after triage/containment when users need to remove persistence, malicious artifacts, unsafe rules, or attacker access.
---

# LimaCharlie Evict Response

## Workflow

Use the `evict` profile. Eviction removes footholds and persistence; it should be
driven by evidence gathered during detect and contain.

1. Confirm what must be removed:
   - Persistence mechanism, malicious file, process, account, scheduled task, rule gap, or access path.
   - Affected sensors and whether containment is still required.
2. Select evidence-backed tools:
   - Endpoint tasking for removal or validation commands.
   - YARA scan preview for suspicious artifacts.
   - D&R, false-positive, integrity, logging, or YARA content previews for durable coverage changes.
3. Stage changes:
   - Preview every mutation.
   - Prefer one logical change per preview so rollback and audit are clear.
   - Record expected effect and validation read before confirmation.
4. Validate eviction:
   - Re-run bounded detection/event/search reads.
   - Confirm persistence no longer appears.
   - Hand off to recovery verification when active footholds are removed.

## Guardrails

Do not equate suppression with eviction. A false-positive or D&R change that
hides alerts without removing attacker access is not eviction. Do not run broad
destructive tasking without explicit target lists and user confirmation.
