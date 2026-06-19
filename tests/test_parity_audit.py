from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "tools" / "parity" / "audit_parity.py"
MANIFEST_PATH = ROOT / "tools" / "parity" / "categories.json"


def load_audit_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("audit_parity", AUDIT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parity_manifest_covers_current_tool_catalog() -> None:
    audit = load_audit_module()

    manifest = audit.load_manifest(MANIFEST_PATH)
    catalog = audit.load_catalog()
    report = audit.build_report(manifest, catalog, docs_index=None)

    assert report["ok"] is True
    assert report["review"]["status"] == "reviewed_with_user"
    assert report["operation_count"] >= 289
    assert report["unsupported_capability_count"] == 2
    assert report["uncategorized_operations"] == []
    assert report["missing_required_operations"] == {}
    assert report["missing_excluded_catalog_keys"] == {}
    policy_ids = {decision["id"] for decision in report["review"]["policy_decisions"]}
    assert "endpoint_agent_local_operations" in policy_ids
    assert "telemetry_streaming_firehose" in policy_ids
    assert "broad_ai_chat_generation" in policy_ids


def test_parity_audit_detects_new_unreviewed_operation() -> None:
    audit = load_audit_module()

    manifest = audit.load_manifest(MANIFEST_PATH)
    catalog = audit.load_catalog()
    catalog["operations"] = dict(catalog["operations"])
    catalog["operations"]["new_surface.unreviewed"] = {
        "suite": "administration",
        "tool": "lc_unreviewed",
        "action": "read",
    }
    report = audit.build_report(manifest, catalog, docs_index=None)

    assert report["ok"] is False
    assert report["uncategorized_operations"] == ["new_surface.unreviewed"]


def test_llms_parser_reads_sections_and_pages() -> None:
    audit = load_audit_module()
    text = """# LimaCharlie Documentation

## Data & Queries

- [LCQL Examples](https://docs.limacharlie.io/4-data-queries/lcql-examples/)
- [Events](https://docs.limacharlie.io/4-data-queries/events/): Events

## AI Sessions

- [Overview](https://docs.limacharlie.io/9-ai-sessions/): AI Sessions
"""

    parsed = audit.parse_llms_txt(text)

    assert [page["title"] for page in parsed.sections["Data & Queries"]] == ["LCQL Examples", "Events"]
    assert parsed.sections["Data & Queries"][1]["summary"] == "Events"
    assert parsed.sections["AI Sessions"][0]["url"] == "https://docs.limacharlie.io/9-ai-sessions/"
