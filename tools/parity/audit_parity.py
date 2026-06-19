#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).with_name("categories.json")
DEFAULT_LLMS_URL = "https://docs.limacharlie.io/llms.txt"


@dataclass(frozen=True)
class DocsIndex:
    sections: dict[str, list[dict[str, str]]]


def load_catalog() -> dict[str, Any]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from limacharlie_mcp.api import LimaCharlieAPI

    client = LimaCharlieAPI(api_key="parity-audit-placeholder")
    return client.tool_catalog()["data"]


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_text_from_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def parse_llms_txt(text: str) -> DocsIndex:
    sections: dict[str, list[dict[str, str]]] = {}
    current = "Pages"
    sections[current] = []
    link_re = re.compile(r"^- \[(?P<title>[^\]]+)\]\((?P<url>[^)]+)\)(?:: (?P<summary>.*))?$")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            current = line.removeprefix("## ").strip()
            sections.setdefault(current, [])
            continue
        match = link_re.match(line)
        if match:
            sections.setdefault(current, []).append(
                {
                    "title": match.group("title"),
                    "url": match.group("url"),
                    "summary": match.group("summary") or "",
                }
            )
    return DocsIndex(sections=sections)


def load_docs_index(*, llms_file: Path | None, llms_url: str | None) -> DocsIndex | None:
    if llms_file:
        return parse_llms_txt(llms_file.read_text(encoding="utf-8"))
    if llms_url:
        return parse_llms_txt(read_text_from_url(llms_url))
    return None


def operation_matches(operation: str, category: dict[str, Any]) -> bool:
    if operation in set(category.get("operation_keys", [])):
        return True
    for prefix in category.get("operation_prefixes", []):
        if operation.startswith(prefix):
            return True
    return False


def audit_category(
    category: dict[str, Any],
    *,
    operations: dict[str, Any],
    unsupported: dict[str, Any],
    docs_index: DocsIndex | None,
) -> dict[str, Any]:
    matched_operations = sorted(
        operation
        for operation in operations
        if operation_matches(operation, category)
    )
    required = sorted(category.get("required_operations", []))
    missing_required = [operation for operation in required if operation not in operations]
    excluded_catalog_keys = sorted(category.get("excluded_catalog_keys", []))
    missing_exclusions = [key for key in excluded_catalog_keys if key not in unsupported]
    doc_sections = category.get("doc_sections", [])
    doc_pages = 0
    missing_doc_sections: list[str] = []
    if docs_index is not None:
        for section in doc_sections:
            pages = docs_index.sections.get(section)
            if pages is None:
                missing_doc_sections.append(section)
            else:
                doc_pages += len(pages)

    return {
        "id": category["id"],
        "title": category["title"],
        "decision": category["decision"],
        "reason": category["reason"],
        "doc_sections": doc_sections,
        "doc_page_count": doc_pages,
        "missing_doc_sections": missing_doc_sections,
        "matched_operation_count": len(matched_operations),
        "matched_operations": matched_operations,
        "required_operations": required,
        "missing_required_operations": missing_required,
        "excluded_catalog_keys": excluded_catalog_keys,
        "missing_excluded_catalog_keys": missing_exclusions,
        "excluded_capabilities": category.get("excluded_capabilities", []),
        "deferred_capabilities": category.get("deferred_capabilities", []),
    }


def build_report(manifest: dict[str, Any], catalog: dict[str, Any], docs_index: DocsIndex | None) -> dict[str, Any]:
    operations = catalog["operations"]
    unsupported = catalog.get("unsupported_capabilities", {})
    categories = [
        audit_category(category, operations=operations, unsupported=unsupported, docs_index=docs_index)
        for category in manifest["categories"]
    ]
    categorized_operations = {
        operation
        for category in manifest["categories"]
        for operation in operations
        if operation_matches(operation, category)
    }
    uncategorized_operations = sorted(set(operations) - categorized_operations)
    missing_required = {
        category["id"]: category["missing_required_operations"]
        for category in categories
        if category["missing_required_operations"]
    }
    missing_exclusions = {
        category["id"]: category["missing_excluded_catalog_keys"]
        for category in categories
        if category["missing_excluded_catalog_keys"]
    }
    missing_doc_sections = {
        category["id"]: category["missing_doc_sections"]
        for category in categories
        if category["missing_doc_sections"]
    }
    decision_counts: dict[str, int] = {}
    for category in categories:
        decision_counts[category["decision"]] = decision_counts.get(category["decision"], 0) + 1

    ok = not missing_required and not missing_exclusions and not missing_doc_sections and not uncategorized_operations
    return {
        "ok": ok,
        "source_indexes": manifest.get("source_indexes", []),
        "operation_count": len(operations),
        "unsupported_capability_count": len(unsupported),
        "category_count": len(categories),
        "decision_counts": decision_counts,
        "categories": categories,
        "uncategorized_operations": uncategorized_operations,
        "missing_required_operations": missing_required,
        "missing_excluded_catalog_keys": missing_exclusions,
        "missing_doc_sections": missing_doc_sections,
    }


def format_markdown(report: dict[str, Any], *, include_operations: bool = False) -> str:
    lines = [
        "# LimaCharlie MCP Parity Audit",
        "",
        f"- Status: {'ok' if report['ok'] else 'needs_review'}",
        f"- Operations: {report['operation_count']}",
        f"- Unsupported capabilities: {report['unsupported_capability_count']}",
        f"- Categories: {report['category_count']}",
        "",
        "| Category | Decision | Docs | Ops | Missing Required | Exclusions Missing |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for category in report["categories"]:
        missing_required = ", ".join(category["missing_required_operations"]) or "-"
        missing_exclusions = ", ".join(category["missing_excluded_catalog_keys"]) or "-"
        lines.append(
            "| {title} | {decision} | {docs} | {ops} | {missing_required} | {missing_exclusions} |".format(
                title=category["title"],
                decision=category["decision"],
                docs=category["doc_page_count"],
                ops=category["matched_operation_count"],
                missing_required=missing_required,
                missing_exclusions=missing_exclusions,
            )
        )
    lines.extend(["", "## Review Notes", ""])
    for category in report["categories"]:
        lines.append(f"### {category['title']}")
        lines.append(f"- Decision: `{category['decision']}`")
        lines.append(f"- Rationale: {category['reason']}")
        if category["excluded_catalog_keys"]:
            lines.append(f"- Catalog exclusions: {', '.join(category['excluded_catalog_keys'])}")
        if category["excluded_capabilities"]:
            excluded = ", ".join(item["id"] for item in category["excluded_capabilities"])
            lines.append(f"- Category exclusions: {excluded}")
        if category["deferred_capabilities"]:
            deferred = ", ".join(item["id"] for item in category["deferred_capabilities"])
            lines.append(f"- Deferred: {deferred}")
        if include_operations:
            operations = ", ".join(category["matched_operations"]) or "-"
            lines.append(f"- Matched operations: {operations}")
        lines.append("")
    if report["uncategorized_operations"]:
        lines.append("## Uncategorized Operations")
        lines.append("")
        for operation in report["uncategorized_operations"]:
            lines.append(f"- `{operation}`")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit LimaCharlie MCP category parity against reviewed categories.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--llms-file", type=Path)
    parser.add_argument("--llms-url", default=None)
    parser.add_argument("--fetch-current-docs", action="store_true", help=f"Fetch {DEFAULT_LLMS_URL}.")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--include-operations", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when the report needs review.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    llms_url = args.llms_url
    if args.fetch_current_docs and not llms_url:
        llms_url = DEFAULT_LLMS_URL
    manifest = load_manifest(args.manifest)
    catalog = load_catalog()
    docs_index = load_docs_index(llms_file=args.llms_file, llms_url=llms_url)
    report = build_report(manifest, catalog, docs_index)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_markdown(report, include_operations=args.include_operations), end="")
    if args.strict and not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
