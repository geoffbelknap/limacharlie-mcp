from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from limacharlie_mcp.api import LimaCharlieAPI


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"
SID = "eb531a76-bd44-48e1-9fb6-5e24ae9560e4"
BAD_SID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class SequencedHTTP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.routes: list[tuple[str, str, httpx.Response]] = []

    def add(self, method: str, url: str, payload: Any, status_code: int = 200) -> None:
        self.routes.append(
            (
                method,
                url,
                httpx.Response(status_code, json=payload, headers={"content-type": "application/json"}),
            )
        )

    def request(self, method, url, *, headers=None, params=None, data=None, json=None, timeout=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "data": data,
                "json": json,
                "timeout": timeout,
            }
        )
        for index, (route_method, route_url, response) in enumerate(self.routes):
            if route_method == method and route_url == url:
                self.routes.pop(index)
                return response
        raise AssertionError(f"unexpected request: {method} {url}")


def make_client(tmp_path: Path, fake: SequencedHTTP) -> LimaCharlieAPI:
    fake.add("POST", "https://jwt.limacharlie.io", {"jwt": "test-token", "expires_in": 3000})
    return LimaCharlieAPI(api_key="secret", audit_path=tmp_path / "audit.jsonl", http_client=fake)


def test_ax_trajectory_discovery_identifies_required_org_scope(tmp_path: Path) -> None:
    client = make_client(tmp_path, SequencedHTTP())

    catalog = client.tool_catalog()
    operations = catalog["data"]["operations"]
    chosen = operations["sensor.list"]

    assert catalog["ok"] is True
    assert chosen["tool"] == "lc_list_sensors"
    assert chosen["required_inputs"] == ["oid"]
    assert chosen["side_effects"] == "none"
    assert all(not op.get("tool", "").startswith("lc_raw") for op in operations.values())


def test_ax_trajectory_sensor_investigation_reports_evidence(tmp_path: Path) -> None:
    fake = SequencedHTTP()
    fake.add(
        "GET",
        f"https://api.limacharlie.io/v1/sensors/{OID}",
        {"sensors": [{"sid": SID, "hostname": "win-prod-01"}]},
    )
    fake.add("GET", f"https://api.limacharlie.io/v1/{SID}", {"info": {"sid": SID, "hostname": "win-prod-01"}})
    client = make_client(tmp_path, fake)

    listed = client.list_sensors(OID, selector="hostname == win-prod-01", limit=10)
    selected_sid = listed["data"]["sensors"][0]["sid"]
    fetched = client.get_sensor(OID, selected_sid)
    answer = {
        "hostname": fetched["data"]["info"]["hostname"],
        "sensor_id": fetched["resource"]["id"],
        "evidence": [
            listed["request_id"],
            fetched["request_id"],
        ],
    }

    assert listed["ok"] is True
    assert fetched["ok"] is True
    assert answer == {
        "hostname": "win-prod-01",
        "sensor_id": SID,
        "evidence": [listed["request_id"], fetched["request_id"]],
    }
    assert listed["meta"]["summary"]["sensors_count"] == 1
    assert fetched["side_effects"] == []


def test_ax_trajectory_not_found_recovery_lists_then_retries(tmp_path: Path) -> None:
    fake = SequencedHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/{BAD_SID}", {"error": "sensor not found"}, status_code=404)
    fake.add("GET", f"https://api.limacharlie.io/v1/sensors/{OID}", {"sensors": [{"sid": SID}]})
    fake.add("GET", f"https://api.limacharlie.io/v1/{SID}", {"info": {"sid": SID, "hostname": "linux-prod-02"}})
    client = make_client(tmp_path, fake)

    first = client.get_sensor(OID, BAD_SID)
    listed = client.list_sensors(OID, limit=25)
    retry = client.get_sensor(OID, listed["data"]["sensors"][0]["sid"])
    trajectory = [first["operation"], listed["operation"], retry["operation"]]

    assert first["ok"] is False
    assert first["error"]["class"] == "not_found"
    assert "List the resource collection." in first["error"]["suggested_next_actions"]
    assert retry["ok"] is True
    assert retry["data"]["info"]["hostname"] == "linux-prod-02"
    assert trajectory == ["sensor.get", "sensor.list", "sensor.get"]


def test_ax_trajectory_action_boundary_requires_preview_before_confirm(tmp_path: Path) -> None:
    fake = SequencedHTTP()
    fake.add("POST", f"https://api.limacharlie.io/v1/{SID}/tags", {"ok": True})
    client = make_client(tmp_path, fake)

    preview = client.preview_add_sensor_tag(OID, SID, "investigating", ttl_seconds=3600)
    assert fake.calls == []
    assert preview["operation"] == "sensor.tag.add.preview"
    assert preview["side_effects"] == []
    assert preview["state"]["current"] == "pending_confirmation"

    confirmed = client.confirm_action(preview["data"]["confirmation_token"])
    replay = client.confirm_action(preview["data"]["confirmation_token"])

    assert confirmed["ok"] is True
    assert confirmed["operation"] == "action.confirm"
    assert confirmed["side_effects"][0]["type"] == "sensor_tag_added"
    assert replay["ok"] is False
    assert replay["error"]["code"] == "action_preview_not_found"
    assert "test-token" not in json.dumps(preview)
    assert "test-token" not in json.dumps(confirmed)


def test_ax_trajectory_lcql_search_is_validate_execute_poll(tmp_path: Path) -> None:
    fake = SequencedHTTP()
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}/url", {"search": "https://search.limacharlie.io"})
    fake.add("POST", "https://search.limacharlie.io/v1/search/validate", {"valid": True, "estimate": {"cost": 2}})
    fake.add("POST", "https://search.limacharlie.io/v1/search", {"queryId": "query-1"})
    fake.add(
        "GET",
        "https://search.limacharlie.io/v1/search/query-1",
        {"completed": True, "results": [{"type": "events", "rows": [{"atom": "a1"}]}]},
    )
    client = make_client(tmp_path, fake)

    validated = client.validate_search_query(OID, "event.FILE_PATH ends with .exe", 1_771_000_000, 1_771_003_600)
    started = client.execute_search_query(OID, "event.FILE_PATH ends with .exe", 1_771_000_000, 1_771_003_600)
    polled = client.poll_search_query(OID, started["state"]["query_id"])
    evidence = [validated["request_id"], started["request_id"], polled["request_id"]]

    assert validated["ok"] is True
    assert started["state"]["query_id"] == "query-1"
    assert polled["state"]["current"] == "succeeded"
    assert polled["data"]["results"][0]["rows"][0]["atom"] == "a1"
    assert evidence == [validated["request_id"], started["request_id"], polled["request_id"]]
    assert "test-token" not in json.dumps(polled)
