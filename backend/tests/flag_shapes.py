"""Shared flag-shape checks for every copy of the scanner."""

import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "flag-shapes.json"


def assert_scanner(search, search_bytes):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for case in payload["cases"]:
        prefix = case.get("prefix") or ""
        if case.get("bytes_hex"):
            found = search_bytes(bytes.fromhex(case["bytes_hex"]), prefix)
        else:
            found = search(case.get("text") or "", prefix)
        limit = case.get("max_hits", 20)
        assert len(found) <= limit, (case["name"], len(found))
        expected = case.get("expect") or []
        if case.get("exact"):
            assert len(found) == len(expected), (case["name"], found)
        for item in expected:
            assert any(hit["value"] == item["value"] and hit["detail"] == item["detail"] for hit in found), (case["name"], found, item)
        for item in case.get("expect_contains") or []:
            assert any(hit["value"] == item["value"] and hit["detail"] == item["detail"] for hit in found), (case["name"], found, item)
