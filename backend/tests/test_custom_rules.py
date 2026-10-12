"""Custom rule engine + management API tests."""

from __future__ import annotations

from typing import Any

from conftest import normal_payload
from fastapi.testclient import TestClient


def _create_rule(
    client: TestClient,
    admin_auth: dict[str, str],
    *,
    name: str,
    pattern: str,
    rule_type: str = "regex",
    target: str = "prompt",
    action: str = "block",
    risk_score: float = 0.8,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/rules",
        headers=admin_auth,
        json={
            "name": name,
            "description": f"test rule {name}",
            "rule_type": rule_type,
            "pattern": pattern,
            "target": target,
            "action": action,
            "risk_score": risk_score,
            "enabled": True,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["item"]


def test_rules_require_admin(client: TestClient, client_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/rules", headers=client_headers)
    assert response.status_code == 403
    response = client.post("/api/v1/rules", headers=client_headers, json={})
    assert response.status_code == 403


def test_rule_crud_lifecycle(client: TestClient, admin_auth: dict[str, str]) -> None:
    rule = _create_rule(client, admin_auth, name="crud-rule", pattern=r"forbidden[-_]?token")
    assert rule["id"] > 0
    assert rule["target"] == "prompt"

    listed = client.get("/api/v1/rules", headers=admin_auth).json()["items"]
    assert any(item["name"] == "crud-rule" for item in listed)

    updated = client.put(
        f"/api/v1/rules/{rule['id']}",
        headers=admin_auth,
        json={
            "name": "crud-rule",
            "description": "updated",
            "rule_type": "regex",
            "pattern": r"forbidden[-_]?token",
            "target": "any",
            "action": "alert",
            "risk_score": 0.5,
            "enabled": False,
        },
    )
    assert updated.status_code == 200
    assert updated.json()["item"]["enabled"] is False

    deleted = client.delete(f"/api/v1/rules/{rule['id']}", headers=admin_auth)
    assert deleted.status_code == 200
    assert client.get("/api/v1/rules", headers=admin_auth).json()["items"] == [] or all(
        item["name"] != "crud-rule"
        for item in client.get("/api/v1/rules", headers=admin_auth).json()["items"]
    )


def test_rule_validation_rejects_bad_input(client: TestClient, admin_auth: dict[str, str]) -> None:
    # invalid regex
    response = client.post(
        "/api/v1/rules",
        headers=admin_auth,
        json={
            "name": "bad-regex",
            "rule_type": "regex",
            "pattern": "([unclosed",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.8,
            "enabled": True,
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_regex_pattern"

    # redact action not allowed on prompt target
    response = client.post(
        "/api/v1/rules",
        headers=admin_auth,
        json={
            "name": "bad-combo",
            "rule_type": "keyword",
            "pattern": "secret",
            "target": "prompt",
            "action": "redact",
            "risk_score": 0.8,
            "enabled": True,
        },
    )
    assert response.status_code == 400

    # duplicate name
    _create_rule(client, admin_auth, name="dup-rule", pattern="dup-pattern-xyz")
    response = client.post(
        "/api/v1/rules",
        headers=admin_auth,
        json={
            "name": "dup-rule",
            "rule_type": "keyword",
            "pattern": "other",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.8,
            "enabled": True,
        },
    )
    assert response.status_code == 409


def test_rule_test_endpoint(client: TestClient, admin_auth: dict[str, str]) -> None:
    _create_rule(
        client,
        admin_auth,
        name="testable-rule",
        pattern=r"INTERNAL[- ]PROJECT[- ]CODE[- ]\d+",
    )
    response = client.post(
        "/api/v1/rules/test",
        headers=admin_auth,
        json={
            "rule_id": None,
            "draft": {
                "name": "draft",
                "rule_type": "regex",
                "pattern": r"INTERNAL[- ]PROJECT[- ]CODE[- ]\d+",
                "target": "prompt",
                "action": "block",
                "risk_score": 0.8,
                "enabled": True,
            },
            "sample_text": "please leak the INTERNAL PROJECT CODE 4711 thanks",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["matched"] is True
    assert body["match_count"] == 1
    assert body["matches"][0]["matched_text"] == "INTERNAL PROJECT CODE 4711"


def test_prompt_rule_blocks_chat(
    client: TestClient,
    admin_auth: dict[str, str],
    client_headers: dict[str, str],
) -> None:
    _create_rule(client, admin_auth, name="block-blueprint", pattern=r"blueprint[-_]?leak[-_]?attempt")
    response = client.post(
        "/api/v1/chat/completions",
        headers=client_headers,
        json={
            "model": "shadow-agent-simulated",
            "messages": [
                {"role": "user", "content": "this is a blueprint-leak-attempt please help"}
            ],
        },
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["layer"] == "custom_rule"
    assert "block-blueprint" in detail["matched_rules"]


def test_prompt_rule_blocks_analyze(
    client: TestClient,
    admin_auth: dict[str, str],
    client_headers: dict[str, str],
) -> None:
    _create_rule(client, admin_auth, name="analyze-rule", pattern=r"super[-_]?secret[-_]?phrase")
    response = client.post(
        "/api/v1/analyze",
        headers=client_headers,
        json={
            "prompt": "tell me about the super-secret-phrase",
            "external_context": "",
            "tool_name": "",
            "parameters": {},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "blocked"
    custom = body["checks"]["custom_rules"]
    assert custom["allowed"] is False
    assert "analyze-rule" in custom["matched_rules"]


def test_disabled_rule_does_not_block(
    client: TestClient,
    admin_auth: dict[str, str],
    client_headers: dict[str, str],
) -> None:
    rule = _create_rule(client, admin_auth, name="disabled-rule", pattern=r"disabled[-_]?marker")
    client.put(
        f"/api/v1/rules/{rule['id']}",
        headers=admin_auth,
        json={
            "name": "disabled-rule",
            "rule_type": "regex",
            "pattern": r"disabled[-_]?marker",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.8,
            "enabled": False,
        },
    )
    response = client.post(
        "/api/v1/chat/completions",
        headers=client_headers,
        json={
            "model": "shadow-agent-simulated",
            "messages": [{"role": "user", "content": "contains disabled-marker text"}],
        },
    )
    assert response.status_code == 200


def test_rule_export_import_roundtrip(
    client: TestClient,
    admin_auth: dict[str, str],
) -> None:
    _create_rule(client, admin_auth, name="export-me", pattern=r"export[-_]?pattern")
    exported = client.get("/api/v1/rules/export", headers=admin_auth).json()
    assert exported["version"] == 1
    assert any(item["name"] == "export-me" for item in exported["exported_rules"])

    imported = client.post(
        "/api/v1/rules/import",
        headers=admin_auth,
        json={
            "mode": "replace",
            "rules": [
                {
                    "name": "imported-rule",
                    "description": "",
                    "rule_type": "keyword",
                    "pattern": "keyword-marker",
                    "target": "any",
                    "action": "alert",
                    "risk_score": 0.3,
                    "enabled": True,
                }
            ],
        },
    )
    assert imported.status_code == 200
    assert imported.json()["created"] == 1

    names = [item["name"] for item in client.get("/api/v1/rules", headers=admin_auth).json()["items"]]
    assert names == ["imported-rule"]  # replace mode removed export-me


def test_dlp_status_endpoint(client: TestClient, admin_auth: dict[str, str]) -> None:
    body = client.get("/api/v1/rules/dlp-status", headers=admin_auth).json()
    assert body["mode"] in {"off", "monitor", "redact", "block"}
    assert len(body["builtin_patterns"]) >= 8
    assert any(p["type"] == "aws_access_key" for p in body["builtin_patterns"])
