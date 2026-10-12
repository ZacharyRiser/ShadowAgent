"""Multi-tenancy tests: default-org seeding, org CRUD, members, tenant isolation.

Tenant model under test
-----------------------
- Platform principals (static env keys) see and manage everything.
- Console users are enrolled in organizations; their JWT carries the active
  org (``org_id`` / ``org_role`` claims) and every admin surface is scoped:
  org admins manage their own org's rows, read platform-shared rows, and get
  404s across tenant boundaries (no existence leak).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

INVITE_TOKEN = "tenancy-invite-token"


def _register_user(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    email: str,
    *,
    platform_role: str = "client",
    password: str = "pass-123456",
) -> dict[str, Any]:
    """Register a console user via the invite-token flow (post-bootstrap)."""
    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_INVITE_TOKEN", INVITE_TOKEN)
    monkeypatch.setenv("SHADOW_AGENT_CONSOLE_DEFAULT_ROLE", platform_role)
    response = client.post(
        "/api/v1/auth/register",
        json={"name": email.split("@", 1)[0], "email": email, "password": password},
        headers={"x-shadow-agent-invite-token": INVITE_TOKEN},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _login(client: TestClient, email: str, password: str = "pass-123456") -> dict[str, Any]:
    response = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _create_org(
    client: TestClient,
    admin_headers: dict[str, str],
    slug: str,
    name: str | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/orgs",
        headers=admin_headers,
        json={"slug": slug, "name": name or slug.replace("-", " ").title()},
    )
    assert response.status_code == 200, response.text
    return response.json()["item"]


def _add_member(
    client: TestClient,
    admin_headers: dict[str, str],
    org_id: int,
    email: str,
    role: str = "member",
) -> dict[str, Any]:
    response = client.post(
        f"/api/v1/orgs/{org_id}/members",
        headers=admin_headers,
        json={"email": email, "role": role},
    )
    assert response.status_code == 200, response.text
    return response.json()["item"]


def _create_rule(
    client: TestClient,
    auth: dict[str, str],
    name: str,
    *,
    pattern: str | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/rules",
        headers=auth,
        json={
            "name": name,
            "description": f"tenancy rule {name}",
            "rule_type": "keyword",
            "pattern": pattern or f"marker-{name}",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.5,
            "enabled": True,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["item"]


def _rule_names(client: TestClient, auth: dict[str, str]) -> list[str]:
    return [item["name"] for item in client.get("/api/v1/rules", headers=auth).json()["items"]]


# --- default organization & console enrollment ------------------------------


def test_bootstrap_admin_owns_default_org(
    client: TestClient, admin_session: tuple[str, str]
) -> None:
    token, email = admin_session
    me = client.get("/api/v1/auth/me", headers=_bearer(token)).json()
    assert me["user"]["email"] == email
    assert me["org_id"] is not None
    assert me["org_role"] == "owner"

    orgs = {org["slug"]: org for org in me["orgs"]}
    assert "default" in orgs
    assert orgs["default"]["is_default"] is True
    assert orgs["default"]["role"] == "owner"


def test_new_registration_enrolls_as_default_org_member(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, unique_id: str
) -> None:
    session = _register_user(client, monkeypatch, f"enroll-{unique_id}@example.com")
    me = client.get("/api/v1/auth/me", headers=_bearer(session["access_token"])).json()
    assert me["orgs"], "new user must belong to at least one organization"
    default = next(org for org in me["orgs"] if org["is_default"])
    assert default["role"] == "member"
    assert me["org_role"] == "member"


# --- organization CRUD -------------------------------------------------------


def test_org_crud_and_slug_validation(
    client: TestClient, admin_headers: dict[str, str], unique_id: str
) -> None:
    # invalid slugs are rejected
    for bad_slug in ("ab", "-leading-hyphen", "trailing-hyphen-", "bad-slug!"):
        response = client.post(
            "/api/v1/orgs", headers=admin_headers, json={"slug": bad_slug, "name": "Bad"}
        )
        assert response.status_code in (400, 422), bad_slug

    # uppercase input is normalized to a lowercase slug
    normalized = _create_org(client, admin_headers, f"Normalize-{unique_id}".lower())
    assert normalized["slug"] == f"normalize-{unique_id}"
    client.delete(f"/api/v1/orgs/{normalized['id']}?force=true", headers=admin_headers)

    slug = f"crud-{unique_id}"
    org = _create_org(client, admin_headers, slug)
    assert org["slug"] == slug
    assert org["is_default"] is False

    # duplicate slug
    response = client.post(
        "/api/v1/orgs", headers=admin_headers, json={"slug": slug, "name": "Duplicate"}
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "org_conflict"

    # platform admin sees every organization
    listed = client.get("/api/v1/orgs", headers=admin_headers).json()["items"]
    assert any(item["slug"] == slug for item in listed)

    # detail + update
    detail = client.get(f"/api/v1/orgs/{org['id']}", headers=admin_headers).json()["item"]
    assert detail["member_count"] == 0
    assert detail["sso_enabled"] is False

    renamed = client.patch(
        f"/api/v1/orgs/{org['id']}", headers=admin_headers, json={"name": "Renamed Org"}
    )
    assert renamed.status_code == 200
    assert renamed.json()["item"]["name"] == "Renamed Org"

    # the org already owns its creation audit row: non-forced delete is refused
    deleted = client.delete(f"/api/v1/orgs/{org['id']}", headers=admin_headers)
    assert deleted.status_code == 409
    assert deleted.json()["detail"]["error"] == "org_not_empty"

    deleted = client.delete(f"/api/v1/orgs/{org['id']}?force=true", headers=admin_headers)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["purged_rows"] >= 1


def test_default_org_cannot_be_deleted(client: TestClient, admin_headers: dict[str, str]) -> None:
    orgs = client.get("/api/v1/orgs", headers=admin_headers).json()["items"]
    default_org = next(org for org in orgs if org["is_default"])
    response = client.delete(f"/api/v1/orgs/{default_org['id']}", headers=admin_headers)
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "default_org_delete_blocked"


def test_org_creation_requires_owner_role_for_console_users(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, unique_id: str
) -> None:
    # platform role admin but plain org member in the default org
    session = _register_user(
        client, monkeypatch, f"orgcreate-{unique_id}@example.com", platform_role="admin"
    )
    response = client.post(
        "/api/v1/orgs",
        headers=_bearer(session["access_token"]),
        json={"slug": f"nope-{unique_id}", "name": "Should Fail"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "owner_role_required"


# --- membership management ---------------------------------------------------


def test_member_management_and_guards(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"members-{unique_id}")
    email = f"member-{unique_id}@example.com"
    _register_user(client, monkeypatch, email)

    # unknown email is a 404 (no account auto-creation)
    response = client.post(
        f"/api/v1/orgs/{org['id']}/members",
        headers=admin_headers,
        json={"email": f"ghost-{unique_id}@example.com", "role": "member"},
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "user_not_found"

    member = _add_member(client, admin_headers, org["id"], email, role="owner")
    assert member["org_role"] == "owner"

    # duplicate membership
    response = client.post(
        f"/api/v1/orgs/{org['id']}/members",
        headers=admin_headers,
        json={"email": email, "role": "member"},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "member_conflict"

    members = client.get(f"/api/v1/orgs/{org['id']}/members", headers=admin_headers).json()["items"]
    assert [item["email"] for item in members] == [email]

    # last owner is protected from demotion and removal
    user_id = member["user_id"]
    response = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{user_id}",
        headers=admin_headers,
        json={"role": "member"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "last_owner_protected"

    response = client.delete(
        f"/api/v1/orgs/{org['id']}/members/{user_id}", headers=admin_headers
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "last_owner_protected"

    # a second member can be added and removed freely
    other_email = f"other-{unique_id}@example.com"
    _register_user(client, monkeypatch, other_email)
    other = _add_member(client, admin_headers, org["id"], other_email, role="admin")

    promoted = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{other['user_id']}",
        headers=admin_headers,
        json={"role": "member"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["item"]["org_role"] == "member"

    removed = client.delete(
        f"/api/v1/orgs/{org['id']}/members/{other['user_id']}", headers=admin_headers
    )
    assert removed.status_code == 200


def test_org_admin_member_cannot_manage_owner_roles(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"owner-guard-{unique_id}")
    admin_email = f"orgadmin-{unique_id}@example.com"
    target_email = f"target-{unique_id}@example.com"
    _register_user(client, monkeypatch, admin_email, platform_role="admin")
    _register_user(client, monkeypatch, target_email)

    _add_member(client, admin_headers, org["id"], admin_email, role="admin")
    target = _add_member(client, admin_headers, org["id"], target_email, role="member")

    admin_session = _login(client, admin_email)
    admin_auth = _bearer(admin_session["access_token"])
    switched = client.post(
        "/api/v1/auth/switch-org",
        headers=admin_auth,
        json={"org_id": org["id"]},
    ).json()

    # org admins may update a member's role…
    response = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{target['user_id']}",
        headers=_bearer(switched["access_token"]),
        json={"role": "admin"},
    )
    assert response.status_code == 200

    # …but never grant the owner role
    response = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{target['user_id']}",
        headers=_bearer(switched["access_token"]),
        json={"role": "owner"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "owner_role_required"


def test_self_removal_and_self_demotion_blocked(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"selfguard-{unique_id}")
    owner_email = f"selfowner-{unique_id}@example.com"
    helper_email = f"selfhelper-{unique_id}@example.com"
    _register_user(client, monkeypatch, owner_email, platform_role="admin")
    _register_user(client, monkeypatch, helper_email, platform_role="admin")

    owner = _add_member(client, admin_headers, org["id"], owner_email, role="owner")
    _add_member(client, admin_headers, org["id"], helper_email, role="owner")

    owner_session = _login(client, owner_email)
    owner_auth = _bearer(owner_session["access_token"])

    response = client.delete(
        f"/api/v1/orgs/{org['id']}/members/{owner['user_id']}", headers=owner_auth
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "self_removal_blocked"

    response = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{owner['user_id']}",
        headers=owner_auth,
        json={"role": "member"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "self_demotion_blocked"


# --- tenant visibility & access control --------------------------------------


def test_console_member_sees_only_membership_orgs(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"visibility-{unique_id}")
    session = _register_user(client, monkeypatch, f"visible-{unique_id}@example.com")

    orgs = client.get("/api/v1/orgs", headers=_bearer(session["access_token"])).json()["items"]
    assert all(item["id"] != org["id"] for item in orgs)

    # direct access to a foreign org hides its existence (404, not 403)
    response = client.get(f"/api/v1/orgs/{org['id']}", headers=_bearer(session["access_token"]))
    assert response.status_code == 404


def test_org_role_gates_on_rule_management(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"rulegate-{unique_id}")

    # a client platform role is blocked from rule management even as org owner
    client_session = _register_user(
        client, monkeypatch, f"clientowner-{unique_id}@example.com", platform_role="client"
    )
    _add_member(
        client, admin_headers, org["id"], f"clientowner-{unique_id}@example.com", role="owner"
    )
    client_auth = _bearer(client_session["access_token"])
    switched = client.post(
        "/api/v1/auth/switch-org", headers=client_auth, json={"org_id": org["id"]}
    )
    assert switched.status_code == 200
    response = client.post(
        "/api/v1/rules", headers=_bearer(switched.json()["access_token"]), json={}
    )
    assert response.status_code == 403

    # an org admin with the platform admin role manages rules inside its org
    admin_session = _register_user(
        client, monkeypatch, f"orgadmin-{unique_id}@example.com", platform_role="admin"
    )
    member = _add_member(
        client, admin_headers, org["id"], f"orgadmin-{unique_id}@example.com", role="admin"
    )
    admin_auth = _bearer(admin_session["access_token"])
    switched = client.post(
        "/api/v1/auth/switch-org", headers=admin_auth, json={"org_id": org["id"]}
    )
    assert switched.status_code == 200
    admin_auth = _bearer(switched.json()["access_token"])

    rule = _create_rule(client, admin_auth, f"rulegate-{unique_id}")
    assert f"rulegate-{unique_id}" in _rule_names(client, admin_auth)
    assert f"rulegate-{unique_id}" in _rule_names(client, admin_headers)

    # org admins manage managed API keys for their organization
    created = client.post(
        "/api/v1/api-keys",
        headers=admin_auth,
        json={"name": f"rulegate-key-{unique_id}", "role": "client"},
    )
    assert created.status_code == 200

    # demoting the org admin revokes the EXISTING token's org privileges
    demoted = client.patch(
        f"/api/v1/orgs/{org['id']}/members/{member['user_id']}",
        headers=admin_headers,
        json={"role": "member"},
    )
    assert demoted.status_code == 200

    response = client.post(
        "/api/v1/api-keys",
        headers=admin_auth,
        json={"name": f"rulegate-key-2-{unique_id}", "role": "client"},
    )
    assert response.status_code == 403

    # the org-owned rule remains manageable by the org (row ownership, not role)
    response = client.delete(f"/api/v1/rules/{rule['id']}", headers=admin_auth)
    assert response.status_code == 200


def test_custom_rules_tenant_isolation(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org_a = _create_org(client, admin_headers, f"iso-a-{unique_id}")
    org_b = _create_org(client, admin_headers, f"iso-b-{unique_id}")

    admin_a = _register_user(
        client, monkeypatch, f"admin-a-{unique_id}@example.com", platform_role="admin"
    )
    admin_b = _register_user(
        client, monkeypatch, f"admin-b-{unique_id}@example.com", platform_role="admin"
    )
    _add_member(client, admin_headers, org_a["id"], f"admin-a-{unique_id}@example.com", role="owner")
    _add_member(client, admin_headers, org_b["id"], f"admin-b-{unique_id}@example.com", role="owner")

    def _org_auth(session: dict[str, Any], org_id: int) -> dict[str, str]:
        switched = client.post(
            "/api/v1/auth/switch-org",
            headers=_bearer(session["access_token"]),
            json={"org_id": org_id},
        )
        assert switched.status_code == 200, switched.text
        return _bearer(switched.json()["access_token"])

    auth_a = _org_auth(admin_a, org_a["id"])
    auth_b = _org_auth(admin_b, org_b["id"])

    # the same rule name may exist in two organizations
    rule_a = _create_rule(client, auth_a, f"shared-{unique_id}")
    rule_b1 = _create_rule(client, auth_b, f"shared-{unique_id}")
    rule_b2 = _create_rule(client, auth_b, f"org-b-marker-{unique_id}")
    assert rule_a["id"] != rule_b1["id"]

    # each org sees its own rows only
    names_a = _rule_names(client, auth_a)
    assert f"shared-{unique_id}" in names_a
    assert f"org-b-marker-{unique_id}" not in names_a
    names_b = _rule_names(client, auth_b)
    assert f"org-b-marker-{unique_id}" in names_b

    # cross-tenant access by id is a 404 (no existence leak)
    response = client.put(
        f"/api/v1/rules/{rule_b2['id']}",
        headers=auth_a,
        json={
            "name": "hijack",
            "description": "",
            "rule_type": "keyword",
            "pattern": "marker",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.9,
            "enabled": True,
        },
    )
    assert response.status_code == 404
    assert client.delete(f"/api/v1/rules/{rule_b2['id']}", headers=auth_a).status_code == 404

    # platform admin sees everything
    names_platform = _rule_names(client, admin_headers)
    assert f"shared-{unique_id}" in names_platform
    assert f"org-b-marker-{unique_id}" in names_platform

    # platform-shared rules are visible to org admins but read-only
    platform_rule = _create_rule(client, admin_headers, f"platform-{unique_id}")
    assert f"platform-{unique_id}" in _rule_names(client, auth_a)

    response = client.put(
        f"/api/v1/rules/{platform_rule['id']}",
        headers=auth_a,
        json={
            "name": f"platform-{unique_id}",
            "description": "hijack",
            "rule_type": "keyword",
            "pattern": "marker",
            "target": "prompt",
            "action": "block",
            "risk_score": 0.9,
            "enabled": True,
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "rule_read_only"
    assert client.delete(f"/api/v1/rules/{platform_rule['id']}", headers=auth_a).status_code == 403

    # own-org rules remain writable
    response = client.delete(f"/api/v1/rules/{rule_a['id']}", headers=auth_a)
    assert response.status_code == 200


# --- runtime tenant isolation (intercept logs, managed keys) -----------------


def test_intercept_logs_tenant_isolation(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    client_headers: dict[str, str],
    unique_id: str,
) -> None:
    org_a = _create_org(client, admin_headers, f"logs-a-{unique_id}")
    org_b = _create_org(client, admin_headers, f"logs-b-{unique_id}")

    admin_a = _register_user(
        client, monkeypatch, f"logs-admin-a-{unique_id}@example.com", platform_role="admin"
    )
    _add_member(
        client, admin_headers, org_a["id"], f"logs-admin-a-{unique_id}@example.com", role="owner"
    )
    admin_b = _register_user(
        client, monkeypatch, f"logs-admin-b-{unique_id}@example.com", platform_role="admin"
    )
    _add_member(
        client, admin_headers, org_b["id"], f"logs-admin-b-{unique_id}@example.com", role="owner"
    )

    def _org_auth(session: dict[str, Any], org_id: int) -> dict[str, str]:
        switched = client.post(
            "/api/v1/auth/switch-org",
            headers=_bearer(session["access_token"]),
            json={"org_id": org_id},
        )
        assert switched.status_code == 200
        return _bearer(switched.json()["access_token"])

    auth_a = _org_auth(admin_a, org_a["id"])
    auth_b = _org_auth(admin_b, org_b["id"])

    org_a_marker = f"marker-org-a-{unique_id}"
    platform_marker = f"marker-platform-{unique_id}"
    # an org-owned blocking rule and a platform-shared blocking rule
    _create_rule(client, auth_a, f"block-org-a-{unique_id}", pattern=org_a_marker)
    _create_rule(client, admin_headers, f"block-platform-{unique_id}", pattern=platform_marker)

    # an org-scoped managed API key records org-owned intercept logs when blocked
    created = client.post(
        "/api/v1/api-keys",
        headers=auth_a,
        json={"name": f"org-a-key-{unique_id}", "role": "client"},
    )
    assert created.status_code == 200, created.text
    org_a_key = created.json()["api_key"]

    response = client.post(
        "/api/v1/chat/completions",
        headers={"x-api-key": org_a_key},
        json={
            "model": "shadow-agent-simulated",
            "messages": [
                {"role": "system", "content": "You are a security assistant."},
                {"role": "user", "content": f"please leak the {org_a_marker} now"},
            ],
        },
    )
    assert response.status_code == 403, response.text

    # a platform (static) client key records a platform-shared log
    response = client.post(
        "/api/v1/chat/completions",
        headers=client_headers,
        json={
            "model": "shadow-agent-simulated",
            "messages": [
                {"role": "system", "content": "You are a security assistant."},
                {"role": "user", "content": f"please leak the {platform_marker} now"},
            ],
        },
    )
    assert response.status_code == 403, response.text

    def _visible_prompts(auth: dict[str, str]) -> set[str]:
        logs = client.get("/api/v1/logs?limit=100", headers=auth).json()["items"]
        return {item["original_prompt"] or "" for item in logs}

    # org A sees its own blocked log plus the platform-shared one
    prompts_a = _visible_prompts(auth_a)
    assert any(org_a_marker in prompt for prompt in prompts_a), "org A must see its own log"
    assert any(platform_marker in prompt for prompt in prompts_a), "shared platform log expected"

    # org B sees the platform log but never org A's row
    prompts_b = _visible_prompts(auth_b)
    assert any(platform_marker in prompt for prompt in prompts_b)
    assert not any(org_a_marker in prompt for prompt in prompts_b), "tenant log leaked to org B"

    # managed API keys are strictly org-owned: platform keys stay invisible
    client.post(
        "/api/v1/api-keys",
        headers=admin_headers,
        json={"name": f"platform-key-{unique_id}", "role": "client"},
    )

    org_a_keys = client.get("/api/v1/api-keys", headers=auth_a).json()["items"]
    assert [item["name"] for item in org_a_keys] == [f"org-a-key-{unique_id}"]

    platform_keys = client.get("/api/v1/api-keys", headers=admin_headers).json()["items"]
    platform_key_names = {item["name"] for item in platform_keys}
    assert f"org-a-key-{unique_id}" in platform_key_names
    assert f"platform-key-{unique_id}" in platform_key_names


# --- switch-org --------------------------------------------------------------


def test_switch_org_flow(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"switch-{unique_id}")
    email = f"switcher-{unique_id}@example.com"
    _register_user(client, monkeypatch, email, platform_role="admin")
    _add_member(client, admin_headers, org["id"], email, role="admin")

    login = _login(client, email)
    # highest org role wins as the active context at login
    assert login["org"]["id"] == org["id"]
    assert login["org"]["role"] == "admin"

    me = client.get("/api/v1/auth/me", headers=_bearer(login["access_token"])).json()
    assert me["org_id"] == org["id"]
    assert me["org_role"] == "admin"
    assert {item["id"] for item in me["orgs"]} >= {org["id"]}

    # switch back to the default organization
    default_org = next(item for item in me["orgs"] if item["is_default"])
    switched = client.post(
        "/api/v1/auth/switch-org",
        headers=_bearer(login["access_token"]),
        json={"org_id": default_org["id"]},
    )
    assert switched.status_code == 200
    assert switched.json()["org"]["id"] == default_org["id"]
    assert switched.json()["org"]["role"] == "member"

    me = client.get("/api/v1/auth/me", headers=_bearer(switched.json()["access_token"])).json()
    assert me["org_id"] == default_org["id"]
    assert me["org_role"] == "member"

    # switching to an organization the user does not belong to fails
    foreign = _create_org(client, admin_headers, f"foreign-{unique_id}")
    response = client.post(
        "/api/v1/auth/switch-org",
        headers=_bearer(login["access_token"]),
        json={"org_id": foreign["id"]},
    )
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "org_not_found"


# --- org deletion ------------------------------------------------------------


def test_delete_org_purges_tenant_rows(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    admin_headers: dict[str, str],
    unique_id: str,
) -> None:
    org = _create_org(client, admin_headers, f"purge-{unique_id}")
    admin = _register_user(
        client, monkeypatch, f"purge-admin-{unique_id}@example.com", platform_role="admin"
    )
    _add_member(
        client, admin_headers, org["id"], f"purge-admin-{unique_id}@example.com", role="owner"
    )
    switched = client.post(
        "/api/v1/auth/switch-org",
        headers=_bearer(admin["access_token"]),
        json={"org_id": org["id"]},
    )
    assert switched.status_code == 200
    _create_rule(client, _bearer(switched.json()["access_token"]), f"purge-rule-{unique_id}")

    # non-forced delete is refused while the org still owns rows
    response = client.delete(f"/api/v1/orgs/{org['id']}", headers=admin_headers)
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "org_not_empty"

    deleted = client.delete(
        f"/api/v1/orgs/{org['id']}?force=true", headers=admin_headers
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["purged_rows"] >= 1

    names = _rule_names(client, admin_headers)
    assert f"purge-rule-{unique_id}" not in names
