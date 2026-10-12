"""API routers split by domain."""

from app.routers import (
    api_keys,
    auth,
    gateway,
    monitoring,
    orgs,
    policies,
    replays,
    rules,
    tool_policies,
)

__all__ = [
    "api_keys",
    "auth",
    "gateway",
    "monitoring",
    "orgs",
    "policies",
    "replays",
    "rules",
    "tool_policies",
]
