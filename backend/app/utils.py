"""Small shared pure helpers."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone


def _json_loads_safe(value: str, fallback):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _utc_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None

    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat()


def _normalized_email(value: str) -> str:
    return value.strip().lower()


# Email shape check for console account identities.
#
# Deliberately NOT RFC 5322: quoted local parts, comments and bare domains are
# rejected. The goal is narrower — stop malformed input such as
# "http/l8000@qq.com" or "notanemail" from becoming a stored account identity,
# while still accepting ordinary addresses (dots, "+tag", hyphenated domains).
_EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+$")
_EMAIL_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")
_EMAIL_TLD_RE = re.compile(r"^[A-Za-z]{2,63}$")


def is_valid_email(value: str) -> bool:
    """True when ``value`` looks like a usable email address.

    Rules: exactly one ``@``; local part 1-64 chars of ``[A-Za-z0-9._%+-]``
    with no leading/trailing/consecutive dots; domain of 2+ labels, each
    ``[A-Za-z0-9-]`` and not starting/ending with ``-``; final label (TLD)
    alphabetic, 2-63 chars; total length 3-255.
    """
    if not isinstance(value, str):
        return False

    candidate = value.strip()
    if not 3 <= len(candidate) <= 255:
        return False
    if candidate.count("@") != 1:
        return False

    local, _, domain = candidate.partition("@")
    if not 1 <= len(local) <= 64:
        return False
    if not _EMAIL_LOCAL_RE.match(local):
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not _EMAIL_TLD_RE.match(labels[-1]):
        return False
    return all(_EMAIL_LABEL_RE.match(label) for label in labels[:-1])
