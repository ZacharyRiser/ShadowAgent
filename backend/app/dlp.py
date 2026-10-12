"""Response-side DLP: scan model OUTPUT for sensitive data before it reaches
the caller.

Modes (``SHADOW_AGENT_RESPONSE_DLP_MODE``):
- ``off``     : no scanning.
- ``monitor`` : log matches, pass the response through unchanged.
- ``redact``  : replace matched spans with ``[REDACTED:<type>]`` (default).
- ``block``   : refuse to return the response (403 / stream error frame).

Detection = built-in credential patterns + custom rules with target
``response``/``any`` (block rules force blocking, redact rules add redaction
patterns, alert rules log only).

Streaming uses a hold-back state machine: a small tail of generated text is
withheld so secrets spanning chunk boundaries are still caught; a private-key
header suppresses everything until the END marker (or stream end).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.alerts import enqueue_alert
from app.custom_rules import RuleHit, enabled_rules, match_rules
from app.events import publish_event
from app.metrics import record_dlp_scan
from database import SessionLocal
from models import AlertEvent, CustomRule, InterceptLog
from security_controls import redact_sensitive_assignments, sanitize_json
from security_engine import AuditDecision

logger = logging.getLogger("shadow_agent.dlp")

DLP_MODES = ("off", "monitor", "redact", "block")
_DLP_LAYER = "response_dlp"
_DLP_THREAT_TYPE = "Data Exfiltration"

# (type, compiled pattern, risk score)
BUILTIN_DLP_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0.95,
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        0.95,
    ),
    (
        "openai_style_key",
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b"),
        0.9,
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.9,
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        0.95,
    ),
    (
        "jwt_token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        0.9,
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        0.98,
    ),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|access[_-]?token)\b['\"]?\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9_\-/+=.]{16,}"
        ),
        0.85,
    ),
]


def response_dlp_mode() -> str:
    import os

    mode = os.getenv("SHADOW_AGENT_RESPONSE_DLP_MODE", "redact").strip().lower()
    if mode not in DLP_MODES:
        logger.warning("Invalid SHADOW_AGENT_RESPONSE_DLP_MODE=%r, falling back to redact", mode)
        return "redact"
    return mode


@dataclass(slots=True)
class DlpMatch:
    match_type: str
    span: tuple[int, int]
    rule_name: str
    risk_score: float
    action: str  # block | redact | alert
    source: str  # builtin | custom


@dataclass(slots=True)
class ScanOutcome:
    matches: list[DlpMatch] = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        return any(match.action == "block" for match in self.matches)

    @property
    def has_redactions(self) -> bool:
        return any(match.action == "redact" for match in self.matches)

    def summary(self) -> list[dict[str, Any]]:
        counts: dict[tuple[str, str], int] = {}
        for match in self.matches:
            counts[(match.match_type, match.action)] = counts.get((match.match_type, match.action), 0) + 1
        return [
            {"type": match_type, "action": action, "count": count}
            for (match_type, action), count in sorted(counts.items())
        ]

    def max_risk(self) -> float:
        return max((match.risk_score for match in self.matches), default=0.0)


def scan_text(text: str, rules: list[CustomRule]) -> ScanOutcome:
    """Scan ``text`` with builtin patterns + custom response rules."""
    outcome = ScanOutcome()
    if not text:
        return outcome

    for match_type, pattern, risk in BUILTIN_DLP_PATTERNS:
        for match in pattern.finditer(text):
            outcome.matches.append(
                DlpMatch(
                    match_type=match_type,
                    span=(match.start(), match.end()),
                    rule_name=f"builtin:{match_type}",
                    risk_score=risk,
                    action="redact",
                    source="builtin",
                )
            )

    custom_hits: list[RuleHit] = match_rules(text, rules)
    for hit in custom_hits:
        outcome.matches.append(
            DlpMatch(
                match_type=hit.rule.name,
                span=hit.span,
                rule_name=hit.rule.name,
                risk_score=hit.rule.risk_score,
                action=hit.rule.action,
                source="custom",
            )
        )
    return outcome


def apply_redactions(text: str, outcome: ScanOutcome) -> str:
    """Replace builtin matched spans with placeholders (longest-first, no overlaps)."""
    if not outcome.matches:
        return text

    pieces: list[str] = []
    last_end = 0
    spanned = sorted(
        (match for match in outcome.matches if match.span != (0, 0)),
        key=lambda match: match.span,
    )
    for match in spanned:
        start, end = match.span
        if start < last_end:
            continue
        pieces.append(text[last_end:start])
        pieces.append(f"[REDACTED:{match.match_type}]")
        last_end = end
    pieces.append(text[last_end:])
    return "".join(pieces)


# --- log persistence redaction ---------------------------------------------
#
# Intercept and audit rows are the longest-lived records the gateway keeps
# (180-365 days, see app/retention.py) and are read back by the console, by
# exports and by anyone with database access. A prompt that merely *mentions* a
# credential therefore becomes a durable secret at rest, even when the request
# itself was allowed -- the DLP guarantee applies to what leaves the gateway,
# not to what it remembers.
#
# ``redact_text`` was already called on every write, but its pattern set only
# covers ``key=value`` assignments and ``Bearer <token>``. A bare secret --
# ``sk-...``, ``AKIA...``, a JWT, a PEM block -- has no assignment prefix, so it
# used to land in ``intercept_logs.original_prompt`` verbatim. Measured before
# the fix: a prompt containing ``sk-proj-...`` was stored in clear.
#
# ``SHADOW_AGENT_LOG_REDACT`` closes that gap and makes the strength a deliberate
# deployment choice.

LOG_REDACT_MODES = ("off", "secrets", "full")

# Credential *shapes* worth masking in stored text, reused from the response
# scanner so a secret is judged identically whether it is leaving the gateway or
# being written down by it.
_LOG_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # The whole PEM block first: ``BUILTIN_DLP_PATTERNS`` only matches the
    # ``-----BEGIN ... PRIVATE KEY-----`` header, which would leave the key
    # material itself in the log and look like a redaction while doing nothing.
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,16384}?-----END [A-Z ]*PRIVATE KEY-----"
        ),
    ),
    *((match_type, pattern) for match_type, pattern, _risk in BUILTIN_DLP_PATTERNS),
]

# ``full`` adds personal data on top of the credential shapes. Kept short and
# anchored on purpose: PII regexes false-positive easily, and this mode is for
# deployments that would rather over-redact their own audit trail than store a
# customer identifier.
_LOG_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("pii_email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("pii_cn_mobile", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("pii_cn_id", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
]


def log_redact_mode() -> str:
    """How much of a payload is masked before it is persisted.

    - ``secrets`` (default): mask credential shapes -- ``key=value`` and
      ``Bearer`` as before, plus bare AWS / GitHub / OpenAI-style / Slack /
      Google keys, JWTs and private keys.
    - ``full``: ``secrets`` plus email, mainland-China mobile and ID numbers.
    - ``off``: store the payload as received. For a deployment whose audit trail
      is read as forensic evidence; it makes every stored prompt a potential
      secret at rest, so it has to be opted into explicitly.

    An unrecognized value falls back to ``secrets``, never to ``off``: a typo
    must not silently turn redaction off.
    """
    import os

    mode = os.getenv("SHADOW_AGENT_LOG_REDACT", "secrets").strip().lower()
    if mode not in LOG_REDACT_MODES:
        logger.warning("Invalid SHADOW_AGENT_LOG_REDACT=%r, falling back to secrets", mode)
        return "secrets"
    return mode


def redact_for_log(value: str, max_chars: int = 4000) -> str:
    """Mask a payload on its way into the audit trail and cap its length.

    ``off`` still truncates: retention governs how long a row lives, this only
    governs how much of the payload is kept. Redaction is best-effort by nature
    -- it lowers the blast radius of a leaked database, it does not make storing
    prompts safe.
    """
    if not value:
        return value

    mode = log_redact_mode()
    redacted = value
    if mode != "off":
        patterns = _LOG_SECRET_PATTERNS + (_LOG_PII_PATTERNS if mode == "full" else [])
        for match_type, pattern in patterns:
            redacted = pattern.sub(f"[REDACTED:{match_type}]", redacted)
        # Then the narrow ``key=value`` / ``Bearer`` forms the shape patterns
        # miss: short values, and key names that are not credentials at all
        # (``password: hunter2``). Substituting can grow the string slightly,
        # which is why this runs before the final truncation.
        redacted = redact_sensitive_assignments(redacted)

    if len(redacted) > max_chars:
        return redacted[:max_chars] + "...[truncated]"
    return redacted


# --- logging ---------------------------------------------------------------


def _log_dlp_event(
    *,
    request_id: str,
    action_taken: str,
    outcome: ScanOutcome,
    excerpt: str,
    details: dict[str, Any],
    severity_threshold: str = "medium",
    org_id: int | None = None,
) -> None:
    """Persist intercept/alert records and fan out events for a DLP action."""
    scopes = (
        details.get("dlp_scopes")
        or details.get("stream_scope")
        or details.get("dlp_scope")
        or "unknown"
    )
    record_dlp_scan(scopes=scopes, action=action_taken, matches=len(outcome.matches))
    db = SessionLocal()
    try:
        risk = outcome.max_risk()
        severity = "high" if risk >= 0.9 else ("medium" if risk >= 0.75 else "low")
        log_details = {
            "request_id": request_id,
            "layer": _DLP_LAYER,
            "reason": "sensitive_data_detected_in_model_output",
            "risk_score": risk,
            "matched_rules": [match.rule_name for match in outcome.matches][:10],
            "category": "secret_exfiltration",
            "categories": ["secret_exfiltration"],
            "evidence": [redact_for_log(excerpt, max_chars=200)],
            "recommended_action": "block" if outcome.should_block else "redact",
            "action_taken": action_taken,
            "dlp_summary": outcome.summary(),
            **details,
        }
        db.add(
            InterceptLog(
                org_id=org_id,
                request_id=request_id,
                threat_type=_DLP_THREAT_TYPE,
                action_taken=action_taken,
                original_prompt=redact_for_log(excerpt),
                details=json.dumps(sanitize_json(log_details), ensure_ascii=False),
            )
        )
        if severity >= severity_threshold:
            db.add(
                AlertEvent(
                    org_id=org_id,
                    request_id=request_id,
                    severity=severity,
                    channel="console",
                    title=f"Sensitive data {'blocked' if action_taken == 'Blocked' else 'detected'} in model output",
                    summary=f"{len(outcome.matches)} sensitive pattern match(es): "
                    + ", ".join(sorted({match.match_type for match in outcome.matches})),
                    status="triggered",
                    details=json.dumps(sanitize_json(log_details), ensure_ascii=False),
                )
            )
        db.commit()
    finally:
        db.close()

    event = {
        "type": "intercept",
        "org_id": org_id,
        "request_id": request_id,
        "layer": _DLP_LAYER,
        "threat_type": _DLP_THREAT_TYPE,
        "category": "secret_exfiltration",
        "risk_score": outcome.max_risk(),
        "reason": "sensitive_data_detected_in_model_output",
        "recommended_action": "block" if outcome.should_block else "redact",
        "action_taken": action_taken,
    }
    publish_event(event)
    enqueue_alert(event)


def blocked_decision(outcome: ScanOutcome) -> AuditDecision:
    return AuditDecision(
        allowed=False,
        reason="sensitive_data_detected_in_model_output",
        risk_score=max(0.85, outcome.max_risk()),
        matched_rules=[match.rule_name for match in outcome.matches][:10],
        category="secret_exfiltration",
        categories=["secret_exfiltration"],
        evidence=[],
        recommended_action="block",
    )


# --- non-streaming ----------------------------------------------------------

_SCAN_SCOPE_CONTENT = "content"


def _iter_message_segments(
    message: dict[str, Any],
) -> list[tuple[str, str, Callable[[str], None]]]:
    """Model-output text segments inside one response message.

    Returns ``(scope, text, write_back)`` triples. Tool call arguments are
    model output just like ``content`` is — leaving them out of the scan let a
    secret be smuggled out through a function call's arguments untouched.
    """
    segments: list[tuple[str, str, Callable[[str], None]]] = []

    content = message.get("content")
    if isinstance(content, str) and content:
        segments.append(
            (
                _SCAN_SCOPE_CONTENT,
                content,
                lambda value: message.__setitem__("content", value),
            )
        )

    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for index, call in enumerate(tool_calls):
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            if not isinstance(function, dict):
                continue
            arguments = function.get("arguments")
            if isinstance(arguments, str) and arguments:
                segments.append(
                    (
                        f"tool_calls[{index}].function.arguments",
                        arguments,
                        lambda value, target=function: target.__setitem__(
                            "arguments", value
                        ),
                    )
                )

    return segments


def apply_response_dlp(
    data: dict[str, Any],
    *,
    request_id: str,
    db: Session,
    details: dict[str, Any] | None = None,
    org_id: int | None = None,
) -> dict[str, Any]:
    """Scan/redact/block a non-streaming chat completion payload in place."""
    mode = response_dlp_mode()
    if mode == "off":
        return data

    rules = enabled_rules(db, target="response", org_id=org_id)
    outcome_total = ScanOutcome()
    modified = False
    matched_scopes: list[str] = []
    first_excerpt = ""

    for choice in data.get("choices") or []:
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue

        for scope, text, write_back in _iter_message_segments(message):
            outcome = scan_text(text, rules)
            if not outcome.matches:
                continue

            if not first_excerpt:
                first_excerpt = text[:500]
            if scope not in matched_scopes:
                matched_scopes.append(scope)

            block_forced = mode == "block" or outcome.should_block
            if block_forced:
                _log_dlp_event(
                    request_id=request_id,
                    action_taken="Blocked",
                    outcome=outcome,
                    excerpt=text[:500],
                    details={**(details or {}), "dlp_scope": scope},
                    org_id=org_id,
                )
                from fastapi import HTTPException

                decision = blocked_decision(outcome)
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "shadow_agent_intercepted",
                        "request_id": request_id,
                        "layer": _DLP_LAYER,
                        "reason": decision.reason,
                        "risk_score": decision.risk_score,
                        "matched_rules": decision.matched_rules,
                        "category": decision.category,
                        "categories": decision.categories,
                        "evidence": decision.evidence,
                        "recommended_action": decision.recommended_action,
                        "dlp_scope": scope,
                    },
                )

            if mode == "redact" and outcome.has_redactions:
                redacted = _redact_content(text, rules, outcome)
                if redacted != text:
                    write_back(redacted)
                    modified = True

            outcome_total.matches.extend(outcome.matches)

    if outcome_total.matches:
        if mode == "redact" and modified:
            action_taken = "Redacted"
        else:
            action_taken = "Monitored"
        _log_dlp_event(
            request_id=request_id,
            action_taken=action_taken,
            outcome=outcome_total,
            excerpt=first_excerpt,
            details={**(details or {}), "dlp_scopes": matched_scopes},
            org_id=org_id,
        )

    shadow_agent = data.get("shadow_agent")
    if isinstance(shadow_agent, dict):
        shadow_agent["response_dlp"] = {
            "mode": mode,
            "matches": outcome_total.summary(),
        }
    elif outcome_total.matches:
        data["shadow_agent"] = {
            "response_dlp": {"mode": mode, "matches": outcome_total.summary()}
        }

    return data


def _redact_content(content: str, rules: list[CustomRule], outcome: ScanOutcome) -> str:
    """Apply span-based redaction for builtin + custom matches (no overlaps)."""
    return apply_redactions(content, outcome)


# --- streaming ---------------------------------------------------------------

_HOLD_BACK = 256
_PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


class StreamingDlpScanner:
    """Incremental scanner for streamed assistant content.

    ``feed`` returns the text safe to emit now (with redactions applied);
    ``finish`` flushes the withheld tail. In block mode a match yields a
    ``blocked`` result the caller must translate into an SSE error frame.
    """

    def __init__(
        self,
        *,
        mode: str,
        rules: list[CustomRule],
        request_id: str,
        details: dict[str, Any] | None = None,
        org_id: int | None = None,
    ) -> None:
        self.mode = mode
        self.rules = rules
        self.request_id = request_id
        self.details = details or {}
        self.org_id = org_id
        self.buffer = ""
        self.suppressed = False
        self.suppression_emitted = False
        self.matches: list[DlpMatch] = []
        self.blocked = False

    def feed(self, text: str) -> str:
        if self.blocked or not text:
            return ""
        if self.mode == "off":
            return text

        self.buffer += text

        if self.mode == "block":
            outcome = scan_text(self.buffer, self.rules)
            if outcome.matches:
                self.blocked = True
                self._handle_block(outcome)
                return ""
            return self._flush_safe(final=False)

        if self.mode == "monitor":
            # Record matches but never modify the stream.
            self._record_matches(scan_text(self.buffer, self.rules))
            emitted = self.buffer
            self.buffer = ""
            return emitted

        # redact mode
        if self.suppressed:
            return self._drain_suppressed()

        outcome = scan_text(self.buffer, self.rules)
        self._record_matches(outcome)

        # A custom response rule with action=block must terminate the stream
        # even when the global mode is redact.
        if outcome.should_block:
            self.blocked = True
            self._handle_block(outcome)
            return ""

        # Private-key suppression: once a BEGIN marker appears, swallow
        # everything until the matching END marker (or stream end).
        begin = _PRIVATE_KEY_BEGIN.search(self.buffer)
        if begin:
            head = self.buffer[: begin.start()]
            emitted = self._emit_with_redactions(head)
            self.suppressed = True
            self.suppression_emitted = False
            self.buffer = self.buffer[begin.start() :]
            return emitted + self._drain_suppressed()

        return self._flush_safe(final=False)

    def finish(self) -> str:
        if self.blocked:
            return ""
        if self.mode == "off":
            remainder = self.buffer
            self.buffer = ""
            return remainder
        if self.mode == "monitor":
            self._record_matches(scan_text(self.buffer, self.rules))
            remainder = self.buffer
            self.buffer = ""
            return remainder
        if self.suppressed:
            # Unterminated private key block: stay suppressed to the end.
            self.buffer = ""
            return ""
        outcome = scan_text(self.buffer, self.rules)
        self._record_matches(outcome)
        emitted = self._emit_with_redactions(self.buffer)
        self.buffer = ""
        return emitted

    # internals -------------------------------------------------------------

    def _flush_safe(self, *, final: bool) -> str:
        """Emit the safe prefix, holding back near boundary-crossing matches."""
        if final:
            limit = len(self.buffer)
        else:
            limit = max(0, len(self.buffer) - _HOLD_BACK)
        if limit <= 0:
            return ""

        # A match that starts inside the safe region but ends beyond it must
        # not be partially emitted: hold back from its start instead.
        full_outcome = scan_text(self.buffer, self.rules)
        for match in full_outcome.matches:
            start, end = match.span
            if start < limit < end:
                limit = start
        if limit <= 0:
            return ""

        safe_text = self.buffer[:limit]
        emitted = self._emit_with_redactions(safe_text)
        self.buffer = self.buffer[limit:]
        return emitted

    def _emit_with_redactions(self, text: str) -> str:
        if self.mode in {"monitor", "off"}:
            return text
        outcome = scan_text(text, self.rules)
        if not outcome.has_redactions:
            return text
        return _redact_content(text, self.rules, outcome)

    def _drain_suppressed(self) -> str:
        end = _PRIVATE_KEY_END.search(self.buffer)
        if end is None:
            self.buffer = ""
            if not self.suppression_emitted:
                self.suppression_emitted = True
                return f"[REDACTED:private_key]"
            return ""
        rest = self.buffer[end.end() :]
        self.suppressed = False
        self.suppression_emitted = False
        self.buffer = ""
        tail = self.feed(rest)
        marker = "[REDACTED:private_key]" if not self.suppression_emitted else ""
        return marker + tail

    def _record_matches(self, outcome: ScanOutcome) -> None:
        for match in outcome.matches:
            if not any(
                existing.rule_name == match.rule_name for existing in self.matches
            ):
                self.matches.append(match)

    def _handle_block(self, outcome: ScanOutcome) -> None:
        self.matches.extend(outcome.matches)
        _log_dlp_event(
            request_id=self.request_id,
            action_taken="Blocked",
            outcome=outcome,
            excerpt=self.buffer[:500],
            details=self.details,
            org_id=self.org_id,
        )
        self.buffer = ""

    def finalize_logging(self) -> None:
        """Log redact/monitor matches once the stream completes."""
        if self.blocked or not self.matches:
            return
        if self.mode in {"redact", "monitor"}:
            outcome = ScanOutcome(matches=self.matches)
            _log_dlp_event(
                request_id=self.request_id,
                action_taken="Redacted" if self.mode == "redact" else "Monitored",
                outcome=outcome,
                excerpt="[streamed response]",
                details=self.details,
                org_id=self.org_id,
            )

    def blocked_payload(self) -> dict[str, Any]:
        decision = blocked_decision(ScanOutcome(matches=self.matches))
        return {
            "error": "shadow_agent_intercepted",
            "request_id": self.request_id,
            "layer": _DLP_LAYER,
            "reason": decision.reason,
            "risk_score": decision.risk_score,
            "matched_rules": decision.matched_rules,
            "category": decision.category,
            "categories": decision.categories,
            "evidence": decision.evidence,
            "recommended_action": decision.recommended_action,
        }
