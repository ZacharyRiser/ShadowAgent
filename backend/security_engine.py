"""Core purification engine skeleton for Shadow Agent.

The functions in this module are intentionally lightweight for Task 1. Later
iterations can replace the heuristic checks with local embedding models,
DeepSeek-based audit calls, policy stores, and per-tool permission graphs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


INJECTION_PATTERNS = [
    re.compile(r"\bignore (all )?(previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"\bdisregard (all )?(previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"\b忽略(以上|前述|之前|所有).{0,12}(指令|规则|要求)\b", re.IGNORECASE),
    re.compile(r"\b越权\b|\b泄露\b|\b系统提示词\b|\bsystem prompt\b", re.IGNORECASE),
]

BLOCKED_TOOLS = {
    "shell.exec",
    "filesystem.delete",
    "credential.dump",
}


@dataclass(slots=True)
class AuditDecision:
    allowed: bool
    reason: str = "allowed"
    risk_score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)


def separate_instruction_and_data(prompt: str, external_context: str | None) -> dict[str, str]:
    """Separate trusted user intent from untrusted external data.

    Future logic:
    - Preserve the user's direct instruction as the only trusted command source.
    - Wrap retrieval/API/tool output as inert data with provenance metadata.
    - Tag spans by origin, confidence, and whether the model may treat them as
      executable instructions.
    - Feed the separated representation into the policy engine instead of
      concatenating prompt and context directly.
    """

    return {
        "trusted_instruction": prompt.strip(),
        "untrusted_data": (external_context or "").strip(),
    }


def semantic_intent_check(text: str) -> AuditDecision:
    """Check whether text attempts to override policy or steer tool use.

    Future logic:
    - Replace keyword heuristics with semantic similarity against malicious
      intent exemplars and a compact local moderation model.
    - Score indirect prompt injection, credential exfiltration, command
      execution requests, role-play bypasses, and policy override attempts.
    - Return calibrated risk scores for dynamic allow/review/block decisions.
    """

    if not text:
        return AuditDecision(allowed=True)

    matched_rules = [
        pattern.pattern for pattern in INJECTION_PATTERNS if pattern.search(text)
    ]
    if matched_rules:
        return AuditDecision(
            allowed=False,
            reason="prompt_injection_detected",
            risk_score=0.92,
            matched_rules=matched_rules,
        )

    return AuditDecision(allowed=True, risk_score=0.05)


def permission_control(tool_name: str | None, parameters: dict[str, Any] | None) -> AuditDecision:
    """Validate whether a tool call is permitted in the current runtime policy.

    Future logic:
    - Resolve user/session/tool/plugin identity and load its least-privilege
      policy.
    - Check requested arguments against allowlists, deny rules, rate limits,
      data sensitivity labels, and runtime sandbox level.
    - Emit structured authorization evidence for dashboard review.
    """

    if not tool_name:
        return AuditDecision(allowed=True)

    normalized_tool_name = tool_name.strip().lower()
    if normalized_tool_name in BLOCKED_TOOLS:
        return AuditDecision(
            allowed=False,
            reason="tool_not_permitted",
            risk_score=0.87,
            matched_rules=[normalized_tool_name],
        )

    if parameters and parameters.get("requires_admin") is True:
        return AuditDecision(
            allowed=False,
            reason="admin_permission_required",
            risk_score=0.75,
            matched_rules=["requires_admin"],
        )

    return AuditDecision(allowed=True, risk_score=0.1)
