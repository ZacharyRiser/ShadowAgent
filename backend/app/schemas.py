"""Pydantic request/response schemas for every gateway endpoint."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_MESSAGE_CONTENT_LENGTH = 12_000
MAX_TOOL_ARGUMENTS_LENGTH = 20_000
MAX_TOOL_DEFINITIONS = 64
MAX_SERIALIZED_TOOLS_LENGTH = 60_000


class ToolFunctionDefinition(BaseModel):
    """The ``function`` block of one entry in the request's ``tools`` list."""

    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4000)
    parameters: dict[str, Any] | None = None


class ToolDefinition(BaseModel):
    """An OpenAI tool declaration: ``{"type": "function", "function": {...}}``."""

    type: Literal["function"] = "function"
    function: ToolFunctionDefinition


class ToolFunctionCallBody(BaseModel):
    """The ``function`` block of one model-emitted tool call."""

    name: str = Field(min_length=1, max_length=128)
    # OpenAI sends function arguments as a JSON-encoded *string*, streamed in
    # fragments, so this must stay a string rather than a parsed object.
    arguments: str = Field(default="", max_length=MAX_TOOL_ARGUMENTS_LENGTH)


class ToolFunctionCall(BaseModel):
    """One model-emitted tool invocation (``assistant.tool_calls[]``)."""

    id: str | None = Field(default=None, max_length=128)
    type: Literal["function"] = "function"
    function: ToolFunctionCallBody


# Standard OpenAI /chat/completions parameters Shadow Agent forwards verbatim.
#
# An explicit whitelist is used instead of ``extra="allow"`` on purpose: the
# gateway decides what reaches the model, and anything it forwards becomes an
# input the detection layers must be able to inspect. An open passthrough would
# let a caller push unbounded, uninspected keys straight into the upstream body.
FORWARDED_OPENAI_FIELDS: tuple[str, ...] = (
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "seed",
    "n",
    "logprobs",
    "top_logprobs",
    "logit_bias",
    "response_format",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "stream_options",
    "user",
)


def _dump_forwarded_value(value: Any) -> Any:
    """Convert a validated field value back to plain JSON-compatible data."""
    if isinstance(value, BaseModel):
        return value.model_dump(exclude_none=True)
    if isinstance(value, list):
        return [_dump_forwarded_value(item) for item in value]
    return value


def parse_function_arguments(raw: str) -> dict[str, Any] | None:
    """Best-effort decode of a tool call's ``arguments`` JSON string.

    Non-JSON fragments are surfaced under ``raw_arguments`` so the behaviour
    engines still see the text instead of silently skipping it.
    """
    text = (raw or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"raw_arguments": text}
    if isinstance(parsed, dict):
        return parsed
    return {"raw_arguments": text}


class ChatMessage(BaseModel):
    """One conversational turn, covering both plain text and tool exchanges.

    ``content`` is optional because the OpenAI wire format allows an assistant
    turn that carries only ``tool_calls`` (its ``content`` is ``null`` or an
    empty string). Without that, every agent tool loop fails on its second
    round trip.
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = Field(default=None, max_length=MAX_MESSAGE_CONTENT_LENGTH)
    tool_calls: list[ToolFunctionCall] | None = Field(
        default=None,
        max_length=MAX_TOOL_DEFINITIONS,
        description="Tool invocations emitted by the assistant turn.",
    )
    tool_call_id: str | None = Field(
        default=None,
        max_length=128,
        description="Links a role=tool result back to its assistant tool call.",
    )
    name: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _require_usable_payload(self) -> "ChatMessage":
        has_text = bool((self.content or "").strip())
        if self.role in {"system", "user"} and not has_text:
            # The gateway derives its trusted instruction and its primary
            # detection text from these turns; an empty one is not actionable.
            raise ValueError(f"a {self.role} message must carry non-empty content")
        if not has_text and not self.tool_calls and not self.tool_call_id:
            raise ValueError("message must carry content, tool_calls, or tool_call_id")
        return self

    @property
    def text(self) -> str:
        """Message content as a string, for detection paths that need one."""
        return self.content or ""


MAX_SERIALIZED_PARAMETERS_LENGTH = 20_000


def _validate_parameters_size(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reject oversized tool parameter payloads before they reach the engines."""
    if value is None:
        return None
    serialized = json.dumps(value, ensure_ascii=False, default=str)
    if len(serialized) > MAX_SERIALIZED_PARAMETERS_LENGTH:
        raise ValueError(
            "parameters payload is too large (max 20000 characters when serialized)"
        )
    return value


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="shadow-agent-simulated", max_length=120)
    messages: list[ChatMessage] = Field(min_length=1, max_length=100)
    external_context: str | None = Field(
        default=None,
        max_length=20000,
        description="Untrusted retrieval/API/plugin result to be purified before LLM use.",
    )
    tool_name: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Optional downstream tool name requested by the agent runtime. "
            "Legacy companion to the OpenAI-native tool_calls form."
        ),
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Optional downstream tool parameters for permission checks.",
    )
    stream: bool = False

    # --- standard OpenAI passthrough parameters -----------------------------
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    max_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    max_completion_tokens: int | None = Field(default=None, ge=1, le=1_000_000)
    stop: str | list[str] | None = None
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: int | None = None
    n: int | None = Field(default=None, ge=1, le=16)
    logprobs: bool | None = None
    top_logprobs: int | None = Field(default=None, ge=0, le=20)
    logit_bias: dict[str, int] | None = None
    response_format: dict[str, Any] | None = None
    tools: list[ToolDefinition] | None = Field(
        default=None, max_length=MAX_TOOL_DEFINITIONS
    )
    tool_choice: str | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    stream_options: dict[str, Any] | None = None
    user: str | None = Field(default=None, max_length=256)

    @field_validator("parameters")
    @classmethod
    def _check_parameters_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_parameters_size(value)

    @field_validator("stop")
    @classmethod
    def _check_stop_length(cls, value: str | list[str] | None) -> str | list[str] | None:
        # Only the documented OpenAI limit is enforced. Whitespace-only
        # sequences such as "\n\n" are legal and extremely common, so they must
        # not be rejected here.
        if isinstance(value, list) and len(value) > 4:
            raise ValueError("stop accepts at most 4 sequences")
        return value

    @field_validator("tools")
    @classmethod
    def _check_tools_size(
        cls, value: list[ToolDefinition] | None
    ) -> list[ToolDefinition] | None:
        if value is None:
            return None
        serialized = json.dumps(
            [item.model_dump(exclude_none=True) for item in value],
            ensure_ascii=False,
            default=str,
        )
        if len(serialized) > MAX_SERIALIZED_TOOLS_LENGTH:
            raise ValueError(
                "tools payload is too large "
                f"(max {MAX_SERIALIZED_TOOLS_LENGTH} characters when serialized)"
            )
        return value

    def upstream_passthrough(self) -> dict[str, Any]:
        """Only the explicitly-set standard parameters, ready for the upstream body."""
        forwarded: dict[str, Any] = {}
        for name in FORWARDED_OPENAI_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            forwarded[name] = _dump_forwarded_value(value)
        return forwarded

    def tool_invocations(self) -> list[tuple[str, dict[str, Any] | None]]:
        """Every tool the caller wants run, as ``(name, parameters)`` pairs.

        Real agent traffic expresses this through the OpenAI-native
        ``messages[].tool_calls``; the legacy ``tool_name``/``parameters``
        fields stay supported as a fallback for the gateway's own API.
        """
        invocations: list[tuple[str, dict[str, Any] | None]] = []
        for message in self.messages:
            for call in message.tool_calls or []:
                invocations.append(
                    (call.function.name, parse_function_arguments(call.function.arguments))
                )
        if not invocations and self.tool_name:
            invocations.append((self.tool_name, self.parameters))
        return invocations


class AnalyzeRequest(BaseModel):
    prompt: str = Field(default="", max_length=12000)
    external_context: str | None = Field(default=None, max_length=20000)
    tool_name: str | None = Field(default=None, max_length=128)
    parameters: dict[str, Any] | None = Field(default=None)

    @field_validator("parameters")
    @classmethod
    def _check_parameters_size(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_parameters_size(value)


class InterceptLogResponse(BaseModel):
    id: int
    request_id: str = ""
    timestamp: str
    threat_type: str
    action_taken: str
    original_prompt: str
    details: dict[str, Any]


class SecurityPolicyResponse(BaseModel):
    id: int
    name: str
    blacklist_keyword: str
    description: str
    severity: str
    scope: str
    enabled: bool
    system_managed: bool


class SecurityPolicyUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    blacklist_keyword: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="medium", max_length=32)
    scope: str = Field(default="Prompt", max_length=64)
    enabled: bool = True


class ToolPolicyResponse(BaseModel):
    id: int
    tool_name: str
    description: str
    allowed: bool
    requires_admin_approval: bool
    system_managed: bool


class ToolPolicyUpsert(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    allowed: bool = False
    requires_admin_approval: bool = False


class ApprovalRequestResponse(BaseModel):
    id: int
    request_id: str
    status: str
    threat_type: str
    reason: str
    recommended_action: str
    original_prompt: str
    tool_name: str
    categories: list[str]
    evidence: list[str]
    details: dict[str, Any]
    reviewed_by: str
    review_comment: str
    created_at: str
    updated_at: str


class ApprovalReviewRequest(BaseModel):
    status: Literal["approved", "rejected"]
    review_comment: str = Field(default="", max_length=4000)


class AlertEventResponse(BaseModel):
    id: int
    request_id: str
    severity: str
    channel: str
    title: str
    summary: str
    status: str
    details: dict[str, Any]
    created_at: str


class ReplayRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=96)


class CustomRuleUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)
    rule_type: Literal["regex", "keyword"]
    pattern: str = Field(min_length=1, max_length=512)
    target: Literal["prompt", "response", "any"] = "prompt"
    action: Literal["block", "redact", "alert"] = "block"
    risk_score: float = Field(default=0.8, ge=0.0, le=1.0)
    enabled: bool = True


class CustomRuleTestRequest(BaseModel):
    """Test a rule (existing by id, or an ad-hoc draft) against sample text."""

    sample_text: str = Field(min_length=0, max_length=20000)
    rule_id: int | None = None
    draft: CustomRuleUpsert | None = None


class CustomRuleImportRequest(BaseModel):
    rules: list[CustomRuleUpsert] = Field(min_length=1, max_length=200)
    mode: Literal["merge", "replace"] = "merge"


class CustomRuleResponse(BaseModel):
    id: int
    name: str
    description: str
    rule_type: str
    pattern: str
    target: str
    action: str
    risk_score: float
    enabled: bool
    created_at: str
    updated_at: str


class ReplayRunResponse(BaseModel):
    id: int
    source_request_id: str
    replay_request_id: str
    triggered_by: str
    verdict: str
    risk_score: str
    category: str
    details: dict[str, Any]
    created_at: str


class AuthRegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=6, max_length=256)


class AuthLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class AuthUserResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: str


class AuthOrgResponse(BaseModel):
    """Active organization context embedded in a console session."""

    id: int
    slug: str
    name: str
    role: str
    is_default: bool = False


class AuthSessionResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: int
    user: AuthUserResponse
    org: AuthOrgResponse | None = None


class SwitchOrgRequest(BaseModel):
    org_id: int


class OrgCreateRequest(BaseModel):
    slug: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,62}[a-zA-Z0-9]$")
    name: str = Field(min_length=1, max_length=128)


class OrgUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class OrgMemberAddRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    role: Literal["owner", "admin", "member"] = "member"


class OrgMemberUpdateRequest(BaseModel):
    role: Literal["owner", "admin", "member"]


class SsoUpsertRequest(BaseModel):
    """Per-organization OIDC connection (Authorization Code + PKCE)."""

    provider_name: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=255)
    # Empty string keeps the stored secret (update flows never echo it back).
    client_secret: str = Field(default="", max_length=512)
    issuer_url: str = Field(min_length=1, max_length=512)
    scopes: str = Field(default="openid email profile", max_length=255)
    jit_enabled: bool = True
    default_role: str = Field(default="client", min_length=1, max_length=32)
    enabled: bool = True


class ConsoleBootstrapStatusResponse(BaseModel):
    initialized: bool
    bootstrap_required: bool
    bootstrap_token_configured: bool
    demo_override_enabled: bool
    open_registration_enabled: bool
    invite_token_configured: bool
    recommended_role: str


class ManagedApiKeyResponse(BaseModel):
    id: int
    name: str
    role: str
    description: str
    key_prefix: str
    masked_key: str
    created_by: str
    is_active: bool
    expires_at: str | None
    last_used_at: str | None
    last_used_by: str
    created_at: str
    updated_at: str


class ManagedApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: str = Field(default="client", min_length=1, max_length=32)
    description: str = Field(default="", max_length=4000)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ManagedApiKeyCreateResponse(BaseModel):
    item: ManagedApiKeyResponse
    api_key: str


class ManagedApiKeyRotateRequest(BaseModel):
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    clear_expiration: bool = False
