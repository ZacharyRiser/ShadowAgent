"""HTTP client implementations for the Shadow Agent gateway.

The gateway is OpenAI-compatible (``Authorization: Bearer <api_key>`` +
``/api/v1/chat/completions``), so the OpenAI SDK also works directly — this
client adds first-class handling of security decisions (403 intercepts),
risk analysis, and model listing.

Usage::

    from shadowagent import ShadowAgentClient

    client = ShadowAgentClient("http://127.0.0.1:8000", api_key="sak_...")
    completion = client.chat([{"role": "user", "content": "hi"}])
"""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_TIMEOUT_SECONDS = 60.0


class ShadowAgentError(Exception):
    """Base error for Shadow Agent client failures."""


class ShadowAgentBlockedError(ShadowAgentError):
    """Raised when the gateway blocks a request (HTTP 403).

    ``decision`` carries the full security decision payload from the
    gateway: request_id, layer, reason, risk_score, category, categories,
    matched_rules, evidence, recommended_action.
    """

    def __init__(self, message: str, decision: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.decision: dict[str, Any] = decision or {}

    @property
    def request_id(self) -> str:
        return str(self.decision.get("request_id", ""))

    @property
    def risk_score(self) -> float:
        return float(self.decision.get("risk_score", 0.0))

    @property
    def reason(self) -> str:
        return str(self.decision.get("reason", ""))


def _handle_response(response: httpx.Response) -> Any:
    if response.status_code == 403:
        try:
            detail = response.json().get("detail") or {}
        except ValueError:
            detail = {}
        if not isinstance(detail, dict):
            detail = {"reason": str(detail)}
        message = detail.get("reason") or "Request blocked by Shadow Agent security policy."
        raise ShadowAgentBlockedError(message, decision=detail)
    if response.status_code == 401:
        raise ShadowAgentError(
            f"Authentication failed (HTTP 401). Check your API key. Body: {response.text[:200]}"
        )
    response.raise_for_status()
    return response.json()


class _BaseClient:
    """Shared request building (auth header, payloads, URLs)."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("base_url is required (e.g. http://127.0.0.1:8000)")
        if not api_key:
            raise ValueError("api_key is required (managed key or shared client key)")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._http = http_client

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"}

    def _chat_url(self) -> str:
        return f"{self._base_url}/api/v1/chat/completions"

    def _analyze_url(self) -> str:
        return f"{self._base_url}/api/v1/analyze"

    def _models_url(self) -> str:
        return f"{self._base_url}/api/v1/models"

    def _chat_payload(
        self,
        messages: list[dict[str, Any]],
        model: str | None,
        stream: bool,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"messages": messages, **params}
        if model is not None:
            payload["model"] = model
        if stream:
            payload["stream"] = True
        return payload

    def _analyze_payload(
        self,
        prompt: str,
        external_context: str,
        tool_name: str,
        parameters: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "prompt": prompt,
            "external_context": external_context,
            "tool_name": tool_name,
            "parameters": parameters or {},
        }


class ShadowAgentClient(_BaseClient):
    """Synchronous Shadow Agent gateway client.

    Args:
        base_url: Gateway origin, e.g. ``http://127.0.0.1:8000``.
        api_key: Managed API key (``sak_...``) or shared client key.
        timeout: Per-request timeout in seconds.
        http_client: Optional pre-configured ``httpx.Client`` (tests/reuse).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(base_url, api_key, timeout=timeout, http_client=http_client)
        self._owns_client = http_client is None
        self._sync_client: httpx.Client = http_client or httpx.Client(timeout=timeout)

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        stream: bool = False,
        **params: Any,
    ) -> Any:
        """Send a chat completion through the security gateway.

        Returns the completion dict, or the raw ``httpx.Response`` when
        ``stream=True`` so callers can iterate SSE frames.
        Raises ``ShadowAgentBlockedError`` when the request is intercepted.
        """
        response = self._sync_client.post(
            self._chat_url(),
            json=self._chat_payload(messages, model, stream, params),
            headers=self._headers(),
        )
        if stream:
            response.raise_for_status()
            return response
        return _handle_response(response)

    def analyze(
        self,
        prompt: str,
        *,
        external_context: str = "",
        tool_name: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the detection engines without calling a model; returns the decision."""
        response = self._sync_client.post(
            self._analyze_url(),
            json=self._analyze_payload(prompt, external_context, tool_name, parameters),
            headers=self._headers(),
        )
        return _handle_response(response)

    def models(self) -> list[str]:
        """List available model ids (OpenAI-compatible)."""
        response = self._sync_client.get(self._models_url(), headers=self._headers())
        body = _handle_response(response)
        return [item["id"] for item in body.get("data", [])]

    def close(self) -> None:
        if self._owns_client:
            self._sync_client.close()

    def __enter__(self) -> "ShadowAgentClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class AsyncShadowAgentClient(_BaseClient):
    """Async variant of :class:`ShadowAgentClient` (same API, awaitables)."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(base_url, api_key, timeout=timeout, http_client=http_client)
        self._owns_client = http_client is None
        self._async_client: httpx.AsyncClient = http_client or httpx.AsyncClient(timeout=timeout)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        model: str | None = None,
        stream: bool = False,
        **params: Any,
    ) -> Any:
        response = await self._async_client.post(
            self._chat_url(),
            json=self._chat_payload(messages, model, stream, params),
            headers=self._headers(),
        )
        if stream:
            response.raise_for_status()
            return response
        return _handle_response(response)

    async def analyze(
        self,
        prompt: str,
        *,
        external_context: str = "",
        tool_name: str = "",
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self._async_client.post(
            self._analyze_url(),
            json=self._analyze_payload(prompt, external_context, tool_name, parameters),
            headers=self._headers(),
        )
        return _handle_response(response)

    async def models(self) -> list[str]:
        response = await self._async_client.get(self._models_url(), headers=self._headers())
        body = _handle_response(response)
        return [item["id"] for item in body.get("data", [])]

    async def close(self) -> None:
        if self._owns_client:
            await self._async_client.aclose()

    async def __aenter__(self) -> "AsyncShadowAgentClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()
