"""Shadow Agent Python SDK — thin client for the security gateway.

Synchronous and asynchronous clients with OpenAI-style chat completions,
risk analysis, and model listing. Blocked requests raise
``ShadowAgentBlockedError`` carrying the full security decision.
"""

from shadowagent.client import (
    AsyncShadowAgentClient,
    ShadowAgentBlockedError,
    ShadowAgentClient,
    ShadowAgentError,
)

__all__ = [
    "AsyncShadowAgentClient",
    "ShadowAgentBlockedError",
    "ShadowAgentClient",
    "ShadowAgentError",
]
__version__ = "0.4.0"
