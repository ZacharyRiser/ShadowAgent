"""Is the gateway a drop-in OpenAI-compatible proxy? Measure it, don't assume it.

The README sells the gateway as "change ``base_url`` and you are done". That
claim was false for most of the OpenAI wire surface, and the failure mode was
silent: clients kept working while six standard parameters quietly stopped
having any effect. This tool pins the five behaviours that were broken so they
cannot regress unnoticed. Each one is checked against the real code paths — the
upstream transport is mocked and a throwaway database stands in for the real
one, so the tool cannot drift from the implementation and writes nothing.

The five checks, and what each protects:

1. Request field fidelity — ``ChatCompletionRequest`` declares no
   ``model_config``, so Pydantic v2 defaults to ``extra="ignore"`` and silently
   drops undeclared standard parameters.
2. Upstream body fidelity — ``_forward_to_upstream`` rebuilds the upstream body
   from scratch, so a parameter must be explicitly carried across or it never
   leaves the gateway.
3. Multi-turn tool conversations — ``ChatMessage.content`` used to be
   ``str`` with ``min_length=1``, rejecting the legal assistant turn whose
   ``content`` is ``null`` and carrying only ``tool_calls``. That broke function
   calling on the second round trip with a 422.
4. Non-streaming response DLP — the scan walked ``choices[].message.content``
   only, so a secret written into ``tool_calls[].function.arguments`` was
   forwarded untouched.
5. Streaming response DLP — likewise, the SSE path only fed ``delta.content``
   to the scanner.

Read-only by construction: an in-memory SQLite database stands in for the real
one, the upstream transport is mocked, and DLP event logging is stubbed so no
intercept row is written. No network call is made.

Usage (from ``backend/``):
    python tools/check_openai_compat.py
    python tools/check_openai_compat.py --verbose

Exit code 0 means the gateway is fully drop-in compatible; 1 means at least one
gap is still present.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import models  # noqa: E402,F401  (registers tables on Base.metadata)
from app.dlp import apply_response_dlp, scan_text  # noqa: E402
from app.schemas import ChatCompletionRequest  # noqa: E402
from app.upstream import _forward_to_upstream, _stream_upstream_response  # noqa: E402
from database import Base  # noqa: E402

# Fields any OpenAI-compatible client is entitled to send on
# /chat/completions. Value is Chinese for the human-readable report.
STANDARD_REQUEST_FIELDS: dict[str, Any] = {
    "temperature": 0.2,
    "max_tokens": 256,
    "top_p": 0.9,
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Look up the weather for a city",
                "parameters": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"],
                },
            },
        }
    ],
    "tool_choice": "auto",
    "response_format": {"type": "json_object"},
}

# A value the builtin DLP patterns are expected to catch. Deliberately shaped
# like an OpenAI key so BUILTIN_DLP_PATTERNS matches it.
FAKE_SECRET = "sk-proj-EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1234"
SECRET_IN_TOOL_ARGUMENTS = json.dumps(
    {"path": "/tmp/leak.txt", "content": f"api_key={FAKE_SECRET}"},
    ensure_ascii=False,
)

ASSISTANT_TOOL_TURN: dict[str, Any] = {
    "role": "assistant",
    "content": "",
    "tool_calls": [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "get_weather", "arguments": '{"city":"Nanjing"}'},
        }
    ],
}
TOOL_RESULT_TURN: dict[str, Any] = {
    "role": "tool",
    "tool_call_id": "call_1",
    "content": '{"temp": 28}',
}


class _FakeJsonResponse:
    """Minimal stand-in for a non-streaming httpx.Response."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.is_error = False
        self.status_code = 200
        self.text = json.dumps(payload)

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeStreamResponse:
    """Minimal stand-in for a streaming httpx.Response."""

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames
        self.is_error = False
        self.status_code = 200
        self.headers = {"content-type": "text/event-stream"}

    async def aiter_raw(self):
        for frame in self._frames:
            yield frame

    async def aread(self) -> bytes:
        return b"".join(self._frames)

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """Records what the gateway would actually put on the wire."""

    def __init__(self, stream_frames: list[bytes] | None = None) -> None:
        self.captured_json: dict[str, Any] | None = None
        self.captured_stream_json: dict[str, Any] | None = None
        self.captured_headers: dict[str, str] | None = None
        self._stream_frames = stream_frames or []

    async def post(self, url, *, headers=None, json=None, timeout=None):  # noqa: A002
        self.captured_json = json
        self.captured_headers = headers
        return _FakeJsonResponse({"choices": [{"message": {"content": "ok"}}]})

    def build_request(self, method, url, *, headers=None, json=None):  # noqa: A002
        self.captured_stream_json = json
        self.captured_headers = headers
        return {"method": method, "url": url, "headers": headers, "json": json}

    async def send(self, request, *, stream=False):
        return _FakeStreamResponse(self._stream_frames)


def _memory_session():
    """A throwaway database so nothing here can touch shadow_agent.db."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


@contextlib.contextmanager
def _no_side_effects():
    """Silence DLP event logging.

    ``_log_dlp_event`` opens its own ``SessionLocal()`` bound to the real
    database, so it would write intercept rows once the DLP checks start
    matching. The tool must stay strictly read-only.
    """
    with patch("app.dlp._log_dlp_event", lambda **kwargs: None):
        yield


def _sse_frame(delta: dict[str, Any]) -> bytes:
    event = {"id": "chatcmpl-x", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta}]}
    return ("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode("utf-8")


def check_request_field_fidelity() -> tuple[bool, list[str]]:
    raw = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Look up the weather in Nanjing"}],
        **STANDARD_REQUEST_FIELDS,
    }
    parsed = ChatCompletionRequest(**raw).model_dump()
    dropped = sorted(set(raw) - set(parsed))
    detail = [
        f"客户端发送字段 {len(raw)} 个，schema 保留 {len(parsed)} 个",
        f"被静默丢弃（dropped）: {dropped if dropped else '无'}",
    ]
    return not dropped, detail


async def _capture_upstream_body() -> dict[str, Any]:
    os.environ.setdefault("SHADOW_AGENT_UPSTREAM_BASE_URL", "http://127.0.0.1:9/v1")
    payload = ChatCompletionRequest(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Look up the weather in Nanjing"}],
        **STANDARD_REQUEST_FIELDS,
    )
    client = _FakeClient()
    with patch("app.upstream._get_upstream_client", return_value=client):
        await _forward_to_upstream(
            payload,
            request_id="compat-check",
            separated={"trusted_instruction": "Look up the weather in Nanjing", "untrusted_data": ""},
        )
    return client.captured_json or {}


def check_upstream_body_fidelity(captured: dict[str, Any]) -> tuple[bool, list[str]]:
    expected = set(STANDARD_REQUEST_FIELDS) | {"model", "messages"}
    missing = sorted(expected - set(captured))
    detail = [
        f"实际上行字段（upstream body keys）: {sorted(captured)}",
        f"未能抵达上游的标准字段: {missing if missing else '无'}",
    ]
    return not missing, detail


def check_multi_turn_tool_conversation() -> tuple[bool, list[str]]:
    raw = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Look up the weather in Nanjing"},
            ASSISTANT_TOOL_TURN,
            TOOL_RESULT_TURN,
        ],
    }
    try:
        parsed = ChatCompletionRequest(**raw).model_dump()
    except ValidationError as exc:
        first = exc.errors()[0]
        return False, [
            "多轮工具会话（assistant tool_calls + tool 结果）被 schema 拒绝",
            f"location={'.'.join(str(p) for p in first['loc'])}  msg={first['msg']}",
        ]

    assistant = parsed["messages"][1]
    kept_tool_calls = "tool_calls" in assistant
    kept_tool_call_id = "tool_call_id" in parsed["messages"][2]
    ok = kept_tool_calls and kept_tool_call_id
    return ok, [
        f"schema 接受了该会话，但 assistant.tool_calls 是否保留: {kept_tool_calls}",
        f"tool 消息的 tool_call_id 是否保留: {kept_tool_call_id}",
    ]


def check_response_dlp_non_streaming() -> tuple[bool, list[str]]:
    os.environ["SHADOW_AGENT_RESPONSE_DLP_MODE"] = "redact"
    db = _memory_session()
    try:
        body = {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "write_file", "arguments": SECRET_IN_TOOL_ARGUMENTS},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
        with _no_side_effects():
            apply_response_dlp(body, request_id="compat-check", db=db)
        survived = FAKE_SECRET in json.dumps(body, ensure_ascii=False)
    finally:
        db.close()

    pattern_hits = len(scan_text(SECRET_IN_TOOL_ARGUMENTS, []).matches)
    detail = [
        f"内置 DLP 模式对同一字符串的命中数（proves the pattern exists）: {pattern_hits}",
        f"经 apply_response_dlp 后密钥仍在响应中: {survived}",
    ]
    return not survived, detail


async def _capture_stream_output() -> bytes:
    os.environ.setdefault("SHADOW_AGENT_UPSTREAM_BASE_URL", "http://127.0.0.1:9/v1")
    os.environ["SHADOW_AGENT_RESPONSE_DLP_MODE"] = "redact"
    frames = [
        _sse_frame(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "write_file", "arguments": SECRET_IN_TOOL_ARGUMENTS},
                    }
                ]
            }
        ),
        b"data: [DONE]\n\n",
    ]
    client = _FakeClient(stream_frames=frames)
    payload = ChatCompletionRequest(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Save the key"}],
        stream=True,
    )
    db = _memory_session()
    try:
        with _no_side_effects(), patch(
            "app.upstream._get_upstream_client", return_value=client
        ):
            response = await _stream_upstream_response(
                payload,
                request_id="compat-check",
                separated={"trusted_instruction": "Save the key", "untrusted_data": ""},
                db=db,
                org_id=None,
            )
            return b"".join([chunk async for chunk in response.body_iterator])
    finally:
        db.close()


def check_response_dlp_streaming(output: bytes) -> tuple[bool, list[str]]:
    text = output.decode("utf-8", errors="replace")
    survived = FAKE_SECRET in text
    detail = [
        f"流式输出字节数: {len(output)}",
        f"经流式 DLP 后密钥仍在 SSE 帧中: {survived}",
    ]
    return not survived, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", action="store_true", help="print every line of detail")
    args = parser.parse_args()

    upstream_body = asyncio.run(_capture_upstream_body())
    stream_output = asyncio.run(_capture_stream_output())

    results: list[tuple[str, str, bool, list[str]]] = [
        ("1", "请求侧标准参数保真度", *check_request_field_fidelity()),
        ("2", "上游请求体保真度", *check_upstream_body_fidelity(upstream_body)),
        ("3", "多轮工具会话（agent 工具循环）", *check_multi_turn_tool_conversation()),
        ("4", "响应侧 DLP（非流式 tool_calls 参数）", *check_response_dlp_non_streaming()),
        ("5", "响应侧 DLP（流式 tool_calls 参数）", *check_response_dlp_streaming(stream_output)),
    ]

    failures = [item for item in results if not item[2]]
    for number, title, ok, detail in results:
        print(f"[{'PASS' if ok else 'GAP '}] {number}. {title}")
        for line in detail if args.verbose or not ok else detail[:1]:
            print(f"        {line}")
    print()
    print(f"闸门结果：{len(results) - len(failures)}/{len(results)} 项通过，{len(failures)} 项存在缺口.")
    if failures:
        print("存在缺口的项：" + ", ".join(f"{number}.{title}" for number, title, _ok, _detail in failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
