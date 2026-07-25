"""Bounded AI Pass model discovery and OpenAI-compatible chat transport."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field

import httpx
from pydantic import SecretStr

from app.core.config import get_settings
from app.services.llm import ChatMessage, ChatResponse

AIPASS_MODELS_URL = "https://aipass.one/oauth2/v1/models"
AIPASS_CHAT_URL = "https://aipass.one/oauth2/v1/chat/completions"


class AIPassUpstreamError(RuntimeError):
    """Sanitized upstream failure; never includes response bodies or tokens."""

    def __init__(self, message: str = "AI Pass request failed.", *, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class AIPassProtocolError(AIPassUpstreamError):
    """The upstream returned a malformed success payload."""


class AIPassResponseTooLarge(AIPassUpstreamError):
    """A bounded response exceeded its configured byte ceiling."""


@dataclass(frozen=True)
class AIPassModel:
    """Sanitized live model descriptor exposed to the account settings UI."""

    id: str
    name: str


@dataclass(frozen=True)
class AIPassStreamChunk:
    """One normalized chunk from an AI Pass SSE response."""

    delta: str = ""
    done: bool = False
    usage: dict[str, int | float] = field(default_factory=dict)


TokenProvider = Callable[[bool], Awaitable[SecretStr]]
ConnectionInvalidator = Callable[[], Awaitable[None]]


def _http_timeout() -> httpx.Timeout:
    total = float(get_settings().aipass_oauth_timeout_seconds)
    return httpx.Timeout(timeout=total, connect=min(total, 5.0), pool=min(total, 5.0))


def _new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=_http_timeout(),
        follow_redirects=False,
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


async def _read_response_bytes(response: httpx.Response, *, max_bytes: int) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise AIPassResponseTooLarge()
        except ValueError:
            pass
    total = 0
    parts: list[bytes] = []
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise AIPassResponseTooLarge()
        parts.append(chunk)
    return b"".join(parts)


async def read_json_bounded(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None = None,
    json_body: object | None = None,
    data: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> object:
    """Issue one request and parse a size-bounded JSON response."""
    try:
        async with asyncio.timeout(float(get_settings().aipass_oauth_timeout_seconds)):
            async with client.stream(
                method,
                url,
                headers=headers,
                json=json_body,
                data=data,
                params=params,
            ) as response:
                body = await _read_response_bytes(response, max_bytes=max_bytes)
                if response.status_code >= 400:
                    raise AIPassUpstreamError(status_code=response.status_code)
    except (TimeoutError, httpx.HTTPError) as exc:
        raise AIPassUpstreamError() from exc
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIPassProtocolError() from exc


async def request_bounded(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> bytes:
    """Issue a request with a bounded, optional response body."""
    try:
        async with asyncio.timeout(float(get_settings().aipass_oauth_timeout_seconds)):
            async with client.stream(
                method,
                url,
                headers=headers,
                data=data,
            ) as response:
                body = await _read_response_bytes(response, max_bytes=max_bytes)
                if response.status_code >= 400:
                    raise AIPassUpstreamError(status_code=response.status_code)
                return body
    except (TimeoutError, httpx.HTTPError) as exc:
        raise AIPassUpstreamError() from exc


def parse_models(payload: object) -> list[AIPassModel]:
    """Accept OpenAI ``{object:list,data:[...]}`` and legacy string arrays."""
    if isinstance(payload, list):
        if not all(isinstance(item, str) and 0 < len(item.strip()) <= 128 for item in payload):
            raise AIPassProtocolError()
        return [AIPassModel(id=item.strip(), name=item.strip()) for item in payload]

    if (
        not isinstance(payload, dict)
        or payload.get("object", "list") != "list"
        or not isinstance(payload.get("data"), list)
    ):
        raise AIPassProtocolError()
    data = payload["data"]
    if not data:
        return []
    models: list[AIPassModel] = []
    for item in data:
        if not isinstance(item, dict):
            raise AIPassProtocolError()
        model_id = item.get("id")
        if not isinstance(model_id, str) or not 0 < len(model_id.strip()) <= 128:
            raise AIPassProtocolError()
        raw_name = item.get("name") or item.get("display_name") or model_id
        name = raw_name if isinstance(raw_name, str) and raw_name.strip() else model_id
        if len(name.strip()) > 256:
            raise AIPassProtocolError()
        models.append(AIPassModel(id=model_id.strip(), name=name.strip()))
    return models


async def discover_models(
    access_token: SecretStr,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[AIPassModel]:
    """Fetch the current AI Pass model catalog; model ids are never hard-coded."""
    owned = client is None
    http = client or _new_client()
    try:
        payload = await read_json_bounded(
            http,
            "GET",
            AIPASS_MODELS_URL,
            params={"detailed": "true"},
            headers={"Authorization": f"Bearer {access_token.get_secret_value()}"},
            max_bytes=int(get_settings().aipass_oauth_max_response_bytes),
        )
        return parse_models(payload)
    finally:
        if owned:
            await http.aclose()


def _json_size(payload: object) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())


def _usage_count(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000_000:
        raise AIPassProtocolError()
    return value


class AIPassProvider:
    """AI Pass wallet-backed LLM provider with a redacting representation."""

    name = "aipass"

    def __init__(
        self,
        *,
        model: str,
        token_provider: TokenProvider,
        connection_invalidator: ConnectionInvalidator | None = None,
        client: httpx.AsyncClient | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self._model = model
        self._token_provider = token_provider
        self._connection_invalidator = connection_invalidator
        self._client = client
        self._max_tokens = max_tokens or int(get_settings().llm_max_tokens)

    def __repr__(self) -> str:
        return f"AIPassProvider(model={self._model!r})"

    __str__ = __repr__

    async def _invalidate_connection(self) -> None:
        if self._connection_invalidator is not None:
            with contextlib.suppress(Exception):
                await self._connection_invalidator()

    def _payload(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float,
        stream: bool,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {"role": message.role, "content": message.content} for message in messages
            ],
            "temperature": temperature,
            "max_tokens": self._max_tokens,
            "stream": stream,
        }
        if _json_size(payload) > int(get_settings().aipass_chat_max_request_bytes):
            raise AIPassProtocolError("AI Pass request is too large.", status_code=413)
        return payload

    async def _chat_attempt(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float,
        force_refresh: bool,
        client: httpx.AsyncClient,
    ) -> ChatResponse:
        token = await self._token_provider(force_refresh)
        payload = self._payload(messages, temperature=temperature, stream=False)
        raw = await read_json_bounded(
            client,
            "POST",
            AIPASS_CHAT_URL,
            headers={"Authorization": f"Bearer {token.get_secret_value()}"},
            json_body=payload,
            max_bytes=int(get_settings().aipass_chat_max_response_bytes),
        )
        if not isinstance(raw, dict):
            raise AIPassProtocolError()
        try:
            choices = raw["choices"]
            message = choices[0]["message"]
            content = message["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIPassProtocolError() from exc
        if not isinstance(content, str):
            raise AIPassProtocolError()
        raw_usage = raw.get("usage")
        usage: dict[str, object] = raw_usage if isinstance(raw_usage, dict) else {}
        return ChatResponse(
            text=content,
            prompt_tokens=_usage_count(usage.get("prompt_tokens")),
            completion_tokens=_usage_count(usage.get("completion_tokens")),
            model=self._model,
        )

    async def chat_with_usage(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.2,
    ) -> ChatResponse:
        owned = self._client is None
        client = self._client or _new_client()
        try:
            try:
                return await self._chat_attempt(
                    messages,
                    temperature=temperature,
                    force_refresh=False,
                    client=client,
                )
            except AIPassUpstreamError as exc:
                if exc.status_code != 401:
                    raise
                try:
                    return await self._chat_attempt(
                        messages,
                        temperature=temperature,
                        force_refresh=True,
                        client=client,
                    )
                except AIPassUpstreamError as retry_exc:
                    if retry_exc.status_code == 401:
                        await self._invalidate_connection()
                    raise
        finally:
            if owned:
                await client.aclose()

    async def chat(
        self,
        messages: list[ChatMessage],
        temperature: float = 0.2,
    ) -> str:
        return (await self.chat_with_usage(messages, temperature)).text

    async def stream(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
    ) -> AsyncIterator[AIPassStreamChunk]:
        """Stream SSE with byte/event/time ceilings; cancellation closes HTTP."""
        owned = self._client is None
        client = self._client or _new_client()
        payload = self._payload(messages, temperature=temperature, stream=True)
        timeout_s = float(get_settings().llm_provider_timeout_s)
        try:
            async with asyncio.timeout(timeout_s):
                for attempt in range(2):
                    token = await self._token_provider(attempt == 1)
                    async with client.stream(
                        "POST",
                        AIPASS_CHAT_URL,
                        headers={
                            "Authorization": f"Bearer {token.get_secret_value()}",
                            "Accept": "text/event-stream",
                        },
                        json=payload,
                    ) as response:
                        if response.status_code == 401 and attempt == 0:
                            await _read_response_bytes(
                                response,
                                max_bytes=min(
                                    int(get_settings().aipass_chat_max_response_bytes),
                                    64 * 1024,
                                ),
                            )
                            continue
                        if response.status_code >= 400:
                            await _read_response_bytes(
                                response,
                                max_bytes=min(
                                    int(get_settings().aipass_chat_max_response_bytes),
                                    64 * 1024,
                                ),
                            )
                            if response.status_code == 401:
                                await self._invalidate_connection()
                            raise AIPassUpstreamError(status_code=response.status_code)
                        async for chunk in _parse_sse(response):
                            yield chunk
                        return
                raise AIPassUpstreamError(status_code=401)
        except (TimeoutError, httpx.HTTPError) as exc:
            raise AIPassUpstreamError() from exc
        finally:
            if owned:
                await client.aclose()


async def _parse_sse(response: httpx.Response) -> AsyncIterator[AIPassStreamChunk]:
    max_total = int(get_settings().aipass_stream_max_response_bytes)
    max_event = int(get_settings().aipass_stream_max_event_bytes)
    total = 0
    buffer = b""
    usage: dict[str, int | float] = {}
    async for raw in response.aiter_bytes():
        total += len(raw)
        if total > max_total:
            raise AIPassResponseTooLarge()
        # Normalize only after appending so a CRLF split across network chunks
        # is still recognized as one line ending.
        buffer = (buffer + raw).replace(b"\r\n", b"\n")
        if len(buffer) > max_event and b"\n\n" not in buffer:
            raise AIPassResponseTooLarge()
        while b"\n\n" in buffer:
            event, buffer = buffer.split(b"\n\n", 1)
            if len(event) > max_event:
                raise AIPassResponseTooLarge()
            data_lines = [
                line[5:].lstrip() for line in event.split(b"\n") if line.startswith(b"data:")
            ]
            if not data_lines:
                continue
            data = b"\n".join(data_lines)
            if data == b"[DONE]":
                yield AIPassStreamChunk(done=True, usage=usage)
                return
            try:
                payload = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AIPassProtocolError() from exc
            if not isinstance(payload, dict):
                raise AIPassProtocolError()
            if "error" in payload:
                raise AIPassUpstreamError()
            raw_usage = payload.get("usage")
            if isinstance(raw_usage, dict):
                usage = {
                    "prompt_tokens": _usage_count(raw_usage.get("prompt_tokens")),
                    "completion_tokens": _usage_count(raw_usage.get("completion_tokens")),
                    "cost_usd": 0.0,
                }
            choices = payload.get("choices")
            if isinstance(choices, list) and choices:
                choice = choices[0]
                delta = choice.get("delta") if isinstance(choice, dict) else None
                text = delta.get("content") if isinstance(delta, dict) else None
                if isinstance(text, str) and text:
                    yield AIPassStreamChunk(delta=text)
                finish = choice.get("finish_reason") if isinstance(choice, dict) else None
                if finish is not None:
                    yield AIPassStreamChunk(done=True, usage=usage)
                    return
    if buffer.strip():
        raise AIPassProtocolError()
    yield AIPassStreamChunk(done=True, usage=usage)


__all__ = [
    "AIPASS_CHAT_URL",
    "AIPASS_MODELS_URL",
    "AIPassModel",
    "AIPassProtocolError",
    "AIPassProvider",
    "AIPassResponseTooLarge",
    "AIPassStreamChunk",
    "AIPassUpstreamError",
    "discover_models",
    "parse_models",
    "read_json_bounded",
    "request_bounded",
]
