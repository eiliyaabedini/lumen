"""AI Pass live-model and bounded chat transport tests."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr

from app.services import aipass_client
from app.services.llm import ChatMessage


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "object": "list",
                "data": [
                    {"id": "live-model-a", "name": "Model A"},
                    {"id": "live-model-b"},
                ],
            },
            ["live-model-a", "live-model-b"],
        ),
        (["legacy-model-a", "legacy-model-b"], ["legacy-model-a", "legacy-model-b"]),
        ([], []),
    ],
)
def test_parse_models_accepts_openai_and_legacy_shapes(payload, expected) -> None:
    models = aipass_client.parse_models(payload)
    assert [m.id for m in models] == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"object": "list", "data": "not-a-list"},
        {"data": [{"id": ""}, {"name": "missing-id"}]},
        [1, None, {"id": "not-legacy"}],
    ],
)
def test_parse_models_rejects_malformed_shapes(payload) -> None:
    with pytest.raises(aipass_client.AIPassProtocolError):
        aipass_client.parse_models(payload)


async def test_model_discovery_uses_detailed_true_and_bearer_only() -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["query"] = parse_qs(urlparse(str(request.url)).query)
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={"object": "list", "data": [{"id": "live-model"}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    models = await aipass_client.discover_models(
        SecretStr("model-access-token"),
        client=client,
    )
    await client.aclose()

    assert [m.id for m in models] == ["live-model"]
    assert seen == {
        "path": "/oauth2/v1/models",
        "query": {"detailed": ["true"]},
        "authorization": "Bearer model-access-token",
    }


async def test_nonstreaming_chat_is_bounded_and_openai_compatible() -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "wallet answer"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3},
                "model": "live-model",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def token_provider(_force_refresh: bool) -> SecretStr:
        return SecretStr("chat-access-token")

    provider = aipass_client.AIPassProvider(
        model="live-model",
        token_provider=token_provider,
        client=client,
        max_tokens=256,
    )
    response = await provider.chat_with_usage(
        [ChatMessage(role="user", content="hello")],
        temperature=0.1,
    )
    await client.aclose()

    assert response.text == "wallet answer"
    assert response.prompt_tokens == 7
    assert response.completion_tokens == 3
    assert seen["path"] == "/oauth2/v1/chat/completions"
    assert seen["authorization"] == "Bearer chat-access-token"
    assert seen["body"] == {
        "model": "live-model",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.1,
        "max_tokens": 256,
        "stream": False,
    }
    assert "chat-access-token" not in repr(provider)


async def test_chat_refreshes_once_on_401() -> None:
    tokens: list[str] = []
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        tokens.append(request.headers["authorization"])
        if calls == 1:
            return httpx.Response(401, json={"error": {"message": "expired"}})
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {},
                "model": "live-model",
            },
        )

    async def token_provider(force_refresh: bool) -> SecretStr:
        return SecretStr("new-token" if force_refresh else "old-token")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = aipass_client.AIPassProvider(
        model="live-model",
        token_provider=token_provider,
        client=client,
        max_tokens=32,
    )
    assert await provider.chat([ChatMessage(role="user", content="hi")]) == "ok"
    await client.aclose()
    assert tokens == ["Bearer old-token", "Bearer new-token"]


async def test_chat_marks_connection_for_reauth_after_second_401() -> None:
    invalidations = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "revoked"}})

    async def token_provider(force_refresh: bool) -> SecretStr:
        return SecretStr("new-token" if force_refresh else "old-token")

    async def invalidate() -> None:
        nonlocal invalidations
        invalidations += 1

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = aipass_client.AIPassProvider(
        model="live-model",
        token_provider=token_provider,
        connection_invalidator=invalidate,
        client=client,
        max_tokens=32,
    )

    with pytest.raises(aipass_client.AIPassUpstreamError) as exc:
        await provider.chat([ChatMessage(role="user", content="hi")])
    await client.aclose()

    assert exc.value.status_code == 401
    assert invalidations == 1


async def test_oversized_response_is_rejected_without_echoing_body() -> None:
    sentinel = "upstream-body-secret"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=(sentinel * 100).encode())

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(aipass_client.AIPassResponseTooLarge) as exc:
        await aipass_client.read_json_bounded(
            client,
            "GET",
            "https://aipass.one/test",
            max_bytes=32,
        )
    await client.aclose()
    assert sentinel not in str(exc.value)


async def test_stream_cancellation_closes_upstream_response() -> None:
    closed = asyncio.Event()

    class BlockingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'data: {"choices":[{"delta":{"content":"first"}}]}\\n\\n'
            await asyncio.Future()

        async def aclose(self) -> None:
            closed.set()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=BlockingStream(),
        )

    async def token_provider(_force_refresh: bool) -> SecretStr:
        return SecretStr("stream-token")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = aipass_client.AIPassProvider(
        model="live-model",
        token_provider=token_provider,
        client=client,
        max_tokens=32,
    )

    async def consume() -> None:
        async for _ in provider.stream(
            [ChatMessage(role="user", content="hello")],
            temperature=0.2,
        ):
            pass

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(closed.wait(), timeout=1)
    await client.aclose()
