"""Focused AI Pass OAuth2 account-connection contract.

These tests intentionally exercise the service boundary rather than a browser
SDK: Lumen is server-backed, so OAuth state, PKCE verifier, access tokens and
refresh tokens must stay in FastAPI/Postgres and never cross into browser JS.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.core import secrets_crypto
from app.core.config import get_settings
from app.db.base import get_sessionmaker
from app.models.aipass_connection import AIPassConnection, AIPassOAuthTransaction
from app.models.llm_call import BILLING_AIPASS
from app.models.tutor_turn_job import TURN_STATUS_ABORTED
from app.services import aipass_oauth, byok
from app.services.aipass_client import AIPassModel, AIPassProvider
from app.services.tutor_turn_service import create_turn
from app.workers.tasks.tutor_streaming import _cancel_when_turn_aborted


def _enable(monkeypatch) -> None:
    monkeypatch.setenv("FEATURE_AIPASS_OAUTH_ENABLED", "true")
    monkeypatch.setenv("AIPASS_OAUTH_CLIENT_ID", "first-party-client-sentinel")
    monkeypatch.setenv(
        "AIPASS_OAUTH_REDIRECT_URI",
        "http://localhost:8000/api/v1/aipass/oauth/callback",
    )
    monkeypatch.setenv("BYOK_ALLOW_DERIVED_KEK", "true")
    get_settings.cache_clear()
    secrets_crypto.reset_for_tests()

    async def metadata() -> aipass_oauth.OAuthMetadata:
        return aipass_oauth.OAuthMetadata(
            issuer="https://aipass.one",
            authorization_endpoint="https://aipass.one/oauth2/authorize",
            token_endpoint="https://aipass.one/oauth2/token",
            userinfo_endpoint="https://aipass.one/oauth2/userinfo",
            revocation_endpoint="https://aipass.one/oauth2/revoke",
        )

    monkeypatch.setattr(aipass_oauth, "get_metadata", metadata)


@pytest.fixture(autouse=True)
def _reset_settings():
    yield
    get_settings.cache_clear()
    secrets_crypto.reset_for_tests()


def test_pkce_is_s256_and_state_is_strong() -> None:
    first = aipass_oauth.generate_pkce()
    second = aipass_oauth.generate_pkce()

    assert len(first.verifier) >= 43
    assert len(first.state) >= 32
    assert first.state != second.state
    assert first.verifier != second.verifier
    expected = aipass_oauth.base64url_sha256(first.verifier)
    assert first.challenge == expected
    assert "=" not in first.challenge


async def test_connect_endpoint_redirects_with_http_only_browser_binding(
    client, auth_headers, monkeypatch
) -> None:
    _enable(monkeypatch)
    headers = await auth_headers()

    response = await client.post(
        "/api/v1/me/aipass/connect",
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == 303
    parsed = urlparse(response.headers["location"])
    query = parse_qs(parsed.query)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "aipass.one",
        "/oauth2/authorize",
    )
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["state"][0]) >= 32
    assert len(query["code_challenge"][0]) >= 43
    assert "code_verifier" not in query
    cookie = response.headers["set-cookie"]
    assert "aipass_link=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert response.headers["cache-control"] == "no-store"

    callback = await client.get(
        "/api/v1/aipass/oauth/callback",
        params={"state": query["state"][0], "error": "access_denied"},
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["cache-control"] == "no-store"
    assert callback.headers["referrer-policy"] == "no-referrer"
    assert "aipass=error" in callback.headers["location"]


async def test_start_connect_keeps_verifier_server_side(db_session, make_user, monkeypatch) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-start@lumen.test")

    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()

    assert start.authorization_url.startswith("https://aipass.one/")
    assert "code_challenge_method=S256" in start.authorization_url
    assert "code_verifier" not in start.authorization_url
    assert "first-party-client-sentinel" in start.authorization_url

    tx = (
        await db_session.execute(
            select(AIPassOAuthTransaction).where(AIPassOAuthTransaction.user_id == user.id)
        )
    ).scalar_one()
    assert tx.state_hash == hashlib.sha256(start.state.encode()).hexdigest()
    assert tx.browser_nonce_hash == hashlib.sha256(start.browser_nonce.encode()).hexdigest()
    assert start.state.encode() not in tx.enc_code_verifier
    assert b"first-party-client-sentinel" not in tx.enc_code_verifier
    assert secrets_crypto.decrypt(tx.enc_code_verifier).decode() == start.verifier


async def test_live_selected_connection_drives_aipass_context(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-context@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="context-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("context-access-token"),
            refresh_token=SecretStr("context-refresh-token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )

    async def fake_models(_db, *, user_id: str) -> list[AIPassModel]:
        assert user_id == user.id
        return [AIPassModel(id="live-selected-model", name="Live selected model")]

    monkeypatch.setattr(aipass_oauth, "list_models", fake_models)
    await aipass_oauth.select_model(
        db_session,
        user_id=user.id,
        model="live-selected-model",
    )
    await db_session.commit()

    ctx = await byok.resolve_context(db_session, user_id=user.id)
    assert ctx.mode == BILLING_AIPASS
    assert ctx.aipass_connection_id == connection.id
    assert ctx.credential_id is None

    provider, billing_mode = await byok.build_provider(db_session, ctx)
    assert isinstance(provider, AIPassProvider)
    assert provider.name == "aipass"
    assert billing_mode == BILLING_AIPASS
    assert "context-access-token" not in repr(provider)


async def test_reactivation_revalidates_the_stored_model_live(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-stale-model@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="stale-model-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("stale-access"),
            refresh_token=SecretStr("stale-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    connection.model = "removed-model"
    connection.is_active = False
    await db_session.commit()

    async def fake_models(_db, *, user_id: str) -> list[AIPassModel]:
        assert user_id == user.id
        return [AIPassModel(id="current-model", name="Current model")]

    monkeypatch.setattr(aipass_oauth, "list_models", fake_models)
    with pytest.raises(aipass_oauth.AIPassProtocolError):
        await aipass_oauth.set_active(db_session, user_id=user.id, is_active=True)
    assert connection.is_active is False


async def test_callback_encrypts_tokens_and_state_is_one_time(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-callback@lumen.test")
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()

    seen: dict[str, object] = {}

    async def fake_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        seen["code"] = code
        seen["verifier"] = verifier
        return aipass_oauth.TokenSet(
            access_token=SecretStr("access-token-sentinel"),
            refresh_token=SecretStr("refresh-token-sentinel"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access profile:read",
        )

    async def fake_userinfo(access_token: SecretStr) -> dict[str, object]:
        assert access_token.get_secret_value() == "access-token-sentinel"
        return {"sub": "aipass-user-123", "email": "never-store@example.test"}

    monkeypatch.setattr(aipass_oauth, "exchange_code", fake_exchange)
    monkeypatch.setattr(aipass_oauth, "fetch_userinfo", fake_userinfo)

    with pytest.raises(aipass_oauth.AIPassOAuthStateError):
        await aipass_oauth.complete_connection(
            db_session,
            state=start.state,
            code="authorization-code-sentinel",
            browser_nonce="wrong-browser",
        )

    await aipass_oauth.complete_connection(
        db_session,
        state=start.state,
        code="authorization-code-sentinel",
        browser_nonce=start.browser_nonce,
    )
    await db_session.commit()

    assert seen == {
        "code": "authorization-code-sentinel",
        "verifier": start.verifier,
    }
    row = (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.user_id == user.id)
        )
    ).scalar_one()
    encrypted = bytes(row.enc_token_bundle)
    assert b"access-token-sentinel" not in encrypted
    assert b"refresh-token-sentinel" not in encrypted
    assert b"never-store@example.test" not in encrypted
    bundle = json.loads(secrets_crypto.decrypt(encrypted))
    assert bundle["access_token"] == "access-token-sentinel"
    assert bundle["refresh_token"] == "refresh-token-sentinel"
    assert row.subject_hash == hashlib.sha256(b"aipass-user-123").hexdigest()

    with pytest.raises(aipass_oauth.AIPassOAuthStateError):
        await aipass_oauth.complete_connection(
            db_session,
            state=start.state,
            code="replayed-code",
            browser_nonce=start.browser_nonce,
        )


async def test_refresh_rotation_replaces_bundle_atomically(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-refresh@lumen.test")
    old = aipass_oauth.TokenSet(
        access_token=SecretStr("old-access-token"),
        refresh_token=SecretStr("old-refresh-token"),
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
        scope="api:access",
    )
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="subject-1",
        tokens=old,
    )
    await db_session.commit()
    connection_id = connection.id
    old_blob = bytes(connection.enc_token_bundle)

    async def fake_refresh(refresh_token: SecretStr) -> aipass_oauth.TokenSet:
        assert refresh_token.get_secret_value() == "old-refresh-token"
        return aipass_oauth.TokenSet(
            access_token=SecretStr("rotated-access-token"),
            refresh_token=SecretStr("rotated-refresh-token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    monkeypatch.setattr(aipass_oauth, "refresh_tokens", fake_refresh)

    access = await aipass_oauth.get_valid_access_token(
        connection_id=connection_id,
        user_id=user.id,
        force_refresh=True,
    )
    assert access.get_secret_value() == "rotated-access-token"

    db_session.expire_all()
    fresh = (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection_id)
        )
    ).scalar_one()
    assert bytes(fresh.enc_token_bundle) != old_blob
    rotated = json.loads(secrets_crypto.decrypt(fresh.enc_token_bundle))
    assert rotated["refresh_token"] == "rotated-refresh-token"
    assert "old-refresh-token" not in json.dumps(rotated)


async def test_refresh_request_uses_public_client_json(monkeypatch) -> None:
    _enable(monkeypatch)
    captured: dict[str, object] = {}

    async def fake_read_json(client, method, url, **kwargs):
        del client
        captured.update(method=method, url=url, **kwargs)
        return {
            "access_token": "rotated-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

    monkeypatch.setattr(aipass_oauth, "read_json_bounded", fake_read_json)

    await aipass_oauth.refresh_tokens(SecretStr("original-refresh-token"))

    assert captured["method"] == "POST"
    assert captured["url"] == "https://aipass.one/oauth2/token"
    assert captured["json_body"] == {
        "grantType": "refresh_token",
        "refreshToken": "original-refresh-token",
        "clientId": "first-party-client-sentinel",
    }
    assert "client_secret" not in captured["json_body"]


async def test_repeated_models_401_marks_connection_for_reauth(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-model-401@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="subject-model-401",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("model-old-access"),
            refresh_token=SecretStr("model-old-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    connection.model = "live-model"
    connection.is_active = True
    await db_session.commit()
    connection_id = connection.id
    seen_tokens: list[str] = []

    async def unauthorized(token: SecretStr) -> list[AIPassModel]:
        seen_tokens.append(token.get_secret_value())
        raise aipass_oauth.AIPassUpstreamError(status_code=401)

    async def rotate(refresh_token: SecretStr) -> aipass_oauth.TokenSet:
        assert refresh_token.get_secret_value() == "model-old-refresh"
        return aipass_oauth.TokenSet(
            access_token=SecretStr("model-rotated-access"),
            refresh_token=SecretStr("model-rotated-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    monkeypatch.setattr(aipass_oauth, "discover_models", unauthorized)
    monkeypatch.setattr(aipass_oauth, "refresh_tokens", rotate)

    with pytest.raises(aipass_oauth.AIPassReauthRequired):
        await aipass_oauth.list_models(db_session, user_id=user.id)

    db_session.expire_all()
    fresh = (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection_id)
        )
    ).scalar_one()
    assert seen_tokens == ["model-old-access", "model-rotated-access"]
    assert fresh.status == "reauth_required"
    assert fresh.is_active is False


async def test_disconnect_revokes_then_clears_even_if_revoke_fails(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-disconnect@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="subject-2",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("disconnect-access"),
            refresh_token=SecretStr("disconnect-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    await db_session.commit()
    revoked: list[str] = []

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())
        if len(revoked) == 1:
            raise aipass_oauth.AIPassUpstreamError("redacted")

    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)
    await aipass_oauth.disconnect(db_session, user_id=user.id)
    await db_session.commit()

    assert revoked == ["disconnect-refresh", "disconnect-access"]
    assert (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection.id)
        )
    ).scalar_one_or_none() is None


async def test_revocation_uses_the_discovered_form_endpoint(monkeypatch) -> None:
    _enable(monkeypatch)
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["content_type"] = request.headers["content-type"]
        seen["body"] = parse_qs(request.content.decode())
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(aipass_oauth.httpx, "AsyncClient", lambda **_kwargs: client)

    await aipass_oauth.revoke_token(
        SecretStr("revocation-token"),
        token_type_hint="refresh_token",
    )

    assert seen == {
        "path": "/oauth2/revoke",
        "content_type": "application/x-www-form-urlencoded",
        "body": {
            "token": ["revocation-token"],
            "client_id": ["first-party-client-sentinel"],
            "token_type_hint": ["refresh_token"],
        },
    }


async def test_disconnect_clears_unreadable_local_token_material(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-corrupt-disconnect@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="subject-corrupt",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("corrupt-access"),
            refresh_token=SecretStr("corrupt-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    connection.enc_token_bundle = b"unreadable-encrypted-bundle"
    await db_session.commit()

    await aipass_oauth.disconnect(db_session, user_id=user.id)
    await db_session.commit()

    assert (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection.id)
        )
    ).scalar_one_or_none() is None


async def test_aborted_turn_cancels_worker_owner(db_session, make_user) -> None:
    user = await make_user(email="aipass-cancel@lumen.test")
    turn = await create_turn(
        db_session,
        user_id=user.id,
        conversation_id=None,
        reserved_cost_usd=Decimal("0"),
        reservation_ip_key=None,
        enqueue_task=False,
    )
    turn.status = TURN_STATUS_ABORTED
    await db_session.commit()

    owner_started = asyncio.Event()

    async def owner() -> None:
        owner_started.set()
        await asyncio.Future()

    owner_task = asyncio.create_task(owner())
    await owner_started.wait()
    cancelled_by_user = asyncio.Event()
    watcher = asyncio.create_task(
        _cancel_when_turn_aborted(
            get_sessionmaker(),
            turn_id=turn.id,
            owner=owner_task,
            cancelled_by_user=cancelled_by_user,
        )
    )

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(owner_task, timeout=1)
    await asyncio.wait_for(watcher, timeout=1)
    assert cancelled_by_user.is_set()
