"""Focused AI Pass OAuth2 account-connection contract.

These tests intentionally exercise the service boundary rather than a browser
SDK: Lumen is server-backed, so OAuth state, PKCE verifier, access tokens and
refresh tokens must stay in FastAPI/Postgres and never cross into browser JS.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
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
from app.models.tutor_turn_job import TURN_STATUS_ABORTED, TutorTurnJob
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


def test_oauth_start_values_have_redacting_representations() -> None:
    pkce = aipass_oauth.PKCEValues(
        state="state-sentinel",
        verifier="verifier-sentinel",
        challenge="challenge-sentinel",
    )
    start = aipass_oauth.OAuthStart(
        authorization_url="https://aipass.one/oauth2/authorize?client_id=client-sentinel",
        state="state-sentinel",
        verifier="verifier-sentinel",
        browser_nonce="browser-sentinel",
    )

    rendered = f"{pkce!r} {start!r}"
    for sentinel in (
        "state-sentinel",
        "verifier-sentinel",
        "challenge-sentinel",
        "client-sentinel",
        "browser-sentinel",
    ):
        assert sentinel not in rendered


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


async def test_callback_rejects_malformed_sensitive_input_without_reflection(client) -> None:
    response = await client.get(
        "/api/v1/aipass/oauth/callback",
        params={
            "state": "tiny-state",
            "code": "authorization-code-sentinel",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "aipass=error" in response.headers["location"]
    assert "authorization-code-sentinel" not in response.headers["location"]
    assert "authorization-code-sentinel" not in response.text
    assert "tiny-state" not in response.text


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
    connection_id = connection.id

    default_ctx = await byok.resolve_context(db_session, user_id=user.id)
    assert default_ctx.aipass_connection_id is None

    ctx = await byok.resolve_context(db_session, user_id=user.id, allow_aipass=True)
    assert ctx.mode == BILLING_AIPASS
    assert ctx.aipass_connection_id == connection_id
    assert ctx.credential_id is None

    provider, billing_mode = await byok.build_provider(db_session, ctx)
    assert isinstance(provider, AIPassProvider)
    assert provider.name == "aipass"
    assert billing_mode == BILLING_AIPASS
    assert "context-access-token" not in repr(provider)


async def test_resolved_aipass_context_fails_closed_if_feature_is_disabled(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-disable-race@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="disable-race-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("disable-race-access"),
            refresh_token=SecretStr("disable-race-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    connection.model = "live-model"
    connection.is_active = True
    await db_session.commit()

    ctx = await byok.resolve_context(db_session, user_id=user.id, allow_aipass=True)
    monkeypatch.setenv("FEATURE_AIPASS_OAUTH_ENABLED", "false")
    get_settings.cache_clear()

    with pytest.raises(aipass_oauth.AIPassConfigurationError):
        await byok.build_provider(db_session, ctx)


async def test_malformed_aipass_context_never_falls_through_to_platform(db_session) -> None:
    ctx = byok.LLMContext(
        user_id=None,
        aipass_connection_id="opaque-connection-id",
        foreground=False,
        mode=BILLING_AIPASS,
    )

    with pytest.raises(aipass_oauth.AIPassConfigurationError):
        await byok.build_provider(db_session, ctx)


async def test_invalid_kek_map_does_not_enable_oauth_storage(
    db_session, make_user, monkeypatch
) -> None:
    user = await make_user(email="aipass-invalid-kek@lumen.test")
    monkeypatch.setenv("FEATURE_AIPASS_OAUTH_ENABLED", "true")
    monkeypatch.setenv("AIPASS_OAUTH_CLIENT_ID", "configured-client")
    monkeypatch.setenv(
        "AIPASS_OAUTH_REDIRECT_URI",
        "http://localhost:8000/api/v1/aipass/oauth/callback",
    )
    monkeypatch.setenv("BYOK_MASTER_KEYS", '{"1":""}')
    monkeypatch.setenv("BYOK_ALLOW_DERIVED_KEK", "false")
    get_settings.cache_clear()
    secrets_crypto.reset_for_tests()

    with pytest.raises(aipass_oauth.AIPassConfigurationError):
        await aipass_oauth.start_connection(db_session, user_id=user.id)


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


async def test_complete_connection_commits_issued_grant_before_return(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-callback-commit@lumen.test")
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()

    async def fake_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        del code, verifier
        return aipass_oauth.TokenSet(
            access_token=SecretStr("commit-access"),
            refresh_token=SecretStr("commit-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_userinfo(_access_token: SecretStr) -> dict[str, object]:
        return {"sub": "commit-subject"}

    monkeypatch.setattr(aipass_oauth, "exchange_code", fake_exchange)
    monkeypatch.setattr(aipass_oauth, "fetch_userinfo", fake_userinfo)

    await aipass_oauth.complete_connection(
        db_session,
        state=start.state,
        code="authorization-code",
        browser_nonce=start.browser_nonce,
    )

    async with get_sessionmaker()() as observer:
        persisted = (
            await observer.execute(
                select(AIPassConnection).where(AIPassConnection.user_id == user.id)
            )
        ).scalar_one_or_none()
    assert persisted is not None


async def test_callback_commit_failure_revokes_issued_grant(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-callback-commit-failure@lumen.test")
    user_id = user.id
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()
    revoked: list[str] = []

    async def fake_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        del code, verifier
        return aipass_oauth.TokenSet(
            access_token=SecretStr("failed-commit-access"),
            refresh_token=SecretStr("failed-commit-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_userinfo(_access_token: SecretStr) -> dict[str, object]:
        return {"sub": "failed-commit-subject"}

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())

    real_commit = db_session.commit
    commit_calls = 0

    async def fail_final_commit() -> None:
        nonlocal commit_calls
        commit_calls += 1
        if commit_calls == 2:
            raise RuntimeError("simulated commit failure")
        await real_commit()

    monkeypatch.setattr(aipass_oauth, "exchange_code", fake_exchange)
    monkeypatch.setattr(aipass_oauth, "fetch_userinfo", fake_userinfo)
    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)
    monkeypatch.setattr(db_session, "commit", fail_final_commit)

    with pytest.raises(RuntimeError, match="simulated commit failure"):
        await aipass_oauth.complete_connection(
            db_session,
            state=start.state,
            code="authorization-code",
            browser_nonce=start.browser_nonce,
        )

    assert revoked == ["failed-commit-refresh", "failed-commit-access"]
    async with get_sessionmaker()() as observer:
        persisted = (
            await observer.execute(
                select(AIPassConnection).where(AIPassConnection.user_id == user_id)
            )
        ).scalar_one_or_none()
    assert persisted is None


async def test_failed_exchange_purges_consumed_pkce_verifier(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-exchange-failure@lumen.test")
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()

    async def failed_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        del code, verifier
        raise aipass_oauth.AIPassUpstreamError()

    monkeypatch.setattr(aipass_oauth, "exchange_code", failed_exchange)

    with pytest.raises(aipass_oauth.AIPassUpstreamError):
        await aipass_oauth.complete_connection(
            db_session,
            state=start.state,
            code="authorization-code",
            browser_nonce=start.browser_nonce,
        )

    async with get_sessionmaker()() as observer:
        transaction = (
            await observer.execute(
                select(AIPassOAuthTransaction).where(AIPassOAuthTransaction.user_id == user.id)
            )
        ).scalar_one_or_none()
    assert transaction is None


async def test_reconnect_revokes_the_replaced_grant(db_session, make_user, monkeypatch) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-reconnect-revoke@lumen.test")
    await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="reconnect-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("replaced-access"),
            refresh_token=SecretStr("replaced-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()
    revoked: list[str] = []

    async def fake_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        del code, verifier
        return aipass_oauth.TokenSet(
            access_token=SecretStr("replacement-access"),
            refresh_token=SecretStr("replacement-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_userinfo(_access_token: SecretStr) -> dict[str, object]:
        return {"sub": "reconnect-subject"}

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())

    monkeypatch.setattr(aipass_oauth, "exchange_code", fake_exchange)
    monkeypatch.setattr(aipass_oauth, "fetch_userinfo", fake_userinfo)
    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)

    await aipass_oauth.complete_connection(
        db_session,
        state=start.state,
        code="authorization-code",
        browser_nonce=start.browser_nonce,
    )

    assert revoked == ["replaced-refresh", "replaced-access"]
    connection = (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.user_id == user.id)
        )
    ).scalar_one()
    bundle = json.loads(secrets_crypto.decrypt(connection.enc_token_bundle))
    assert bundle["refresh_token"] == "replacement-refresh"


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


async def test_refresh_commit_failure_revokes_rotation_and_requires_reauth(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-refresh-commit-failure@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="refresh-commit-failure-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("pre-failure-access"),
            refresh_token=SecretStr("pre-failure-refresh"),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            scope="api:access",
        ),
    )
    await db_session.commit()
    connection_id = connection.id
    revoked: list[str] = []

    async def fake_refresh(_refresh_token: SecretStr) -> aipass_oauth.TokenSet:
        return aipass_oauth.TokenSet(
            access_token=SecretStr("unpersisted-access"),
            refresh_token=SecretStr("unpersisted-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())

    @asynccontextmanager
    async def failing_session():
        async with get_sessionmaker()() as session:
            real_commit = session.commit
            commit_calls = 0

            async def fail_rotation_commit() -> None:
                nonlocal commit_calls
                commit_calls += 1
                if commit_calls == 1:
                    raise RuntimeError("simulated rotation commit failure")
                await real_commit()

            monkeypatch.setattr(session, "commit", fail_rotation_commit)
            yield session

    def failing_session_factory():
        return failing_session()

    monkeypatch.setattr(aipass_oauth, "refresh_tokens", fake_refresh)
    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)

    with pytest.raises(aipass_oauth.AIPassReauthRequired):
        await aipass_oauth.get_valid_access_token(
            connection_id=connection_id,
            user_id=user.id,
            force_refresh=True,
            session_factory=failing_session_factory,  # type: ignore[arg-type]
        )

    assert revoked == ["unpersisted-refresh", "unpersisted-access"]
    db_session.expire_all()
    fresh = (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection_id)
        )
    ).scalar_one()
    assert fresh.status == "reauth_required"
    assert fresh.is_active is False
    bundle = json.loads(secrets_crypto.decrypt(fresh.enc_token_bundle))
    assert bundle["refresh_token"] == "pre-failure-refresh"


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


async def test_disconnect_serializes_with_refresh_rotation(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-refresh-disconnect@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="refresh-disconnect-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("old-access"),
            refresh_token=SecretStr("old-refresh"),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            scope="api:access",
        ),
    )
    await db_session.commit()
    connection_id = connection.id

    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()
    revoked: list[str] = []

    async def fake_refresh(_refresh_token: SecretStr) -> aipass_oauth.TokenSet:
        refresh_started.set()
        await release_refresh.wait()
        return aipass_oauth.TokenSet(
            access_token=SecretStr("rotated-access"),
            refresh_token=SecretStr("rotated-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())

    monkeypatch.setattr(aipass_oauth, "refresh_tokens", fake_refresh)
    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)

    refresh_task = asyncio.create_task(
        aipass_oauth.get_valid_access_token(
            connection_id=connection_id,
            user_id=user.id,
            force_refresh=True,
        )
    )
    await refresh_started.wait()

    async def run_disconnect() -> None:
        async with get_sessionmaker()() as session:
            await aipass_oauth.disconnect(session, user_id=user.id)
            await session.commit()

    disconnect_task = asyncio.create_task(run_disconnect())
    await asyncio.sleep(0.05)
    release_refresh.set()
    await refresh_task
    await disconnect_task

    assert revoked == ["rotated-refresh", "rotated-access"]
    db_session.expire_all()
    assert (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection_id)
        )
    ).scalar_one_or_none() is None


async def test_disconnect_invalidates_callback_finishing_after_exchange(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-callback-disconnect@lumen.test")
    user_id = user.id
    start = await aipass_oauth.start_connection(db_session, user_id=user.id)
    await db_session.commit()

    exchange_started = asyncio.Event()
    release_exchange = asyncio.Event()
    revoked: list[str] = []

    async def fake_exchange(*, code: str, verifier: str) -> aipass_oauth.TokenSet:
        del code, verifier
        exchange_started.set()
        await release_exchange.wait()
        return aipass_oauth.TokenSet(
            access_token=SecretStr("late-access"),
            refresh_token=SecretStr("late-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        )

    async def fake_userinfo(_access_token: SecretStr) -> dict[str, object]:
        return {"sub": "late-subject"}

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        revoked.append(token.get_secret_value())

    monkeypatch.setattr(aipass_oauth, "exchange_code", fake_exchange)
    monkeypatch.setattr(aipass_oauth, "fetch_userinfo", fake_userinfo)
    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)

    async def run_callback() -> None:
        async with get_sessionmaker()() as session:
            await aipass_oauth.complete_connection(
                session,
                state=start.state,
                code="authorization-code",
                browser_nonce=start.browser_nonce,
            )

    callback_task = asyncio.create_task(run_callback())
    await exchange_started.wait()
    async with get_sessionmaker()() as session:
        await aipass_oauth.disconnect(session, user_id=user.id)
        await session.commit()
    release_exchange.set()

    with pytest.raises(aipass_oauth.AIPassOAuthStateError):
        await callback_task
    assert revoked == ["late-refresh", "late-access"]
    db_session.expire_all()
    assert (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.user_id == user_id)
        )
    ).scalar_one_or_none() is None


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


async def test_disconnect_clears_tokens_if_revocation_is_cancelled(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-disconnect-cancelled-revoke@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="cancelled-revoke-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("cancelled-revoke-access"),
            refresh_token=SecretStr("cancelled-revoke-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    await db_session.commit()
    connection_id = connection.id
    attempts: list[str] = []

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token_type_hint
        attempts.append(token.get_secret_value())
        if len(attempts) == 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)

    await aipass_oauth.disconnect(db_session, user_id=user.id)
    await db_session.commit()

    assert attempts == ["cancelled-revoke-refresh", "cancelled-revoke-access"]
    assert (
        await db_session.execute(
            select(AIPassConnection).where(AIPassConnection.id == connection_id)
        )
    ).scalar_one_or_none() is None


async def test_disconnect_preserves_queued_turn_aipass_funding_marker(
    db_session, make_user, monkeypatch
) -> None:
    _enable(monkeypatch)
    user = await make_user(email="aipass-disconnect-queued-turn@lumen.test")
    connection = await aipass_oauth.store_connection(
        db_session,
        user_id=user.id,
        subject="queued-turn-subject",
        tokens=aipass_oauth.TokenSet(
            access_token=SecretStr("queued-turn-access"),
            refresh_token=SecretStr("queued-turn-refresh"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            scope="api:access",
        ),
    )
    turn = await create_turn(
        db_session,
        user_id=user.id,
        conversation_id=None,
        reserved_cost_usd=Decimal("0"),
        reservation_ip_key=None,
        aipass_connection_id=connection.id,
        enqueue_task=False,
    )
    await db_session.commit()
    connection_id = connection.id
    turn_id = turn.id

    async def fake_revoke(token: SecretStr, *, token_type_hint: str) -> None:
        del token, token_type_hint

    monkeypatch.setattr(aipass_oauth, "revoke_token", fake_revoke)
    await aipass_oauth.disconnect(db_session, user_id=user.id)
    await db_session.commit()

    carried_id = (
        await db_session.execute(
            select(TutorTurnJob.aipass_connection_id).where(TutorTurnJob.id == turn_id)
        )
    ).scalar_one()
    assert carried_id == connection_id
    with pytest.raises(aipass_oauth.AIPassReauthRequired):
        await aipass_oauth.build_provider(
            db_session,
            connection_id=carried_id,
            user_id=user.id,
        )


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
