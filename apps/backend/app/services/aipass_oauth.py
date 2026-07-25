"""Server-owned Authorization Code + PKCE integration for AI Pass."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlparse

import httpx
from pydantic import SecretStr
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import secrets_crypto
from app.core.config import Environment, get_settings
from app.db.base import get_sessionmaker
from app.models.aipass_connection import (
    AIPASS_STATUS_CONNECTED,
    AIPASS_STATUS_REAUTH_REQUIRED,
    AIPassConnection,
    AIPassOAuthTransaction,
)
from app.models.user import User
from app.models.user_llm_credential import UserLLMCredential
from app.services.aipass_client import (
    AIPassModel,
    AIPassProtocolError,
    AIPassProvider,
    AIPassUpstreamError,
    discover_models,
    read_json_bounded,
    request_bounded,
)

AIPASS_DISCOVERY_URL = "https://aipass.one/.well-known/oauth-authorization-server"
_EXPECTED_ISSUER = "https://aipass.one"
_METADATA_TTL_SECONDS = 300
_metadata_cache: tuple[float, OAuthMetadata] | None = None
_metadata_lock = asyncio.Lock()


class AIPassOAuthStateError(RuntimeError):
    """Missing, expired, consumed, or otherwise invalid OAuth state."""


class AIPassConfigurationError(RuntimeError):
    """The optional integration is disabled or incomplete."""


class AIPassReauthRequired(AIPassUpstreamError):
    """Refresh failed and the user must reconnect their AI Pass account."""


@dataclass(frozen=True)
class PKCEValues:
    state: str
    verifier: str
    challenge: str


@dataclass(frozen=True)
class OAuthStart:
    authorization_url: str
    state: str
    verifier: str
    browser_nonce: str


@dataclass(frozen=True)
class OAuthMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    revocation_endpoint: str


@dataclass(frozen=True)
class TokenSet:
    access_token: SecretStr
    refresh_token: SecretStr
    expires_at: datetime
    scope: str


def reset_metadata_cache_for_tests() -> None:
    global _metadata_cache
    _metadata_cache = None


def base64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def generate_pkce() -> PKCEValues:
    """Generate independent high-entropy state and RFC 7636 verifier."""
    verifier = secrets.token_urlsafe(64)
    state = secrets.token_urlsafe(48)
    return PKCEValues(
        state=state,
        verifier=verifier,
        challenge=base64url_sha256(verifier),
    )


def _client_id() -> str:
    settings = get_settings()
    if not settings.feature_aipass_oauth_enabled:
        raise AIPassConfigurationError("AI Pass connection is unavailable.")
    if settings.aipass_oauth_client_id is None:
        raise AIPassConfigurationError("AI Pass client configuration is missing.")
    value = settings.aipass_oauth_client_id.get_secret_value()
    if not value:
        raise AIPassConfigurationError("AI Pass client configuration is missing.")
    return value


def _redirect_uri() -> str:
    value = get_settings().aipass_oauth_redirect_uri
    if value is None:
        raise AIPassConfigurationError("AI Pass callback configuration is missing.")
    rendered = str(value)
    parsed = urlparse(rendered)
    web = urlparse(str(get_settings().web_base_url))
    if (
        parsed.hostname != web.hostname
        or parsed.path != "/api/v1/aipass/oauth/callback"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AIPassConfigurationError("AI Pass callback configuration is invalid.")
    if get_settings().env == Environment.production and parsed.scheme != "https":
        raise AIPassConfigurationError("AI Pass callback configuration must use HTTPS.")
    return rendered


def _require_secure_storage() -> None:
    """Refuse real OAuth material under a derived KEK unless dev opted in."""
    settings = get_settings()
    real = bool(settings.byok_master_keys)
    if real:
        return
    if settings.env != Environment.production and settings.byok_allow_derived_kek:
        return
    raise AIPassConfigurationError("Secure token storage is not configured for AI Pass.")


def _validate_endpoint(url: object) -> str:
    if not isinstance(url, str):
        raise AIPassProtocolError()
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "aipass.one"
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AIPassProtocolError()
    return url


def _parse_metadata(raw: object) -> OAuthMetadata:
    if not isinstance(raw, dict) or raw.get("issuer") != _EXPECTED_ISSUER:
        raise AIPassProtocolError()
    methods = raw.get("code_challenge_methods_supported")
    auth_methods = raw.get("token_endpoint_auth_methods_supported")
    grants = raw.get("grant_types_supported")
    if not isinstance(methods, list) or "S256" not in methods:
        raise AIPassProtocolError()
    if not isinstance(auth_methods, list) or "none" not in auth_methods:
        raise AIPassProtocolError()
    if (
        not isinstance(grants, list)
        or "authorization_code" not in grants
        or "refresh_token" not in grants
    ):
        raise AIPassProtocolError()
    return OAuthMetadata(
        issuer=_EXPECTED_ISSUER,
        authorization_endpoint=_validate_endpoint(raw.get("authorization_endpoint")),
        token_endpoint=_validate_endpoint(raw.get("token_endpoint")),
        userinfo_endpoint=_validate_endpoint(raw.get("userinfo_endpoint")),
        revocation_endpoint=_validate_endpoint(raw.get("revocation_endpoint")),
    )


async def get_metadata(*, force: bool = False) -> OAuthMetadata:
    """Resolve and validate AI Pass endpoints from RFC 8414 discovery."""
    global _metadata_cache
    now = time.monotonic()
    if not force and _metadata_cache and now - _metadata_cache[0] < _METADATA_TTL_SECONDS:
        return _metadata_cache[1]
    async with _metadata_lock:
        now = time.monotonic()
        if not force and _metadata_cache and now - _metadata_cache[0] < _METADATA_TTL_SECONDS:
            return _metadata_cache[1]
        async with httpx.AsyncClient(
            timeout=float(get_settings().aipass_oauth_timeout_seconds),
            follow_redirects=False,
        ) as client:
            raw = await read_json_bounded(
                client,
                "GET",
                AIPASS_DISCOVERY_URL,
                max_bytes=64 * 1024,
            )
        parsed = _parse_metadata(raw)
        _metadata_cache = (now, parsed)
        return parsed


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


async def start_connection(db: AsyncSession, *, user_id: str) -> OAuthStart:
    """Persist one-time state/verifier and return the external authorization URL."""
    _require_secure_storage()
    client_id = _client_id()
    redirect_uri = _redirect_uri()
    metadata = await get_metadata()
    pkce = generate_pkce()
    browser_nonce = secrets.token_urlsafe(32)
    encrypted = secrets_crypto.encrypt(pkce.verifier.encode())
    # One live browser-link transaction per account bounds storage and makes a
    # newly-started connection invalidate any abandoned prior authorization.
    # The user-row lock serializes double-click/concurrent starts before the
    # unique-per-user transaction insert.
    await db.execute(select(User.id).where(User.id == user_id).with_for_update())
    await db.execute(
        delete(AIPassOAuthTransaction).where(AIPassOAuthTransaction.user_id == user_id)
    )
    tx = AIPassOAuthTransaction(
        user_id=user_id,
        state_hash=_state_hash(pkce.state),
        browser_nonce_hash=_state_hash(browser_nonce),
        enc_code_verifier=encrypted,
        key_version=get_settings().byok_master_key_version,
        expires_at=datetime.now(UTC)
        + timedelta(seconds=int(get_settings().aipass_oauth_transaction_ttl_seconds)),
    )
    db.add(tx)
    await db.flush()
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "api:access profile:read",
            "state": pkce.state,
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        }
    )
    return OAuthStart(
        authorization_url=f"{metadata.authorization_endpoint}?{query}",
        state=pkce.state,
        verifier=pkce.verifier,
        browser_nonce=browser_nonce,
    )


def _token_set(raw: object, *, prior_refresh: SecretStr | None = None) -> TokenSet:
    if not isinstance(raw, dict):
        raise AIPassProtocolError()
    access = raw.get("access_token")
    refresh = raw.get("refresh_token")
    if not isinstance(access, str) or not access or len(access) > 64 * 1024:
        raise AIPassProtocolError()
    if not isinstance(refresh, str) or not refresh:
        if prior_refresh is None:
            raise AIPassProtocolError()
        refresh = prior_refresh.get_secret_value()
    if len(refresh) > 64 * 1024:
        raise AIPassProtocolError()
    try:
        expires_in = int(raw.get("expires_in", 3600))
    except (TypeError, ValueError) as exc:
        raise AIPassProtocolError() from exc
    if expires_in <= 0 or expires_in > 90 * 24 * 60 * 60:
        raise AIPassProtocolError()
    token_type = str(raw.get("token_type", "Bearer"))
    if token_type.lower() != "bearer":
        raise AIPassProtocolError()
    scope = raw.get("scope", "")
    if isinstance(scope, str) and len(scope) > 255:
        raise AIPassProtocolError()
    return TokenSet(
        access_token=SecretStr(access),
        refresh_token=SecretStr(refresh),
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
        scope=scope if isinstance(scope, str) else "",
    )


async def exchange_code(*, code: str, verifier: str) -> TokenSet:
    metadata = await get_metadata()
    async with httpx.AsyncClient(
        timeout=float(get_settings().aipass_oauth_timeout_seconds),
        follow_redirects=False,
    ) as client:
        raw = await read_json_bounded(
            client,
            "POST",
            metadata.token_endpoint,
            headers={"Content-Type": "application/json"},
            json_body={
                "grantType": "authorization_code",
                "code": code,
                "codeVerifier": verifier,
                "clientId": _client_id(),
                "redirectUri": _redirect_uri(),
            },
            max_bytes=64 * 1024,
        )
    return _token_set(raw)


async def refresh_tokens(refresh_token: SecretStr) -> TokenSet:
    metadata = await get_metadata()
    async with httpx.AsyncClient(
        timeout=float(get_settings().aipass_oauth_timeout_seconds),
        follow_redirects=False,
    ) as client:
        raw = await read_json_bounded(
            client,
            "POST",
            metadata.token_endpoint,
            headers={"Content-Type": "application/json"},
            json_body={
                "grantType": "refresh_token",
                "refreshToken": refresh_token.get_secret_value(),
                "clientId": _client_id(),
            },
            max_bytes=64 * 1024,
        )
    return _token_set(raw, prior_refresh=refresh_token)


async def fetch_userinfo(access_token: SecretStr) -> dict[str, object]:
    metadata = await get_metadata()
    async with httpx.AsyncClient(
        timeout=float(get_settings().aipass_oauth_timeout_seconds),
        follow_redirects=False,
    ) as client:
        raw = await read_json_bounded(
            client,
            "GET",
            metadata.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token.get_secret_value()}"},
            max_bytes=64 * 1024,
        )
    if not isinstance(raw, dict):
        raise AIPassProtocolError()
    return raw


def _subject(userinfo: dict[str, object]) -> str:
    for field in ("sub", "id", "user_id"):
        value = userinfo.get(field)
        if isinstance(value, (str, int)) and 0 < len(str(value)) <= 4096:
            return str(value)
    raise AIPassProtocolError()


def _bundle_bytes(tokens: TokenSet) -> bytes:
    return json.dumps(
        {
            "access_token": tokens.access_token.get_secret_value(),
            "refresh_token": tokens.refresh_token.get_secret_value(),
            "expires_at": tokens.expires_at.isoformat(),
            "scope": tokens.scope,
        },
        separators=(",", ":"),
    ).encode()


def _decode_bundle(connection: AIPassConnection) -> TokenSet:
    try:
        raw = json.loads(secrets_crypto.decrypt(connection.enc_token_bundle))
        expires_at = datetime.fromisoformat(raw["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return TokenSet(
            access_token=SecretStr(raw["access_token"]),
            refresh_token=SecretStr(raw["refresh_token"]),
            expires_at=expires_at,
            scope=str(raw.get("scope", "")),
        )
    except Exception as exc:
        raise AIPassProtocolError("Stored AI Pass connection is unreadable.") from exc


async def store_connection(
    db: AsyncSession,
    *,
    user_id: str,
    subject: str,
    tokens: TokenSet,
) -> AIPassConnection:
    _require_secure_storage()
    encrypted = secrets_crypto.encrypt(_bundle_bytes(tokens))
    subject_hash = hashlib.sha256(subject.encode()).hexdigest()
    row = (
        await db.execute(select(AIPassConnection).where(AIPassConnection.user_id == user_id))
    ).scalar_one_or_none()
    if row is None:
        row = AIPassConnection(
            user_id=user_id,
            enc_token_bundle=encrypted,
            key_version=get_settings().byok_master_key_version,
            subject_hash=subject_hash,
            token_expires_at=tokens.expires_at,
            scope=tokens.scope,
            status=AIPASS_STATUS_CONNECTED,
            model=None,
            is_active=False,
        )
        db.add(row)
    else:
        row.enc_token_bundle = encrypted
        row.key_version = get_settings().byok_master_key_version
        row.subject_hash = subject_hash
        row.token_expires_at = tokens.expires_at
        row.scope = tokens.scope
        row.status = AIPASS_STATUS_CONNECTED
        # Preserve a previously-selected model across a reconnect; live
        # discovery re-validates it before the next activation/dispatch.
    await db.flush()
    return row


async def complete_connection(
    db: AsyncSession,
    *,
    state: str,
    code: str,
    browser_nonce: str,
) -> AIPassConnection:
    """Consume state before exchange, validate userinfo, then encrypt tokens."""
    if (
        not state
        or len(state) > 512
        or not code
        or len(code) > 4096
        or not browser_nonce
        or len(browser_nonce) > 512
    ):
        raise AIPassOAuthStateError("Invalid OAuth callback.")
    now = datetime.now(UTC)
    tx = (
        await db.execute(
            select(AIPassOAuthTransaction)
            .where(
                AIPassOAuthTransaction.state_hash == _state_hash(state),
                AIPassOAuthTransaction.browser_nonce_hash == _state_hash(browser_nonce),
                AIPassOAuthTransaction.consumed_at.is_(None),
                AIPassOAuthTransaction.expires_at > now,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if tx is None:
        raise AIPassOAuthStateError("Invalid or expired OAuth state.")
    verifier = secrets_crypto.decrypt(tx.enc_code_verifier).decode()
    tx.consumed_at = now
    await db.commit()  # one-time even if the external exchange fails

    tokens = await exchange_code(code=code, verifier=verifier)
    try:
        userinfo = await fetch_userinfo(tokens.access_token)
        return await store_connection(
            db,
            user_id=tx.user_id,
            subject=_subject(userinfo),
            tokens=tokens,
        )
    except Exception:
        # The authorization code has already been consumed. If identity
        # binding or local persistence fails, do not leave the newly-issued
        # grant live: revoke both tokens best-effort before failing closed.
        for token, hint in (
            (tokens.refresh_token, "refresh_token"),
            (tokens.access_token, "access_token"),
        ):
            with contextlib.suppress(Exception):
                await revoke_token(token, token_type_hint=hint)
        raise


async def consume_state(db: AsyncSession, *, state: str, browser_nonce: str) -> None:
    """Consume an OAuth transaction after provider denial/cancel."""
    if not state or len(state) > 512 or not browser_nonce or len(browser_nonce) > 512:
        return
    await db.execute(
        update(AIPassOAuthTransaction)
        .where(
            AIPassOAuthTransaction.state_hash == _state_hash(state),
            AIPassOAuthTransaction.browser_nonce_hash == _state_hash(browser_nonce),
            AIPassOAuthTransaction.consumed_at.is_(None),
        )
        .values(consumed_at=datetime.now(UTC))
    )


async def get_connection(db: AsyncSession, *, user_id: str) -> AIPassConnection | None:
    return (
        await db.execute(select(AIPassConnection).where(AIPassConnection.user_id == user_id))
    ).scalar_one_or_none()


async def get_active_connection(db: AsyncSession, *, user_id: str) -> AIPassConnection | None:
    return (
        await db.execute(
            select(AIPassConnection).where(
                AIPassConnection.user_id == user_id,
                AIPassConnection.is_active.is_(True),
                AIPassConnection.status == AIPASS_STATUS_CONNECTED,
                AIPassConnection.model.is_not(None),
            )
        )
    ).scalar_one_or_none()


async def get_valid_access_token(
    *,
    connection_id: str,
    user_id: str,
    force_refresh: bool = False,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> SecretStr:
    """Read or atomically rotate tokens in an independent short transaction."""
    factory = session_factory or get_sessionmaker()
    async with factory() as db:
        row = (
            await db.execute(
                select(AIPassConnection)
                .where(
                    AIPassConnection.id == connection_id,
                    AIPassConnection.user_id == user_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None or row.status != AIPASS_STATUS_CONNECTED:
            raise AIPassReauthRequired("Reconnect AI Pass.", status_code=401)
        current = _decode_bundle(row)
        should_refresh = force_refresh or current.expires_at <= datetime.now(UTC) + timedelta(
            seconds=30
        )
        if not should_refresh:
            return current.access_token
        try:
            rotated = await refresh_tokens(current.refresh_token)
        except Exception as exc:
            row.status = AIPASS_STATUS_REAUTH_REQUIRED
            row.is_active = False
            await db.commit()
            raise AIPassReauthRequired("Reconnect AI Pass.", status_code=401) from exc
        row.enc_token_bundle = secrets_crypto.encrypt(_bundle_bytes(rotated))
        row.key_version = get_settings().byok_master_key_version
        row.token_expires_at = rotated.expires_at
        row.scope = rotated.scope
        await db.commit()
        return rotated.access_token


async def _mark_reauth_required(
    *,
    connection_id: str,
    user_id: str,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    factory = session_factory or get_sessionmaker()
    async with factory() as db:
        await db.execute(
            update(AIPassConnection)
            .where(
                AIPassConnection.id == connection_id,
                AIPassConnection.user_id == user_id,
            )
            .values(
                status=AIPASS_STATUS_REAUTH_REQUIRED,
                is_active=False,
            )
        )
        await db.commit()


async def list_models(db: AsyncSession, *, user_id: str) -> list[AIPassModel]:
    connection = await get_connection(db, user_id=user_id)
    if connection is None:
        raise AIPassReauthRequired("Connect AI Pass first.", status_code=401)
    token = await get_valid_access_token(
        connection_id=connection.id,
        user_id=user_id,
    )
    try:
        return await discover_models(token)
    except AIPassUpstreamError as exc:
        if exc.status_code != 401:
            raise
    token = await get_valid_access_token(
        connection_id=connection.id,
        user_id=user_id,
        force_refresh=True,
    )
    try:
        return await discover_models(token)
    except AIPassUpstreamError as exc:
        if exc.status_code == 401:
            await _mark_reauth_required(
                connection_id=connection.id,
                user_id=user_id,
            )
            raise AIPassReauthRequired("Reconnect AI Pass.", status_code=401) from exc
        raise


async def select_model(db: AsyncSession, *, user_id: str, model: str) -> AIPassConnection:
    if not model or len(model) > 128:
        raise AIPassProtocolError("Invalid AI Pass model.", status_code=422)
    connection = await get_connection(db, user_id=user_id)
    if connection is None:
        raise AIPassReauthRequired("Connect AI Pass first.", status_code=401)
    models = await list_models(db, user_id=user_id)
    if model not in {item.id for item in models}:
        raise AIPassProtocolError("That AI Pass model is no longer available.", status_code=409)
    # One active user-owned source at a time. BYOK stays intact and can be
    # reactivated later; no existing provider or API path is removed.
    await db.execute(
        update(UserLLMCredential)
        .where(UserLLMCredential.user_id == user_id)
        .values(is_active=False)
    )
    connection.model = model
    connection.status = AIPASS_STATUS_CONNECTED
    connection.is_active = True
    await db.flush()
    return connection


async def set_active(db: AsyncSession, *, user_id: str, is_active: bool) -> AIPassConnection:
    connection = await get_connection(db, user_id=user_id)
    if connection is None:
        raise AIPassReauthRequired("Connect AI Pass first.", status_code=401)
    if is_active and (not connection.model or connection.status != AIPASS_STATUS_CONNECTED):
        raise AIPassProtocolError("Choose an available AI Pass model first.", status_code=409)
    if is_active:
        live_models = await list_models(db, user_id=user_id)
        if connection.model not in {item.id for item in live_models}:
            raise AIPassProtocolError(
                "That AI Pass model is no longer available.",
                status_code=409,
            )
        await db.execute(
            update(UserLLMCredential)
            .where(UserLLMCredential.user_id == user_id)
            .values(is_active=False)
        )
    connection.is_active = is_active
    await db.flush()
    return connection


async def build_provider(
    db: AsyncSession,
    *,
    connection_id: str,
    user_id: str,
    token_session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> AIPassProvider:
    connection = (
        await db.execute(
            select(AIPassConnection).where(
                AIPassConnection.id == connection_id,
                AIPassConnection.user_id == user_id,
                AIPassConnection.status == AIPASS_STATUS_CONNECTED,
                AIPassConnection.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if connection is None or not connection.model:
        raise AIPassReauthRequired("Reconnect AI Pass.", status_code=401)

    async def token_provider(force_refresh: bool) -> SecretStr:
        return await get_valid_access_token(
            connection_id=connection_id,
            user_id=user_id,
            force_refresh=force_refresh,
            session_factory=token_session_factory,
        )

    async def connection_invalidator() -> None:
        await _mark_reauth_required(
            connection_id=connection_id,
            user_id=user_id,
            session_factory=token_session_factory,
        )

    return AIPassProvider(
        model=connection.model,
        token_provider=token_provider,
        connection_invalidator=connection_invalidator,
        max_tokens=int(get_settings().llm_max_tokens),
    )


async def revoke_token(token: SecretStr, *, token_type_hint: str) -> None:
    metadata = await get_metadata()
    async with httpx.AsyncClient(
        timeout=float(get_settings().aipass_oauth_timeout_seconds),
        follow_redirects=False,
    ) as client:
        await request_bounded(
            client,
            "POST",
            metadata.revocation_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "token": token.get_secret_value(),
                "client_id": _client_id(),
                "token_type_hint": token_type_hint,
            },
            max_bytes=64 * 1024,
        )


async def disconnect(db: AsyncSession, *, user_id: str) -> None:
    connection = await get_connection(db, user_id=user_id)
    if connection is None:
        return
    try:
        tokens = _decode_bundle(connection)
    except AIPassProtocolError:
        tokens = None
    # Revoke both independently, but clearing local token material is
    # unconditional and wins over network or local-decryption failure.
    if tokens is not None:
        for token, hint in (
            (tokens.refresh_token, "refresh_token"),
            (tokens.access_token, "access_token"),
        ):
            with contextlib.suppress(Exception):
                await revoke_token(token, token_type_hint=hint)
    await db.execute(delete(AIPassConnection).where(AIPassConnection.id == connection.id))
    await db.flush()


__all__ = [
    "AIPASS_DISCOVERY_URL",
    "AIPassConfigurationError",
    "AIPassOAuthStateError",
    "AIPassReauthRequired",
    "AIPassUpstreamError",
    "OAuthMetadata",
    "OAuthStart",
    "PKCEValues",
    "TokenSet",
    "base64url_sha256",
    "build_provider",
    "complete_connection",
    "consume_state",
    "disconnect",
    "exchange_code",
    "fetch_userinfo",
    "generate_pkce",
    "get_active_connection",
    "get_connection",
    "get_metadata",
    "get_valid_access_token",
    "list_models",
    "refresh_tokens",
    "reset_metadata_cache_for_tests",
    "revoke_token",
    "select_model",
    "set_active",
    "start_connection",
    "store_connection",
]
