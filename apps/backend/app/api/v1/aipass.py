"""Optional server-owned AI Pass OAuth account connection endpoints."""

from __future__ import annotations

from typing import Never
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, Query, Request, status
from fastapi.responses import RedirectResponse

from app.api.deps import CurrentUser, DBSession
from app.core.config import get_settings
from app.core.errors import (
    AIPassConnectionRequiredError,
    AIPassModelUnavailableError,
    AIPassOAuthError,
    AIPassUnavailableError,
    AIPassUpstreamAppError,
)
from app.core.ratelimit import limiter
from app.schemas.aipass import (
    AIPassActivePatch,
    AIPassModelOut,
    AIPassModelSelect,
    AIPassModelsOut,
    AIPassStatusOut,
)
from app.schemas.common import OkResponse
from app.services import aipass_oauth as service
from app.services.aipass_client import AIPassProtocolError, AIPassUpstreamError

router = APIRouter()
_LINK_COOKIE_PROD = "__Host-aipass-link"
_LINK_COOKIE_DEV = "aipass_link"


def _available() -> bool:
    settings = get_settings()
    secure_storage = bool(settings.byok_master_keys) or (
        not settings.is_prod and settings.byok_allow_derived_kek
    )
    return bool(
        settings.feature_aipass_oauth_enabled
        and settings.aipass_oauth_client_id
        and settings.aipass_oauth_client_id.get_secret_value()
        and settings.aipass_oauth_redirect_uri
        and secure_storage
    )


def _redirect_result(result: str) -> RedirectResponse:
    base = str(get_settings().web_base_url).rstrip("/")
    query = urlencode({"aipass": result})
    response = RedirectResponse(
        f"{base}/profile/model?{query}",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
        },
    )
    for name in (_LINK_COOKIE_PROD, _LINK_COOKIE_DEV):
        response.delete_cookie(
            name,
            path="/",
            secure=get_settings().is_prod,
            httponly=True,
            samesite="lax",
        )
    return response


def _require_available() -> None:
    if not _available():
        raise AIPassUnavailableError("AI Pass connection is unavailable.")


def _map_error(exc: Exception) -> Never:
    if isinstance(exc, service.AIPassConfigurationError):
        raise AIPassUnavailableError("AI Pass connection is unavailable.") from exc
    if isinstance(exc, service.AIPassOAuthStateError):
        raise AIPassOAuthError("AI Pass connection could not be verified.") from exc
    if isinstance(exc, service.AIPassReauthRequired):
        raise AIPassConnectionRequiredError("Reconnect AI Pass.") from exc
    if isinstance(exc, AIPassProtocolError) and exc.status_code in (409, 422):
        raise AIPassModelUnavailableError("That AI Pass model is no longer available.") from exc
    if isinstance(exc, AIPassUpstreamError):
        raise AIPassUpstreamAppError("AI Pass is temporarily unavailable.") from exc
    raise exc


@router.get("/me/aipass/status", response_model=AIPassStatusOut)
async def connection_status(user: CurrentUser, db: DBSession) -> AIPassStatusOut:
    if not _available():
        return AIPassStatusOut(
            available=False,
            connected=False,
            active=False,
            model=None,
            status="unavailable",
        )
    connection = await service.get_connection(db, user_id=user.id)
    if connection is None:
        return AIPassStatusOut(
            available=True,
            connected=False,
            active=False,
            model=None,
            status="disconnected",
        )
    return AIPassStatusOut(
        available=True,
        connected=True,
        active=connection.is_active,
        model=connection.model,
        status=connection.status,
    )


@router.post(
    "/me/aipass/connect",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
)
@limiter.limit("10/minute")
async def connect(user: CurrentUser, db: DBSession, request: Request) -> RedirectResponse:
    """Start OAuth via a server redirect; no client id is returned as JSON."""
    del request
    try:
        start = await service.start_connection(db, user_id=user.id)
    except Exception as exc:
        _map_error(exc)
    await db.commit()
    response = RedirectResponse(
        start.authorization_url,
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )
    response.set_cookie(
        key=_LINK_COOKIE_PROD if get_settings().is_prod else _LINK_COOKIE_DEV,
        value=start.browser_nonce,
        max_age=int(get_settings().aipass_oauth_transaction_ttl_seconds),
        secure=get_settings().is_prod,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get(
    "/aipass/oauth/callback",
    response_class=RedirectResponse,
    include_in_schema=False,
)
async def callback(
    db: DBSession,
    state: str = Query(min_length=16, max_length=512),
    code: str | None = Query(default=None, min_length=1, max_length=4096),
    error: str | None = Query(default=None, max_length=128),
    link_cookie_prod: str | None = Cookie(default=None, alias=_LINK_COOKIE_PROD),
    link_cookie_dev: str | None = Cookie(default=None, alias=_LINK_COOKIE_DEV),
) -> RedirectResponse:
    """Validate one-time state plus an HttpOnly browser-link nonce."""
    browser_nonce = link_cookie_prod or link_cookie_dev or ""
    if error is not None or code is None:
        await service.consume_state(
            db,
            state=state,
            browser_nonce=browser_nonce,
        )
        await db.commit()
        return _redirect_result("error")
    try:
        await service.complete_connection(
            db,
            state=state,
            code=code,
            browser_nonce=browser_nonce,
        )
        await db.commit()
    except Exception:
        # Never reflect OAuth/provider errors, authorization codes, state, or
        # token responses into the redirect query or application error body.
        await db.rollback()
        return _redirect_result("error")
    return _redirect_result("connected")


@router.get("/me/aipass/models", response_model=AIPassModelsOut)
async def models(user: CurrentUser, db: DBSession) -> AIPassModelsOut:
    _require_available()
    try:
        rows = await service.list_models(db, user_id=user.id)
    except Exception as exc:
        _map_error(exc)
    return AIPassModelsOut(models=[AIPassModelOut(id=row.id, name=row.name) for row in rows])


@router.put("/me/aipass/model", response_model=AIPassStatusOut)
async def choose_model(
    payload: AIPassModelSelect, user: CurrentUser, db: DBSession
) -> AIPassStatusOut:
    _require_available()
    try:
        connection = await service.select_model(db, user_id=user.id, model=payload.model)
    except Exception as exc:
        _map_error(exc)
    return AIPassStatusOut(
        available=True,
        connected=True,
        active=connection.is_active,
        model=connection.model,
        status=connection.status,
    )


@router.patch("/me/aipass", response_model=AIPassStatusOut)
async def patch_connection(
    payload: AIPassActivePatch, user: CurrentUser, db: DBSession
) -> AIPassStatusOut:
    _require_available()
    try:
        connection = await service.set_active(db, user_id=user.id, is_active=payload.is_active)
    except Exception as exc:
        _map_error(exc)
    return AIPassStatusOut(
        available=True,
        connected=True,
        active=connection.is_active,
        model=connection.model,
        status=connection.status,
    )


@router.delete(
    "/me/aipass",
    response_model=OkResponse,
    responses={status.HTTP_200_OK: {"model": OkResponse}},
)
async def disconnect(
    user: CurrentUser,
    db: DBSession,
) -> OkResponse:
    await service.disconnect(db, user_id=user.id)
    return OkResponse()
