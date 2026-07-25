"""Server-owned AI Pass OAuth connection and one-time PKCE transaction."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


AIPASS_STATUS_CONNECTED = "connected"
AIPASS_STATUS_REAUTH_REQUIRED = "reauth_required"


class AIPassConnection(IdMixin, TimestampMixin, Base):
    """One encrypted AI Pass token bundle per Lumen user.

    The access and refresh tokens live only inside ``enc_token_bundle``.
    ``subject_hash`` binds reconnects without persisting AI Pass profile PII.
    """

    __tablename__ = "aipass_connections"
    __table_args__ = (
        Index("uq_aipass_connections_user", "user_id", unique=True),
        Index(
            "ix_aipass_connections_active",
            "user_id",
            postgresql_where=text("is_active"),
        ),
    )

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    enc_token_bundle: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=AIPASS_STATUS_CONNECTED)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    user: Mapped[User] = relationship()


class AIPassOAuthTransaction(IdMixin, TimestampMixin, Base):
    """Short-lived one-time state record holding an encrypted PKCE verifier."""

    __tablename__ = "aipass_oauth_transactions"
    __table_args__ = (
        Index("uq_aipass_oauth_transactions_state", "state_hash", unique=True),
        Index("uq_aipass_oauth_transactions_user", "user_id", unique=True),
        Index("ix_aipass_oauth_transactions_expires", "expires_at"),
    )

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    browser_nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    enc_code_verifier: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship()


__all__ = [
    "AIPASS_STATUS_CONNECTED",
    "AIPASS_STATUS_REAUTH_REQUIRED",
    "AIPassConnection",
    "AIPassOAuthTransaction",
]
