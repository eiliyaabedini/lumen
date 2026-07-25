"""AI Pass OAuth account connections.

Phase A: additive, reversible, and inert behind FEATURE_AIPASS_OAUTH_ENABLED.
Token bundles and PKCE verifiers are envelope-encrypted; no plaintext token
column exists. The streaming turn carries only an opaque connection id.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0054"
down_revision: str | Sequence[str] | None = "0053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PHASE = "A"


def upgrade() -> None:
    op.create_table(
        "aipass_connections",
        sa.Column("id", sa.String(length=21), nullable=False),
        sa.Column("user_id", sa.String(length=21), nullable=False),
        sa.Column("enc_token_bundle", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("subject_hash", sa.String(length=64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scope", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_aipass_connections_user",
        "aipass_connections",
        ["user_id"],
        unique=True,
    )
    op.create_index(
        "ix_aipass_connections_active",
        "aipass_connections",
        ["user_id"],
        unique=False,
        postgresql_where=sa.text("is_active"),
    )
    op.create_index(
        "ix_aipass_connections_created_at",
        "aipass_connections",
        ["created_at"],
    )

    op.create_table(
        "aipass_oauth_transactions",
        sa.Column("id", sa.String(length=21), nullable=False),
        sa.Column("user_id", sa.String(length=21), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("browser_nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("enc_code_verifier", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_aipass_oauth_transactions_state",
        "aipass_oauth_transactions",
        ["state_hash"],
        unique=True,
    )
    op.create_index(
        "uq_aipass_oauth_transactions_user",
        "aipass_oauth_transactions",
        ["user_id"],
        unique=True,
    )
    op.create_index(
        "ix_aipass_oauth_transactions_expires",
        "aipass_oauth_transactions",
        ["expires_at"],
    )
    op.create_index(
        "ix_aipass_oauth_transactions_created_at",
        "aipass_oauth_transactions",
        ["created_at"],
    )

    # This intentionally has no FK. Disconnect deletes the live token row,
    # while queued turns must retain the opaque funding marker so a later
    # worker fails closed instead of falling through to platform billing.
    op.add_column(
        "tutor_turn_jobs",
        sa.Column("aipass_connection_id", sa.String(length=21), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tutor_turn_jobs", "aipass_connection_id")
    op.drop_table("aipass_oauth_transactions")
    op.drop_table("aipass_connections")
