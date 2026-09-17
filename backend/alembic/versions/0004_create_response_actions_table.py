"""create response actions table

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-17

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "response_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(length=255), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("duration_minutes", sa.Integer(), nullable=True),
        sa.Column("policy_result", sa.JSON(), nullable=False),
        sa.Column("execution_result", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("type IN ('BLOCK_IP', 'DISABLE_USER', 'KILL_PROCESS', 'QUARANTINE_FILE')", name="ck_response_actions_type"),
        sa.CheckConstraint("risk IN ('low', 'medium', 'high')", name="ck_response_actions_risk"),
        sa.CheckConstraint("status IN ('PENDING', 'APPROVED', 'EXECUTING', 'SUCCESS', 'FAILED', 'REJECTED')", name="ck_response_actions_status"),
        sa.CheckConstraint("duration_minutes IS NULL OR duration_minutes > 0", name="ck_response_actions_duration_positive"),
    )
    op.create_index("ix_response_actions_incident_id", "response_actions", ["incident_id"])
    op.create_index("ix_response_actions_type", "response_actions", ["type"])
    op.create_index("ix_response_actions_target", "response_actions", ["target"])
    op.create_index("ix_response_actions_status", "response_actions", ["status"])


def downgrade() -> None:
    op.drop_table("response_actions")
