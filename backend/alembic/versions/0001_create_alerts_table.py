"""create alerts table

Revision ID: 0001
Revises:
Create Date: 2026-09-11

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("agent_name", sa.String(), nullable=True),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("rule_level", sa.Integer(), nullable=True),
        sa.Column("rule_description", sa.String(), nullable=True),
        sa.Column("mitre_ids", sa.JSON(), nullable=False),
        sa.Column("groups", sa.JSON(), nullable=False),
        sa.Column("src_ip", sa.String(), nullable=True),
        sa.Column("dst_ip", sa.String(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("process_name", sa.String(), nullable=True),
        sa.Column("process_command_line", sa.String(), nullable=True),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("file_hash", sa.String(), nullable=True),
        sa.Column("raw_event", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("fingerprint", name="uq_alerts_fingerprint"),
    )
    op.create_index("ix_alerts_external_id", "alerts", ["external_id"])
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index("ix_alerts_agent_id", "alerts", ["agent_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_username", "alerts", ["username"])
    op.create_index("ix_alerts_file_hash", "alerts", ["file_hash"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])


def downgrade() -> None:
    op.drop_table("alerts")
