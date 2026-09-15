"""create threat intel tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("indicator_type", sa.String(length=20), nullable=False),
        sa.Column("indicator", sa.String(length=2048), nullable=False),
        sa.Column("providers", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("cached_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_lookup_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_threat_intel_indicators_risk_score"),
        sa.UniqueConstraint("indicator_type", "indicator", name="uq_threat_intel_indicators_type_value"),
    )
    op.create_index("ix_threat_intel_indicators_indicator_type", "threat_intel_indicators", ["indicator_type"])
    op.create_index("ix_threat_intel_indicators_indicator", "threat_intel_indicators", ["indicator"])
    op.create_index("ix_threat_intel_indicators_cached_until", "threat_intel_indicators", ["cached_until"])

    op.create_table(
        "alert_threat_intel",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "threat_intel_indicator_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("threat_intel_indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evidence_path", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("alert_id", "threat_intel_indicator_id", "evidence_path", name="uq_alert_threat_intel_path"),
    )
    op.create_index("ix_alert_threat_intel_alert_id", "alert_threat_intel", ["alert_id"])
    op.create_index(
        "ix_alert_threat_intel_threat_intel_indicator_id",
        "alert_threat_intel",
        ["threat_intel_indicator_id"],
    )


def downgrade() -> None:
    op.drop_table("alert_threat_intel")
    op.drop_table("threat_intel_indicators")
