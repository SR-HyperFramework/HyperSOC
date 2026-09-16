"""create incident tables

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("primary_host", sa.String(), nullable=True),
        sa.Column("primary_user", sa.String(), nullable=True),
        sa.Column("primary_src_ip", sa.String(), nullable=True),
        sa.Column("mitre_ids", sa.JSON(), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("ai_summary", sa.Text(), nullable=True),
        sa.Column("ai_analysis", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="ck_incidents_severity"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_incidents_confidence"),
        sa.CheckConstraint("alert_count >= 0", name="ck_incidents_alert_count"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_first_seen", "incidents", ["first_seen"])
    op.create_index("ix_incidents_last_seen", "incidents", ["last_seen"])
    op.create_index("ix_incidents_primary_host", "incidents", ["primary_host"])
    op.create_index("ix_incidents_primary_user", "incidents", ["primary_user"])
    op.create_index("ix_incidents_primary_src_ip", "incidents", ["primary_src_ip"])

    op.create_table(
        "incident_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_alert"),
    )
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])
    op.create_index("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"])


def downgrade() -> None:
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
