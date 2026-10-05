"""Align generated audit/collection timestamps with ORM not-null contracts."""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

TIMESTAMPS = {
    "alert_threat_intel": ["created_at"], "alerts": ["created_at"],
    "audit_events": ["created_at"], "behavior_models": ["created_at"],
    "hub_entities": ["updated_at"], "hub_evidence": ["collected_at"],
    "incident_alerts": ["created_at"], "incidents": ["created_at", "updated_at"],
    "response_actions": ["created_at", "updated_at"], "soc_users": ["created_at"],
    "threat_intel_indicators": ["created_at", "updated_at"],
    "workflow_jobs": ["created_at", "updated_at"],
}


def upgrade():
    for table_name, columns in TIMESTAMPS.items():
        for column_name in columns:
            table = sa.table(table_name, sa.column(column_name, sa.DateTime(timezone=True)))
            op.execute(table.update().where(table.c[column_name].is_(None)).values({column_name: sa.func.now()}))
            op.alter_column(table_name, column_name, existing_type=sa.DateTime(timezone=True), nullable=False)


def downgrade():
    for table_name, columns in TIMESTAMPS.items():
        for column_name in columns:
            op.alter_column(table_name, column_name, existing_type=sa.DateTime(timezone=True), nullable=True)
