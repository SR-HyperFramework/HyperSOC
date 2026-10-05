"""Durable alert-processing jobs with leases and checkpoints."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("investigations", sa.Column("workflow_key", sa.String(100)))
    op.create_unique_constraint("uq_investigations_workflow_key", "investigations", ["workflow_key"])
    op.create_table(
        "workflow_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("lease_token", UUID(as_uuid=True)),
        sa.Column("output", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("alert_id", name="uq_workflow_alert"),
    )
    op.create_index("ix_workflow_jobs_alert_id", "workflow_jobs", ["alert_id"])
    op.create_index("ix_workflow_jobs_status", "workflow_jobs", ["status"])


def downgrade():
    op.drop_table("workflow_jobs")
    op.drop_constraint("uq_investigations_workflow_key", "investigations", type_="unique")
    op.drop_column("investigations", "workflow_key")
