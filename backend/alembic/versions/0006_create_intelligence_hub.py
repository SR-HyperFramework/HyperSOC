"""Create canonical hub evidence and entity relationship storage."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "hub_entities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("external_key", sa.String(512), nullable=False),
        sa.Column("label", sa.String(512), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("kind", "external_key", name="uq_hub_entity_key"),
    )
    op.create_index("ix_hub_entities_kind", "hub_entities", ["kind"])
    op.create_table(
        "hub_relationships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", UUID(as_uuid=True), sa.ForeignKey("hub_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("hub_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.String(512), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.UniqueConstraint("source_id", "target_id", "relation", "source_ref", name="uq_hub_relationship_evidence"),
    )
    for name in ("source_id", "target_id", "observed_at"):
        op.create_index(f"ix_hub_relationships_{name}", "hub_relationships", [name])
    op.create_table(
        "hub_evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="SET NULL")),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("external_id", sa.String(512), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_key", sa.String(512)),
        sa.Column("identity_key", sa.String(512)),
        sa.Column("normalized", sa.JSON(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("source", "external_id", name="uq_hub_evidence_source"),
    )
    for name in ("alert_id", "source", "category", "timestamp", "host_key", "identity_key"):
        op.create_index(f"ix_hub_evidence_{name}", "hub_evidence", [name])


def downgrade():
    op.drop_table("hub_evidence")
    op.drop_table("hub_relationships")
    op.drop_table("hub_entities")
