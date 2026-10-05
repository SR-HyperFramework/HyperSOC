"""Versioned learned categorical behavior models and technique transitions."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "behavior_models",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("host_key", sa.String(512), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("trained_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trained_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("corpus_digest", sa.String(64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_behavior_models_host_key", "behavior_models", ["host_key"])
    op.create_index("ix_behavior_models_trained_until", "behavior_models", ["trained_until"])


def downgrade():
    op.drop_table("behavior_models")
