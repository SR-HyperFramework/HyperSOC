"""Record the material incident facts each investigation was generated from."""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("investigations", sa.Column("incident_signature", sa.String(length=64), nullable=True))


def downgrade():
    op.drop_column("investigations", "incident_signature")
