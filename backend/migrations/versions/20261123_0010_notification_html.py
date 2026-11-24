"""HTML body for e-mail notifications (one nullable column added; existing rows untouched).

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('notification_logs', sa.Column('body_html', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('notification_logs', 'body_html')
