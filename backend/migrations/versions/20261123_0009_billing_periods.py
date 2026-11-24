"""Billing periods per subscription (new table only; existing data untouched).

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import app.models.base

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('billing_periods',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('period_start', sa.Date(), nullable=False),
    sa.Column('period_end', sa.Date(), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('invoice_ids', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('total_original', sa.Numeric(precision=18, scale=6), nullable=True),
    sa.Column('currency', sa.String(length=3), nullable=True),
    sa.Column('total_usd', sa.Numeric(precision=18, scale=6), nullable=True),
    sa.Column('total_inr', sa.Numeric(precision=18, scale=6), nullable=True),
    sa.Column('total_source', sa.String(length=16), nullable=True),
    sa.Column('is_final', sa.Boolean(), nullable=False),
    sa.Column('total_collected_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('last_seen_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider', 'scope_external_id', 'name', name='uq_billing_periods_key')
    )
    op.create_index('ix_billing_periods_scope', 'billing_periods', ['provider', 'scope_external_id', 'period_start'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_billing_periods_scope', table_name='billing_periods')
    op.drop_table('billing_periods')
