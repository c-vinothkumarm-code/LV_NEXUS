"""Account ownership and its change history (new tables only; existing data untouched).

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa

import app.models.base

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('account_ownership',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('provider', sa.String(length=16), nullable=False),
                    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
                    *[sa.Column(c, sa.String(length=255), nullable=True) for c in (
                        'spoc_name', 'spoc_email', 'owner_name', 'owner_email', 'entity', 'entity_lead', 'entity_lead_email',
                        'cloud_admin_email', 'finops_spoc_name', 'finops_spoc_email')],
                    sa.Column('cost_centre', sa.String(length=128), nullable=True),
                    sa.Column('notes', sa.Text(), nullable=True),
                    sa.Column('updated_by', sa.String(length=255), nullable=True),
                    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
                    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('provider', 'scope_external_id', name='uq_account_ownership_scope'))
    op.create_table('account_ownership_history',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('ownership_id', sa.Integer(), nullable=False),
                    sa.Column('provider', sa.String(length=16), nullable=False),
                    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
                    sa.Column('field', sa.String(length=64), nullable=False),
                    sa.Column('old_value', sa.Text(), nullable=True),
                    sa.Column('new_value', sa.Text(), nullable=True),
                    sa.Column('changed_by', sa.String(length=255), nullable=False),
                    sa.Column('changed_at', app.models.base.UTCDateTime(), nullable=False),
                    sa.ForeignKeyConstraint(['ownership_id'], ['account_ownership.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_account_ownership_history_ownership_id', 'account_ownership_history', ['ownership_id'])
    op.create_index('ix_account_ownership_history_scope_external_id', 'account_ownership_history', ['scope_external_id'])


def downgrade() -> None:
    op.drop_table('account_ownership_history')
    op.drop_table('account_ownership')
