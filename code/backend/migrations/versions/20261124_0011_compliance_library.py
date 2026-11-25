"""Compliance policy library: settings, runs, results (new tables only; existing data untouched).

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import app.models.base

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None
J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    op.create_table('compliance_policy_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('policy_key', sa.String(length=32), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('params', J, nullable=True),
    sa.Column('owner', sa.String(length=255), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('attested_status', sa.String(length=16), nullable=True),
    sa.Column('attested_by', sa.String(length=255), nullable=True),
    sa.Column('attested_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('attestation_evidence', sa.String(length=1024), nullable=True),
    sa.Column('attestation_valid_until', sa.Date(), nullable=True),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('policy_key')
    )
    op.create_table('compliance_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('started_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('finished_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('trigger', sa.String(length=32), nullable=False),
    sa.Column('triggered_by', sa.String(length=255), nullable=True),
    sa.Column('totals', J, nullable=True),
    sa.Column('scores', J, nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('compliance_results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('run_id', sa.Integer(), nullable=False),
    sa.Column('policy_key', sa.String(length=32), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('scope_name', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('failing', sa.Integer(), nullable=False),
    sa.Column('assessed', sa.Integer(), nullable=False),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.Column('evidence', J, nullable=True),
    sa.Column('basis', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['run_id'], ['compliance_runs.id']),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_compliance_results_run_id', 'compliance_results', ['run_id'], unique=False)
    op.create_index('ix_compliance_results_run_policy', 'compliance_results', ['run_id', 'policy_key'], unique=False)


def downgrade() -> None:
    op.drop_table('compliance_results')  # its indexes go with it (MySQL will not drop an FK-backing index first)
    op.drop_table('compliance_runs')
    op.drop_table('compliance_policy_settings')
