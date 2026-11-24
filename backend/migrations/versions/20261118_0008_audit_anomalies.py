"""Live audit anomalies (new table only; existing data untouched).

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import app.models.base

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_anomalies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('dedupe_key', sa.String(length=64), nullable=False),
    sa.Column('rule', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('principal', sa.String(length=512), nullable=True),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('detail', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('event_ids', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('event_count', sa.Integer(), nullable=False),
    sa.Column('first_event_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('last_event_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('acknowledged_by', sa.String(length=255), nullable=True),
    sa.Column('acknowledged_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dedupe_key', name='uq_audit_anomaly_key')
    )
    op.create_index('ix_audit_anomaly_seen', 'audit_anomalies', ['last_event_at'], unique=False)
    op.create_index(op.f('ix_audit_anomalies_rule'), 'audit_anomalies', ['rule'], unique=False)
    op.create_index(op.f('ix_audit_anomalies_severity'), 'audit_anomalies', ['severity'], unique=False)
    op.create_index(op.f('ix_audit_anomalies_principal'), 'audit_anomalies', ['principal'], unique=False)
    op.create_index(op.f('ix_audit_anomalies_status'), 'audit_anomalies', ['status'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_anomalies')
