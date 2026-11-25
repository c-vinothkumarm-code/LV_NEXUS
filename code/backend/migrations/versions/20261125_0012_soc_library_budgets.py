"""SOC rule library metadata, incident disposition, e-mail attachments, budget approval record (new nullable columns only).

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import app.models.base

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None
J = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    op.add_column('audit_detection_rules', sa.Column('soc_category', sa.String(length=2), nullable=True))
    op.add_column('audit_detection_rules', sa.Column('mitre', J, nullable=True))
    op.add_column('audit_detection_rules', sa.Column('investigation_steps', sa.Text(), nullable=True))
    op.add_column('audit_detection_rules', sa.Column('remediation', sa.Text(), nullable=True))
    op.add_column('audit_detection_rules', sa.Column('exclusions', J, nullable=True))
    op.add_column('audit_detection_rules', sa.Column('data_requirements', J, nullable=True))
    op.add_column('audit_detection_rules', sa.Column('last_triggered_at', app.models.base.UTCDateTime(), nullable=True))
    op.add_column('audit_detection_rules', sa.Column('match_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('cloud_budgets', sa.Column('budget_type', sa.String(length=24), nullable=True))
    op.add_column('cloud_budgets', sa.Column('approver_name', sa.String(length=255), nullable=True))
    op.add_column('cloud_budgets', sa.Column('approver_email', sa.String(length=255), nullable=True))
    op.add_column('cloud_budgets', sa.Column('approval_reference', sa.String(length=255), nullable=True))
    op.add_column('cloud_budgets', sa.Column('approval_evidence', J, nullable=True))
    op.add_column('investigation_cases', sa.Column('disposition', sa.String(length=32), nullable=True))
    op.add_column('investigation_cases', sa.Column('confidence', sa.String(length=8), nullable=True))
    op.add_column('investigation_cases', sa.Column('summary', sa.Text(), nullable=True))
    op.add_column('investigation_cases', sa.Column('notified_at', app.models.base.UTCDateTime(), nullable=True))
    op.add_column('notification_logs', sa.Column('attachments', J, nullable=True))


def downgrade() -> None:
    op.drop_column('notification_logs', 'attachments')
    op.drop_column('investigation_cases', 'notified_at')
    op.drop_column('investigation_cases', 'summary')
    op.drop_column('investigation_cases', 'confidence')
    op.drop_column('investigation_cases', 'disposition')
    op.drop_column('cloud_budgets', 'approval_evidence')
    op.drop_column('cloud_budgets', 'approval_reference')
    op.drop_column('cloud_budgets', 'approver_email')
    op.drop_column('cloud_budgets', 'approver_name')
    op.drop_column('cloud_budgets', 'budget_type')
    op.drop_column('audit_detection_rules', 'match_count')
    op.drop_column('audit_detection_rules', 'last_triggered_at')
    op.drop_column('audit_detection_rules', 'data_requirements')
    op.drop_column('audit_detection_rules', 'exclusions')
    op.drop_column('audit_detection_rules', 'remediation')
    op.drop_column('audit_detection_rules', 'investigation_steps')
    op.drop_column('audit_detection_rules', 'mitre')
    op.drop_column('audit_detection_rules', 'soc_category')
