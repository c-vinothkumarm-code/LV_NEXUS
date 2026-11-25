"""Cloud Services & Asset Management: asset details, business metadata (+ append-only history), daily activity
snapshots, append-only inventory changes and the activity policy. New tables only; existing data untouched.

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

import app.models.base

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('asset_activity_snapshots',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource_key', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('day', sa.Date(), nullable=False),
    sa.Column('classification', sa.String(length=24), nullable=False),
    sa.Column('reason', sa.Text(), nullable=True),
    sa.Column('state', sa.String(length=64), nullable=True),
    sa.Column('cpu_avg', sa.Float(), nullable=True),
    sa.Column('network_mb_per_day', sa.Float(), nullable=True),
    sa.Column('last_activity_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('snapshot', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('resource_key', 'day', name='uq_asset_activity_day')
    )
    op.create_index(op.f('ix_asset_activity_snapshots_day'), 'asset_activity_snapshots', ['day'], unique=False)
    op.create_index(op.f('ix_asset_activity_snapshots_resource_key'), 'asset_activity_snapshots', ['resource_key'], unique=False)
    op.create_table('asset_details',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource_key', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('resource_id', sa.Text(), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('guest_os', sa.String(length=255), nullable=True),
    sa.Column('guest_os_source', sa.String(length=64), nullable=True),
    sa.Column('cpus', sa.Integer(), nullable=True),
    sa.Column('memory_gb', sa.Float(), nullable=True),
    sa.Column('nic_count', sa.Integer(), nullable=True),
    sa.Column('provisioned_gb', sa.Float(), nullable=True),
    sa.Column('native_backup_status', sa.String(length=32), nullable=True),
    sa.Column('native_backup_last_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('native_backup_detail', sa.String(length=512), nullable=True),
    sa.Column('created_at_provider', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('collected_at', app.models.base.UTCDateTime(), nullable=True),
    sa.Column('gaps', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('resource_key', name='uq_asset_details_key')
    )
    op.create_index(op.f('ix_asset_details_provider'), 'asset_details', ['provider'], unique=False)
    op.create_index(op.f('ix_asset_details_scope_external_id'), 'asset_details', ['scope_external_id'], unique=False)
    op.create_table('asset_inventory_changes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource_key', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('field', sa.String(length=64), nullable=False),
    sa.Column('old_value', sa.Text(), nullable=True),
    sa.Column('new_value', sa.Text(), nullable=True),
    sa.Column('observed_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_inventory_changes_resource_key'), 'asset_inventory_changes', ['resource_key'], unique=False)
    op.create_table('asset_metadata',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource_key', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('scope_external_id', sa.String(length=128), nullable=False),
    sa.Column('resource_id', sa.Text(), nullable=False),
    sa.Column('server_spoc_name', sa.String(length=255), nullable=True),
    sa.Column('server_spoc_email', sa.String(length=255), nullable=True),
    sa.Column('reporting_manager_name', sa.String(length=255), nullable=True),
    sa.Column('reporting_manager_email', sa.String(length=255), nullable=True),
    sa.Column('department', sa.String(length=255), nullable=True),
    sa.Column('asset_owner', sa.String(length=255), nullable=True),
    sa.Column('asset_owner_email', sa.String(length=255), nullable=True),
    sa.Column('business_purpose', sa.Text(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('asset_classification', sa.String(length=32), nullable=True),
    sa.Column('environment_classification', sa.String(length=32), nullable=True),
    sa.Column('confidentiality', sa.String(length=16), nullable=True),
    sa.Column('integrity', sa.String(length=16), nullable=True),
    sa.Column('availability', sa.String(length=16), nullable=True),
    sa.Column('pii_classification', sa.String(length=32), nullable=True),
    sa.Column('business_timeline', sa.String(length=255), nullable=True),
    sa.Column('planned_end_date', sa.Date(), nullable=True),
    sa.Column('commvault_backup_status', sa.String(length=32), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('resource_key', name='uq_asset_metadata_key')
    )
    op.create_index(op.f('ix_asset_metadata_department'), 'asset_metadata', ['department'], unique=False)
    op.create_index(op.f('ix_asset_metadata_provider'), 'asset_metadata', ['provider'], unique=False)
    op.create_index(op.f('ix_asset_metadata_scope_external_id'), 'asset_metadata', ['scope_external_id'], unique=False)
    op.create_index(op.f('ix_asset_metadata_server_spoc_email'), 'asset_metadata', ['server_spoc_email'], unique=False)
    op.create_table('asset_metadata_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('resource_key', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=16), nullable=False),
    sa.Column('field', sa.String(length=64), nullable=False),
    sa.Column('old_value', sa.Text(), nullable=True),
    sa.Column('new_value', sa.Text(), nullable=True),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('changed_by', sa.String(length=255), nullable=False),
    sa.Column('changed_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_asset_metadata_history_resource_key'), 'asset_metadata_history', ['resource_key'], unique=False)
    op.create_table('asset_policy',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('updated_by', sa.String(length=255), nullable=True),
    sa.Column('created_at', app.models.base.UTCDateTime(), nullable=False),
    sa.Column('updated_at', app.models.base.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key', name='uq_asset_policy_key')
    )
    from app.database.triggers import create_triggers
    create_triggers(op.get_bind())  # asset_metadata_history and asset_inventory_changes are append-only


def downgrade() -> None:
    op.drop_table('asset_policy')
    op.drop_index(op.f('ix_asset_metadata_history_resource_key'), table_name='asset_metadata_history')
    op.drop_table('asset_metadata_history')
    op.drop_index(op.f('ix_asset_metadata_server_spoc_email'), table_name='asset_metadata')
    op.drop_index(op.f('ix_asset_metadata_scope_external_id'), table_name='asset_metadata')
    op.drop_index(op.f('ix_asset_metadata_provider'), table_name='asset_metadata')
    op.drop_index(op.f('ix_asset_metadata_department'), table_name='asset_metadata')
    op.drop_table('asset_metadata')
    op.drop_index(op.f('ix_asset_inventory_changes_resource_key'), table_name='asset_inventory_changes')
    op.drop_table('asset_inventory_changes')
    op.drop_index(op.f('ix_asset_details_scope_external_id'), table_name='asset_details')
    op.drop_index(op.f('ix_asset_details_provider'), table_name='asset_details')
    op.drop_table('asset_details')
    op.drop_index(op.f('ix_asset_activity_snapshots_resource_key'), table_name='asset_activity_snapshots')
    op.drop_index(op.f('ix_asset_activity_snapshots_day'), table_name='asset_activity_snapshots')
    op.drop_table('asset_activity_snapshots')
