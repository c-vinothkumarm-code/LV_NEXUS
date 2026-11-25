"""Cloud Services & Asset Management: the governance register on top of the collected inventory.

An asset is a VM (vm_inventory) or any other cloud resource (cloud_resources), identified by provider + resource ID.
- AssetDetail: technical details collected read-only from the clouds (hostname, guest OS, vCPU, memory, NICs, disks,
  cloud-native backup). Overwritten by every sync; a field a provider did not return is NULL with the reason in `gaps`.
- AssetMetadata: business metadata maintained by people (SPOC, manager, department, CIA, PII, Commvault, ...).
  Never written by any sync; every change is kept in AssetMetadataHistory (append-only).
- AssetActivitySnapshot: one row per asset per day (classification, state, IPs) - the activity history.
- AssetInventoryChange: append-only record of changes the sync observed (state, IP, size, OS, backup, ...).
- AssetPolicy: configurable thresholds (activity classification, notifications)."""
from __future__ import annotations

import hashlib
from datetime import date, datetime

from sqlalchemy import Date, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow

# Manual (business) fields: (column, label, kind, allowed values or None)
MANUAL_FIELDS: list[tuple[str, str, str, tuple[str, ...] | None]] = [
    ("server_spoc_name", "Server SPOC", "text", None),
    ("server_spoc_email", "Server SPOC e-mail", "email", None),
    ("reporting_manager_name", "Reporting Manager", "text", None),
    ("reporting_manager_email", "Reporting Manager e-mail", "email", None),
    ("department", "Department", "text", None),
    ("asset_owner", "Asset Owner", "text", None),
    ("asset_owner_email", "Asset Owner e-mail", "email", None),
    ("business_purpose", "Business Purpose", "text", None),
    ("description", "Description", "text", None),
    ("asset_classification", "Asset Classification", "choice", ("Public", "Internal", "Confidential", "Restricted")),
    ("environment_classification", "Classification", "choice", ("Production", "UAT", "Development", "Test", "POC", "DR")),
    ("confidentiality", "Confidentiality", "choice", ("Low", "Medium", "High")),
    ("integrity", "Integrity", "choice", ("Low", "Medium", "High")),
    ("availability", "Availability", "choice", ("Low", "Medium", "High")),
    ("pii_classification", "PII", "choice", ("No PII", "PII", "Sensitive PII")),
    ("business_timeline", "Timeline", "text", None),
    ("planned_end_date", "Planned End Date", "date", None),
    ("commvault_backup_status", "Commvault Backup Status", "choice", ("Protected", "Not protected", "Failed", "Not applicable", "Unknown")),
    ("notes", "Notes", "text", None),
]
MANUAL_COLUMNS = tuple(c for c, _, _, _ in MANUAL_FIELDS)


def resource_key(provider: str, resource_id: str) -> str:
    """Stable, case-insensitive key (resource IDs can be 1,000+ characters; indexes need a fixed length)."""
    return hashlib.sha256(f"{provider}|{(resource_id or '').strip().lower()}".encode()).hexdigest()


class AssetMetadata(TimestampMixin, Base):
    __tablename__ = "asset_metadata"
    __table_args__ = (UniqueConstraint("resource_key", name="uq_asset_metadata_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(16), index=True)
    scope_external_id: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str] = mapped_column(Text)
    server_spoc_name: Mapped[str | None] = mapped_column(String(255))
    server_spoc_email: Mapped[str | None] = mapped_column(String(255), index=True)
    reporting_manager_name: Mapped[str | None] = mapped_column(String(255))
    reporting_manager_email: Mapped[str | None] = mapped_column(String(255))
    department: Mapped[str | None] = mapped_column(String(255), index=True)
    asset_owner: Mapped[str | None] = mapped_column(String(255))
    asset_owner_email: Mapped[str | None] = mapped_column(String(255))
    business_purpose: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    asset_classification: Mapped[str | None] = mapped_column(String(32))
    environment_classification: Mapped[str | None] = mapped_column(String(32))
    confidentiality: Mapped[str | None] = mapped_column(String(16))
    integrity: Mapped[str | None] = mapped_column(String(16))
    availability: Mapped[str | None] = mapped_column(String(16))
    pii_classification: Mapped[str | None] = mapped_column(String(32))
    business_timeline: Mapped[str | None] = mapped_column(String(255))
    planned_end_date: Mapped[date | None] = mapped_column(Date)
    commvault_backup_status: Mapped[str | None] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(String(255))


@make_immutable
class AssetMetadataHistory(Base):
    __tablename__ = "asset_metadata_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    field: Mapped[str] = mapped_column(String(64))
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16), default="ui")  # ui | import
    changed_by: Mapped[str] = mapped_column(String(255))
    changed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AssetDetail(TimestampMixin, Base):
    __tablename__ = "asset_details"
    __table_args__ = (UniqueConstraint("resource_key", name="uq_asset_details_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(16), index=True)
    scope_external_id: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str] = mapped_column(Text)
    hostname: Mapped[str | None] = mapped_column(String(255))
    guest_os: Mapped[str | None] = mapped_column(String(255))
    guest_os_source: Mapped[str | None] = mapped_column(String(64))
    cpus: Mapped[int | None] = mapped_column(Integer)
    memory_gb: Mapped[float | None] = mapped_column(Float)
    nic_count: Mapped[int | None] = mapped_column(Integer)
    provisioned_gb: Mapped[float | None] = mapped_column(Float)
    native_backup_status: Mapped[str | None] = mapped_column(String(32))   # Protected | Not protected | Snapshot schedule | (NULL = not collected)
    native_backup_last_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    native_backup_detail: Mapped[str | None] = mapped_column(String(512))
    created_at_provider: Mapped[datetime | None] = mapped_column(UTCDateTime)
    collected_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    gaps: Mapped[dict] = mapped_column(JSONType, default=dict)            # field -> reason it was not collected


class AssetActivitySnapshot(Base):
    __tablename__ = "asset_activity_snapshots"
    __table_args__ = (UniqueConstraint("resource_key", "day", name="uq_asset_activity_day"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    day: Mapped[date] = mapped_column(Date, index=True)
    classification: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str | None] = mapped_column(String(64))
    cpu_avg: Mapped[float | None] = mapped_column(Float)
    network_mb_per_day: Mapped[float | None] = mapped_column(Float)
    last_activity_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    snapshot: Mapped[dict] = mapped_column(JSONType, default=dict)       # private/public IP, size, OS ... for change detection
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


@make_immutable
class AssetInventoryChange(Base):
    __tablename__ = "asset_inventory_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    field: Mapped[str] = mapped_column(String(64))
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(32))  # asset_details_sync | asset_activity_review


class AssetPolicy(TimestampMixin, Base):
    __tablename__ = "asset_policy"
    __table_args__ = (UniqueConstraint("key", name="uq_asset_policy_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[dict] = mapped_column(JSONType, default=dict)
    updated_by: Mapped[str | None] = mapped_column(String(255))
