from __future__ import annotations

from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, utcnow


class VMInventory(TimestampMixin, Base):
    __tablename__ = "vm_inventory"
    __table_args__ = (UniqueConstraint("provider", "instance_id", name="uq_vm_inventory_instance"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), index=True)
    scope_external_id: Mapped[str] = mapped_column(String(128), index=True)
    instance_id: Mapped[str] = mapped_column(String(512))
    name: Mapped[str | None] = mapped_column(String(255))
    region: Mapped[str | None] = mapped_column(String(64))
    instance_type: Mapped[str | None] = mapped_column(String(64))
    power_state: Mapped[str | None] = mapped_column(String(32))
    public_ip: Mapped[str | None] = mapped_column(String(64))
    private_ip: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str | None] = mapped_column(String(32))
    health_status: Mapped[str] = mapped_column(String(16), default="unknown")  # healthy|warning|critical|unknown
    exposed_ports: Mapped[list] = mapped_column(JSONType, default=list)
    launched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class VMMetric(Base):
    """A NULL value means the metric was unavailable. It is never reported as healthy."""

    __tablename__ = "vm_metrics"
    __table_args__ = (Index("ix_vm_metrics_vm_time", "vm_id", "collected_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vm_id: Mapped[int] = mapped_column(ForeignKey("vm_inventory.id"))
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    cpu_percent: Mapped[float | None] = mapped_column(Float)
    memory_percent: Mapped[float | None] = mapped_column(Float)
    disk_total_gb: Mapped[float | None] = mapped_column(Float)
    disk_used_gb: Mapped[float | None] = mapped_column(Float)
    disk_percent: Mapped[float | None] = mapped_column(Float)
    network_in_bytes: Mapped[float | None] = mapped_column(Float)
    network_out_bytes: Mapped[float | None] = mapped_column(Float)
    missing_metrics: Mapped[list] = mapped_column(JSONType, default=list)


class VMAlert(TimestampMixin, Base):
    __tablename__ = "vm_alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vm_id: Mapped[int] = mapped_column(ForeignKey("vm_inventory.id"), index=True)
    alert_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    message: Mapped[str | None] = mapped_column(Text)
    value: Mapped[float | None] = mapped_column(Float)
    threshold: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
