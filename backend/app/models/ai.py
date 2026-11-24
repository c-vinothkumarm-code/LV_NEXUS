"""AI Intelligence Center: conversations, agent runs, recommendations and the human approval trail for any action.

The AI reads facts through permission-checked tools. It never changes anything: a recommendation that implies a change
goes through human review -> authorized approval -> execution by a person -> verification -> audit record."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow


class AIConversation(Base):
    __tablename__ = "ai_conversations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_email: Mapped[str] = mapped_column(String(255), index=True)
    question: Mapped[str] = mapped_column(Text)
    tools: Mapped[list] = mapped_column(JSONType, default=list)     # tool names used
    facts: Mapped[list] = mapped_column(JSONType, default=list)     # evidence returned by the tools (with sources and timestamps)
    answer: Mapped[str] = mapped_column(Text)
    answer_source: Mapped[str] = mapped_column(String(16))          # template | model
    model: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AIAgentRun(Base):
    __tablename__ = "ai_agent_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent: Mapped[str] = mapped_column(String(32), index=True)
    started_by: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))                 # SUCCESS | PARTIAL | FAILED
    summary: Mapped[str] = mapped_column(Text)
    facts: Mapped[list] = mapped_column(JSONType, default=list)
    recommendations: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AIRecommendation(TimestampMixin, Base):
    __tablename__ = "ai_recommendations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("ai_agent_runs.id"), index=True)
    agent: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    category: Mapped[str] = mapped_column(String(32))
    priority: Mapped[str] = mapped_column(String(16))               # Critical | High | Medium | Low
    rationale: Mapped[str] = mapped_column(Text)                    # why (reasoning, plain words)
    evidence: Mapped[list] = mapped_column(JSONType, default=list)  # [{fact, source, as_of, link}]
    recommended_action: Mapped[str] = mapped_column(Text)
    action_type: Mapped[str | None] = mapped_column(String(32))     # none | iam_change | resource_change | budget_change | policy_change ...
    required_permission: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(16))
    dedup_key: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(24), default="PROPOSED", index=True)
    # PROPOSED | DISMISSED | ACCEPTED (no change needed) | APPROVAL_REQUESTED | APPROVED | REJECTED | EXECUTED | VERIFIED | NOT_VERIFIED
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    executed_by: Mapped[str | None] = mapped_column(String(255))
    verification: Mapped[str | None] = mapped_column(Text)


class AIActionEvent(Base):
    """Every human step on a recommendation (append-only)."""
    __tablename__ = "ai_action_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    recommendation_id: Mapped[int] = mapped_column(ForeignKey("ai_recommendations.id"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


make_immutable(AIActionEvent)
