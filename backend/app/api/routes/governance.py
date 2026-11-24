"""Governance & Compliance API: frameworks, controls (pass rates from native findings), evidence, exceptions view,
and the cloud onboarding governance workflow. Pass rates are not certifications."""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from datetime import UTC, date, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import log_action, require_any
from app.api.serializers import iso
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, CloudSecurityFinding, FindingException, User
from app.models.governance import ComplianceControl, ComplianceFramework, ControlEvidence, GovernanceAuditEvent, OnboardingRequest

router = APIRouter(prefix="/api/v1/governance", tags=["governance and compliance"])
DISCLAIMER = ("Control pass rates are calculated from native cloud security findings and attached evidence. They are not an audit opinion or a "
              "certification; LV NEXUS does not claim compliance with any framework.")
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")


def _audit(db: Session, actor: str, entity: str, entity_id: int | None, action: str, **detail) -> None:
    db.add(GovernanceAuditEvent(entity=entity, entity_id=entity_id, action=action, actor=actor,
                                detail={k: (v.isoformat() if isinstance(v, date) else v) for k, v in detail.items()}))


# ------------------------------------------------------------------ frameworks discovered from findings
def sync_native_frameworks(db: Session, actor: str = "system") -> int:
    """Each distinct compliance standard reported by the providers (e.g. CIS AWS Foundations, NIST 800-53 in Security Hub)
    becomes a native framework, and each control ID it reports becomes a control. Titles come from the findings."""
    created = 0
    rows = db.execute(select(CloudSecurityFinding.compliance_standard, CloudSecurityFinding.control_id, func.min(CloudSecurityFinding.title))
                      .where(CloudSecurityFinding.compliance_standard.is_not(None), CloudSecurityFinding.control_id.is_not(None))
                      .group_by(CloudSecurityFinding.compliance_standard, CloudSecurityFinding.control_id)).all()
    fws = {f.match_standard: f for f in db.scalars(select(ComplianceFramework).where(ComplianceFramework.source == "native"))}
    for standard, control, title in rows:
        for std in [s.strip() for s in standard.split(",") if s.strip()]:
            fw = fws.get(std)
            if fw is None:
                key = re.sub(r"[^a-z0-9]+", "-", std.lower()).strip("-")[:60] or "standard"
                fw = ComplianceFramework(key=f"native-{key}", name=std.rsplit("/", 1)[-1].replace("-", " ").strip() or std, source="native",
                                         match_standard=std, created_by=actor)
                db.add(fw)
                db.flush()
                fws[std] = fw
            if not db.scalar(select(ComplianceControl.id).where(ComplianceControl.framework_id == fw.id, ComplianceControl.control_id == control)):
                db.add(ComplianceControl(framework_id=fw.id, control_id=control, title=(title or control)[:512], mapped_control_ids=[control]))
                created += 1
    return created


def _control_findings(db: Session, fw: ComplianceFramework, c: ComplianceControl) -> tuple[list, list]:
    """(active failing findings, resolved / passing findings) mapped to this control."""
    q = select(CloudSecurityFinding)
    conds = []
    if c.mapped_control_ids:
        conds.append(CloudSecurityFinding.control_id.in_(c.mapped_control_ids))
    for kw in c.mapped_keywords or []:
        conds.append(CloudSecurityFinding.title.ilike(f"%{kw}%"))
        conds.append(CloudSecurityFinding.category.ilike(f"%{kw}%"))
    if not conds:
        return [], []
    from sqlalchemy import or_
    q = q.where(or_(*conds))
    if fw.source == "native" and fw.match_standard:
        q = q.where(CloudSecurityFinding.compliance_standard.ilike(f"%{fw.match_standard}%"))
    rows = list(db.scalars(q.limit(5000)))
    failing = [f for f in rows if f.native_state == "ACTIVE" and f.internal_status in OPEN]
    other = [f for f in rows if f not in failing]
    return failing, other


def control_status(db: Session, fw: ComplianceFramework, c: ComplianceControl) -> dict:
    failing, other = _control_findings(db, fw, c)
    excepted = [f for f in other if f.native_state == "ACTIVE" and f.internal_status == "EXCEPTION"]
    evidence = db.scalar(select(func.count()).select_from(ControlEvidence).where(ControlEvidence.control_id == c.id)) or 0
    if failing:
        status = "FAIL"
    elif other:
        status = "PASS"
    elif c.manual_status in ("PASS", "FAIL") and evidence:
        status = c.manual_status
    else:
        status = "NOT_ASSESSED"
    return {"id": c.id, "control_id": c.control_id, "title": c.title, "description": c.description, "status": status,
            "failing_findings": len(failing), "assessed_findings": len(failing) + len(other), "excepted": len(excepted),
            "evidence": evidence, "owner": c.owner, "remediation_owner": c.remediation_owner, "review_date": iso(c.review_date),
            "review_overdue": bool(c.review_date and c.review_date < date.today()), "mapped_control_ids": c.mapped_control_ids,
            "mapped_keywords": c.mapped_keywords, "basis": "native findings" if failing or other else ("evidence" if status != "NOT_ASSESSED" else None)}


def framework_summary(db: Session, fw: ComplianceFramework) -> dict:
    controls = [control_status(db, fw, c) for c in db.scalars(select(ComplianceControl).where(ComplianceControl.framework_id == fw.id))]
    assessed = [c for c in controls if c["status"] != "NOT_ASSESSED"]
    passed = sum(1 for c in assessed if c["status"] == "PASS")
    return {"id": fw.id, "key": fw.key, "name": fw.name, "version": fw.version, "source": fw.source, "owner": fw.owner, "enabled": fw.enabled,
            "controls": len(controls), "assessed": len(assessed), "passed": passed, "failed": sum(1 for c in assessed if c["status"] == "FAIL"),
            "not_assessed": len(controls) - len(assessed), "pass_rate": round(100 * passed / len(assessed), 1) if assessed else None}


@router.get("/frameworks")
def frameworks(db: Session = Depends(get_db), user: User = Depends(require("onboarding:read"))):
    sync_native_frameworks(db)
    db.commit()
    return {"items": [framework_summary(db, f) for f in db.scalars(select(ComplianceFramework).order_by(ComplianceFramework.source, ComplianceFramework.name))],
            "disclaimer": DISCLAIMER}


@router.get("/frameworks/{fw_id}")
def framework_detail(fw_id: int, db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    fw = db.get(ComplianceFramework, fw_id)
    if fw is None:
        raise HTTPException(404, "Framework not found")
    return {**framework_summary(db, fw), "disclaimer": DISCLAIMER,
            "control_list": [control_status(db, fw, c) for c in db.scalars(select(ComplianceControl).where(ComplianceControl.framework_id == fw.id)
                                                                             .order_by(ComplianceControl.control_id))]}


class FrameworkImport(BaseModel):
    key: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=255)
    version: str | None = None
    owner: str | None = None
    csv_text: str = Field(min_length=10, max_length=2_000_000)


@router.post("/frameworks", status_code=201)
def import_framework(body: FrameworkImport, db: Session = Depends(get_db), user: User = Depends(require("governance:manage"))):
    """Import controls for ISO 27001, SOC 2, an internal standard, etc. Columns: control_id, title, description,
    mapped_control_ids (semicolon list of native control IDs), mapped_keywords (semicolon list), owner, review_date (YYYY-MM-DD).
    Control text is supplied by your organisation (licensed standards are not shipped with the platform)."""
    if db.scalar(select(ComplianceFramework.id).where(ComplianceFramework.key == body.key)):
        raise HTTPException(409, "A framework with this key exists")
    fw = ComplianceFramework(key=body.key, name=body.name, version=body.version, owner=body.owner, source="custom", created_by=user.email)
    db.add(fw)
    db.flush()
    n, errors = 0, []
    for i, raw_row in enumerate(csv.DictReader(io.StringIO(body.csv_text)), start=2):
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items()}
        if not row.get("control_id") or not row.get("title"):
            errors.append({"row": i, "error": "control_id and title are required"})
            continue
        try:
            review = date.fromisoformat(row["review_date"]) if row.get("review_date") else None
        except ValueError:
            errors.append({"row": i, "error": "review_date must be YYYY-MM-DD"})
            continue
        db.add(ComplianceControl(framework_id=fw.id, control_id=row["control_id"][:128], title=row["title"][:512], description=row.get("description") or None,
                                 mapped_control_ids=[x.strip() for x in row.get("mapped_control_ids", "").split(";") if x.strip()],
                                 mapped_keywords=[x.strip() for x in row.get("mapped_keywords", "").split(";") if x.strip()],
                                 owner=row.get("owner") or None, review_date=review, updated_by=user.email))
        n += 1
    _audit(db, user.email, "framework", fw.id, "framework.imported", controls=n, errors=len(errors))
    log_action(db, user.email, "governance.framework_import", body.key)
    db.commit()
    return {"id": fw.id, "controls": n, "errors": errors}


class ControlUpdate(BaseModel):
    owner: str | None = None
    remediation_owner: str | None = None
    review_date: date | None = None
    manual_status: str | None = None
    mapped_control_ids: list[str] | None = None
    mapped_keywords: list[str] | None = None


@router.patch("/controls/{control_id}")
def update_control(control_id: int, body: ControlUpdate, db: Session = Depends(get_db), user: User = Depends(require("governance:manage"))):
    c = db.get(ComplianceControl, control_id)
    if c is None:
        raise HTTPException(404, "Control not found")
    if body.manual_status and body.manual_status not in ("PASS", "FAIL", "NOT_ASSESSED"):
        raise HTTPException(422, "manual_status must be PASS, FAIL or NOT_ASSESSED")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(c, k, v)
    c.updated_by = user.email
    _audit(db, user.email, "control", c.id, "control.updated", **{k: str(v) for k, v in changes.items()})
    db.commit()
    return control_status(db, db.get(ComplianceFramework, c.framework_id), c)


class EvidenceBody(BaseModel):
    kind: str = "link"
    reference: str = Field(min_length=3, max_length=1024)
    notes: str | None = Field(default=None, max_length=4000)


@router.get("/controls/{control_id}/evidence")
def list_evidence(control_id: int, db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    return {"items": [{"id": e.id, "kind": e.kind, "reference": e.reference, "notes": e.notes, "added_by": e.added_by, "at": iso(e.created_at)}
                      for e in db.scalars(select(ControlEvidence).where(ControlEvidence.control_id == control_id).order_by(ControlEvidence.id.desc()))]}


@router.post("/controls/{control_id}/evidence", status_code=201)
def add_evidence(control_id: int, body: EvidenceBody, db: Session = Depends(get_db), user: User = Depends(require("governance:manage"))):
    if db.get(ComplianceControl, control_id) is None:
        raise HTTPException(404, "Control not found")
    if body.kind not in ("document", "link", "finding_export", "screenshot", "note"):
        raise HTTPException(422, "kind must be document, link, finding_export, screenshot or note")
    e = ControlEvidence(control_id=control_id, kind=body.kind, reference=body.reference, notes=body.notes, added_by=user.email)
    db.add(e)
    _audit(db, user.email, "control", control_id, "evidence.added", kind=body.kind)
    db.commit()
    return {"id": e.id}


@router.get("/exceptions")
def exceptions(db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    rows = list(db.scalars(select(FindingException).order_by(FindingException.id.desc()).limit(500)))
    today = date.today()
    return {"items": [{"id": e.id, "finding_id": e.finding_id, "status": e.status, "risk_owner": e.risk_owner, "approver": e.approver,
                       "expires_at": iso(e.expires_at), "expired": e.expires_at.date() < today if e.expires_at else False,
                       "justification": e.business_justification} for e in rows],
            "by_status": dict(Counter(e.status for e in rows))}


# ------------------------------------------------------------------ onboarding governance workflow
STAGES = [("requirement", "Cloud requirement form", "governance:manage"), ("manager", "Manager approval", "access:approve"),
          ("cost", "Cost estimation", "budget:manage"), ("finance", "Entity lead / Finance approval", "budget:approve"),
          ("governance", "Cloud governance review", "governance:manage"), ("architecture", "Architecture and security review", "security:admin"),
          ("setup", "Account / subscription / project setup", "connections:manage"), ("deployment", "Repository and deployment requirements", "connections:manage"),
          ("vapt", "VAPT", "security:admin"), ("production", "Production approval", "governance:manage")]
INTERNET_CHECKS = ["WAF", "DAST", "Domain security", "TLS", "Network exposure review", "Logging and monitoring"]


class OnboardingBody(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    business_purpose: str = Field(min_length=10)
    provider: str
    environment: str
    internet_facing: bool = False
    estimated_monthly_cost_usd: float | None = Field(default=None, ge=0)


class StageBody(BaseModel):
    decision: str
    evidence: str | None = Field(default=None, max_length=1024)
    notes: str | None = Field(default=None, max_length=4000)
    scope_external_id: str | None = None
    checks: dict[str, bool] | None = None


def _onb(o: OnboardingRequest) -> dict:
    cur = o.stages[o.current_stage] if o.status == "IN_PROGRESS" and o.current_stage < len(o.stages) else None
    return {"id": o.id, "request_key": o.request_key, "title": o.title, "business_purpose": o.business_purpose, "provider": o.provider,
            "environment": o.environment, "internet_facing": o.internet_facing, "estimated_monthly_cost_usd": o.estimated_monthly_cost_usd,
            "scope_external_id": o.scope_external_id, "requester": o.requester, "stages": o.stages, "current_stage": o.current_stage,
            "waiting_for": cur["label"] if cur else None, "status": o.status, "created_at": iso(o.created_at)}


@router.get("/onboarding")
def list_onboarding(db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    return {"items": [_onb(o) for o in db.scalars(select(OnboardingRequest).order_by(OnboardingRequest.id.desc()))],
            "stages": [{"key": k, "label": label, "permission": p} for k, label, p in STAGES], "internet_checks": INTERNET_CHECKS}


@router.post("/onboarding", status_code=201)
def create_onboarding(body: OnboardingBody, db: Session = Depends(get_db), user: User = Depends(require("access:request"))):
    if body.provider not in SCOPE_MODELS:
        raise HTTPException(422, "provider must be aws, azure or gcp")
    stages = [{"key": k, "label": label, "permission": p, "status": "PENDING"} for k, label, p in STAGES]
    if body.internet_facing:
        vapt = next(s for s in stages if s["key"] == "vapt")
        vapt["checks"] = {c: False for c in INTERNET_CHECKS}
    n = (db.scalar(select(func.count()).select_from(OnboardingRequest)) or 0) + 1
    o = OnboardingRequest(request_key=f"ONB-{n:04d}", requester=user.email, stages=stages, **body.model_dump())
    db.add(o)
    db.flush()
    _audit(db, user.email, "onboarding", o.id, "onboarding.created")
    db.commit()
    return _onb(o)


def _production_blockers(db: Session, o: OnboardingRequest) -> list[str]:
    if not o.scope_external_id:
        return ["The account / subscription / project has not been linked to this request"]
    open_ = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
        CloudSecurityFinding.provider == o.provider, CloudSecurityFinding.scope_external_id == o.scope_external_id,
        CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE",
        CloudSecurityFinding.severity.in_(["Critical", "High"]), CloudSecurityFinding.internal_status.in_(OPEN))) or 0
    return [f"{open_} Critical / High security finding(s) are open without an approved exception"] if open_ else []


@router.post("/onboarding/{oid}/stage")
def decide_stage(oid: int, body: StageBody, db: Session = Depends(get_db),
                 user: User = Depends(require_any(*sorted({p for _, _, p in STAGES})))):
    o = db.get(OnboardingRequest, oid)
    if o is None:
        raise HTTPException(404, "Request not found")
    if o.status != "IN_PROGRESS":
        raise HTTPException(409, f"Request is {o.status.lower()}")
    stages = [dict(s) for s in o.stages]
    st = stages[o.current_stage]
    if st["permission"] not in user.permission_names:
        raise HTTPException(403, f"{st['label']} requires the permission {st['permission']}")
    if user.email == o.requester and st["key"] not in ("requirement", "cost", "deployment"):
        raise HTTPException(403, "The requester cannot approve their own onboarding request")
    if body.decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(422, "decision must be APPROVED or REJECTED")
    if body.decision == "REJECTED" and not (body.notes or "").strip():
        raise HTTPException(422, "Notes are required to reject")
    if body.decision == "APPROVED":
        if st["key"] == "setup":
            model = SCOPE_MODELS[o.provider]
            if not body.scope_external_id or not db.scalar(select(model.id).where(model.external_id == body.scope_external_id)):
                raise HTTPException(422, "Link the account / subscription / project, which must appear in the discovered inventory")
            o.scope_external_id = body.scope_external_id
        if st["key"] == "vapt" and "checks" in st:
            checks = {**st["checks"], **(body.checks or {})}
            st["checks"] = checks
            missing = [k for k, v in checks.items() if not v]
            if missing:
                raise HTTPException(422, f"Internet-facing requirements not confirmed: {', '.join(missing)}")
        if st["key"] in ("vapt", "production") and not body.evidence:
            raise HTTPException(422, "Attach the evidence reference (report, ticket or document)")
        if st["key"] == "production":
            blockers = _production_blockers(db, o)
            if blockers:
                raise HTTPException(409, "Not ready for production: " + "; ".join(blockers))
    st.update(status=body.decision, by=user.email, at=iso(datetime.now(UTC)), evidence=body.evidence, notes=body.notes)
    stages[o.current_stage] = st
    o.stages = stages
    if body.decision == "REJECTED":
        o.status = "REJECTED"
    else:
        o.current_stage += 1
        if o.current_stage >= len(stages):
            o.status = "APPROVED_FOR_PRODUCTION"
    _audit(db, user.email, "onboarding", o.id, f"stage.{body.decision.lower()}", stage=st["key"])
    db.commit()
    return _onb(o)


@router.get("/history")
def governance_history(db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    return {"items": [{"entity": e.entity, "entity_id": e.entity_id, "action": e.action, "actor": e.actor, "detail": e.detail, "at": iso(e.created_at)}
                      for e in db.scalars(select(GovernanceAuditEvent).order_by(GovernanceAuditEvent.id.desc()).limit(300))]}
