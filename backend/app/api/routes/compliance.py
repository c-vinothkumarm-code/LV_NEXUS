"""Compliance policy library API: scores per framework, policies with evidence, settings, attestations, audit report.

Read access follows the governance pages (onboarding:read, plus auditors through reports:export); changes need
governance:manage and are written to the audit log. Nothing here changes a cloud."""
from __future__ import annotations

import csv
import html
import io
from collections import Counter, defaultdict
from datetime import UTC, date, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import log_action, require_any
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import User
from app.models.compliance import CompliancePolicySetting, ComplianceResult, ComplianceRun
from app.services.compliance import engine
from app.services.compliance.library import BY_KEY, DOMAINS, FRAMEWORKS, LEGAL, POLICIES, UPCOMING, VOLUNTARY

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])
READ = require_any("onboarding:read", "reports:export")
DISCLAIMER = ("Scores come from automated checks over data LV NEXUS has collected from the clouds, plus attestations. They support "
              "audits and certifications; they are not a certification or a legal opinion. Confirm legal applicability with counsel.")
OBLIGATION_LABEL = {LEGAL: "Legal requirement (in force)", UPCOMING: "Legal requirement (commencing 13 May 2027)",
                    VOLUNTARY: "Voluntary framework", "internal": "Internal LatentView policy"}


def _iso(dt):
    return dt.isoformat() if dt else None


def _results(db: Session, run: ComplianceRun | None) -> dict[str, list[ComplianceResult]]:
    out = defaultdict(list)
    if run:
        for r in db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == run.id)):
            out[r.policy_key].append(r)
    return out


def _policy_row(p, eff, rows: list, setting) -> dict:
    st = engine.policy_status(rows) if rows else ("DISABLED" if not eff["enabled"] else "NOT_RUN")
    fail = [r for r in rows if r.status == "FAIL"]
    return {"key": p.key, "title": p.title, "domain": p.domain, "domain_label": DOMAINS[p.domain], "severity": eff["severity"],
            "default_severity": p.severity, "enabled": eff["enabled"], "kind": p.kind, "status": st, "why": p.why, "remediation": p.remediation,
            "frameworks": sorted(p.refs), "refs": p.refs, "params": eff["params"],
            "scopes_failing": len(fail), "scopes_passing": sum(1 for r in rows if r.status == "PASS"),
            "scopes_not_assessed": sum(1 for r in rows if r.status == "NOT_ASSESSED"), "owner": setting.owner if setting else None,
            "legal": any(FRAMEWORKS[f]["obligation"] in (LEGAL, UPCOMING) for f in p.refs),
            "attestation": None if not setting or not setting.attested_status else {
                "status": setting.attested_status, "by": setting.attested_by, "at": _iso(setting.attested_at),
                "evidence": setting.attestation_evidence, "valid_until": _iso(setting.attestation_valid_until)}}


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(READ)):
    run = engine.latest_run(db)
    res = _results(db, run)
    sets = engine.settings_map(db)
    policies = [_policy_row(p, engine.effective(p, sets.get(p.key)), res.get(p.key, []), sets.get(p.key)) for p in POLICIES]
    frameworks = [{"key": k, **fw, "obligation_label": OBLIGATION_LABEL[fw["obligation"]], **((run.scores or {}).get(k) or {} if run else {})}
                  for k, fw in FRAMEWORKS.items()]
    domains = []
    for d, label in DOMAINS.items():
        ps = [p for p in policies if p["domain"] == d and p["enabled"]]
        c = Counter(p["status"] for p in ps)
        domains.append({"key": d, "label": label, "policies": len(ps), "pass": c["PASS"], "fail": c["FAIL"], "not_assessed": c["NOT_ASSESSED"] + c["NOT_RUN"]})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    top = sorted([p for p in policies if p["status"] == "FAIL"], key=lambda p: (order.get(p["severity"], 9), -p["scopes_failing"]))
    trend = [{"run": r.id, "at": _iso(r.finished_at), **{k: (v or {}).get("score") for k, v in (r.scores or {}).items()}}
             for r in reversed(list(db.scalars(select(ComplianceRun).where(ComplianceRun.finished_at.is_not(None)).order_by(ComplianceRun.id.desc()).limit(30))))]
    c = Counter(p["status"] for p in policies if p["enabled"])
    return {"run": None if not run else {"id": run.id, "finished_at": _iso(run.finished_at), "trigger": run.trigger, "by": run.triggered_by},
            "totals": {"policies": len(POLICIES), "enabled": sum(1 for p in policies if p["enabled"]), "pass": c["PASS"], "fail": c["FAIL"],
                       "not_assessed": c["NOT_ASSESSED"] + c["NOT_RUN"]},
            "frameworks": frameworks, "domains": domains, "top_failing": top[:10], "trend": trend,
            "obligations": OBLIGATION_LABEL, "disclaimer": DISCLAIMER}


@router.get("/policies")
def policies(framework: str | None = None, domain: str | None = None, status: str | None = None,
             db: Session = Depends(get_db), _: User = Depends(READ)):
    run = engine.latest_run(db)
    res, sets = _results(db, run), engine.settings_map(db)
    rows = [_policy_row(p, engine.effective(p, sets.get(p.key)), res.get(p.key, []), sets.get(p.key)) for p in POLICIES
            if (not framework or framework in p.refs) and (not domain or p.domain == domain)]
    if status:
        rows = [r for r in rows if r["status"] == status]
    return {"items": rows, "run_at": _iso(run.finished_at) if run else None, "frameworks": {k: v["name"] for k, v in FRAMEWORKS.items()},
            "domains": DOMAINS}


@router.get("/policies/{key}")
def policy_detail(key: str, db: Session = Depends(get_db), _: User = Depends(READ)):
    p = BY_KEY.get(key)
    if p is None:
        raise HTTPException(404, "Policy not found")
    run = engine.latest_run(db)
    rows = _results(db, run).get(key, [])
    s = engine.settings_map(db).get(key)
    order = {"FAIL": 0, "NOT_ASSESSED": 1, "PASS": 2}
    return {**_policy_row(p, engine.effective(p, s), rows, s), "run_at": _iso(run.finished_at) if run else None,
            "references": [{"framework": FRAMEWORKS[f]["name"], "obligation": OBLIGATION_LABEL[FRAMEWORKS[f]["obligation"]], "items": refs}
                           for f, refs in p.refs.items()],
            "results": [{"provider": r.provider, "scope": r.scope_external_id, "scope_name": r.scope_name, "status": r.status, "detail": r.detail,
                         "evidence": r.evidence or [], "basis": r.basis, "failing": r.failing, "assessed": r.assessed}
                        for r in sorted(rows, key=lambda r: (order.get(r.status, 9), r.scope_name or ""))],
            "notes": s.notes if s else None}


class PolicyUpdate(BaseModel):
    enabled: bool | None = None
    severity: str | None = Field(default=None, pattern="^(Critical|High|Medium|Low)$")
    params: dict | None = None
    owner: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=4000)


def _setting(db: Session, key: str) -> CompliancePolicySetting:
    s = db.scalar(select(CompliancePolicySetting).where(CompliancePolicySetting.policy_key == key))
    if s is None:
        s = CompliancePolicySetting(policy_key=key, enabled=True)
        db.add(s)
    return s


@router.put("/policies/{key}")
def update_policy(key: str, body: PolicyUpdate, db: Session = Depends(get_db), user: User = Depends(require("governance:manage"))):
    p = BY_KEY.get(key)
    if p is None:
        raise HTTPException(404, "Policy not found")
    if body.params is not None:
        unknown = set(body.params) - set(p.params)
        if unknown:
            raise HTTPException(422, f"Unknown parameter(s) for {key}: {', '.join(sorted(unknown))}; allowed: {', '.join(p.params) or 'none'}")
    s = _setting(db, key)
    before = {"enabled": s.enabled, "severity": s.severity, "params": s.params, "owner": s.owner}
    for f in ("enabled", "severity", "params", "owner", "notes"):
        v = getattr(body, f)
        if v is not None:
            setattr(s, f, v)
    s.updated_by = user.email
    log_action(db, user.email, "compliance.policy.update", key, {"before": before, "after": body.model_dump(exclude_none=True)})
    db.commit()
    return policy_detail(key, db, user)


class Attestation(BaseModel):
    status: str = Field(pattern="^(PASS|FAIL)$")
    evidence: str = Field(min_length=5, max_length=1024)
    valid_until: date


@router.post("/policies/{key}/attest")
def attest(key: str, body: Attestation, db: Session = Depends(get_db), user: User = Depends(require("governance:manage"))):
    p = BY_KEY.get(key)
    if p is None:
        raise HTTPException(404, "Policy not found")
    if p.kind != "attestation":
        raise HTTPException(422, "This policy is checked automatically from cloud data; it cannot be attested")
    if body.valid_until <= date.today():
        raise HTTPException(422, "valid_until must be in the future")
    s = _setting(db, key)
    s.attested_status, s.attestation_evidence, s.attestation_valid_until = body.status, body.evidence, body.valid_until
    s.attested_by, s.attested_at, s.updated_by = user.email, datetime.now(UTC), user.email
    log_action(db, user.email, "compliance.policy.attest", key, body.model_dump(mode="json"))
    db.commit()
    return policy_detail(key, db, user)


@router.post("/evaluate")
def evaluate_now(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("governance:manage"))):
    run = engine.evaluate(db, settings, "manual", user.email)
    log_action(db, user.email, "compliance.evaluate", str(run.id), run.totals)
    db.commit()
    return {"run": run.id, "totals": run.totals, "scores": run.scores}


@router.get("/report")
def report(framework: str, format: str = "html", db: Session = Depends(get_db), user: User = Depends(READ)):
    if framework not in FRAMEWORKS:
        raise HTTPException(422, f"framework must be one of {', '.join(FRAMEWORKS)}")
    if format not in ("html", "csv"):
        raise HTTPException(422, "format must be html or csv")
    fw, run = FRAMEWORKS[framework], engine.latest_run(db)
    if run is None:
        raise HTTPException(409, "No compliance evaluation has run yet: run one from the Compliance page or wait for the scheduled run")
    res, sets = _results(db, run), engine.settings_map(db)
    score = (run.scores or {}).get(framework) or {}
    log_action(db, user.email, "compliance.report", framework, {"format": format, "run": run.id})
    db.commit()
    rows = []
    for p in [p for p in POLICIES if framework in p.refs]:
        eff = engine.effective(p, sets.get(p.key))
        for r in res.get(p.key, []) or [None]:
            rows.append([framework, "; ".join(p.refs[framework]), p.key, p.title, eff["severity"], "DISABLED" if not eff["enabled"] else (r.status if r else "NOT_RUN"),
                         r.scope_name if r else "", r.provider if r else "", (r.detail or "") if r else "",
                         " | ".join(f"{e.get('item')}: {e.get('issue')}" for e in (r.evidence or [])[:10]) if r else "", p.remediation, (r.basis or "") if r else ""])
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    head = ["Framework", "Requirement reference", "Policy", "Title", "Severity", "Result", "Scope", "Cloud", "Finding", "Evidence", "Remediation", "Basis"]
    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([f"{fw['name']} - LV NEXUS compliance evidence - run {run.id} at {run.finished_at:%Y-%m-%d %H:%M} UTC - score {score.get('score')} - coverage {score.get('coverage')}%"])
        w.writerow(head)
        w.writerows(rows)
        return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="lvnexus-{framework}-{stamp}.csv"'})
    e = html.escape
    color = {"PASS": "#067647", "FAIL": "#b42318", "NOT_ASSESSED": "#667085", "DISABLED": "#98a2b3", "NOT_RUN": "#98a2b3"}
    body = "".join("<tr>" + "".join(f"<td>{e(str(c))}</td>" if i != 5 else f'<td style="color:{color.get(c, "#344054")};font-weight:600">{e(str(c))}</td>'
                                     for i, c in enumerate(x[1:])) + "</tr>" for x in rows)
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{e(fw['name'])} - LV NEXUS compliance evidence</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;color:#101828;margin:32px}}table{{border-collapse:collapse;width:100%;font-size:12px}}
td,th{{border:1px solid #e4e7ec;padding:6px;vertical-align:top;text-align:left}}th{{background:#f2f4f7}}h1{{font-size:22px;margin:0}}
.k{{display:inline-block;margin:12px 16px 0 0}}.k b{{font-size:20px;display:block}}</style></head><body>
<div style="font-size:11px;letter-spacing:.12em;color:#475467">LATENTVIEW · LV NEXUS · COMPLIANCE EVIDENCE</div>
<h1>{e(fw['name'])}</h1><div style="color:#475467">{e(fw['version'])} · {e(OBLIGATION_LABEL[fw['obligation']])} · {e(fw['authority'])}</div>
<p style="max-width:900px">{e(fw['note'])}</p>
<div><span class="k">Score<b>{e(str(score.get('score', '–')))}{'%' if score.get('score') is not None else ''}</b></span>
<span class="k">Coverage<b>{e(str(score.get('coverage', 0)))}%</b></span><span class="k">Policies failing<b>{score.get('policies_failing', 0)}</b></span>
<span class="k">Evaluated<b style="font-size:14px">{run.finished_at:%d %b %Y %H:%M} UTC (run {run.id})</b></span>
<span class="k">Prepared for<b style="font-size:14px">{e(user.email)}</b></span></div>
<h2 style="font-size:16px;margin-top:24px">Requirements, results and evidence</h2>
<table><tr>{''.join(f'<th>{e(h)}</th>' for h in head[1:])}</tr>{body}</table>
<p style="font-size:11px;color:#667085;margin-top:16px">{e(DISCLAIMER)} Framework texts are not reproduced; references are identifiers only.</p></body></html>"""
    return Response(page, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-store"})

