# LV NEXUS redesign – Phases B to I (24 Nov 2026)

Phase A (tokens, themes, 12-section shell) is in `phase-a.md`. This round delivers the signature 3D experiences, the
executive metric system and focused upgrades of the workspaces, all on the existing APIs and data.

## B – 3D "Connected Intelligence" sign-in (`pages/login/`)
- Split screen: dark navy brand stage (left) + theme-aware sign-in panel (right).
- `ConnectedIntelligence.tsx` (three.js, lazy-loaded chunk ~5 kB + three): particles light up → nodes appear and link into a
  geometric network → the network expands into a two-shell 3D structure → data pulses travel along the links; slow
  rotation and camera drift. The centre is left empty for the logo (never drawn or morphed by the scene).
- Centre: official LV NEXUS logo file when present (`HeroLogo`), otherwise the product mark + name. Messaging: LV NEXUS ·
  Unified Multi-Cloud Control Plane · Governance. Security. Intelligence. FinOps. · Powered by LatentView Analytics.
- Panel: Welcome back, enterprise access text, the SSO providers the server reports (unchanged flow), errors, progress
  steps, session note, "Security and privacy" disclosure. No password / remember-me / forgot-password (SSO only; MFA at the IdP).
- Budget: ≤ 900 particles (300 on mobile), DPR ≤ 1.75, paused when hidden / off screen, still frame with reduced motion,
  2D canvas fallback when WebGL is missing or the context is lost; mobile shows a short simplified band above the form.

## C – Executive Overview metrics (`GET /api/v1/home/metrics`, `components/metrics.tsx`)
- `services/metrics/executive.py`: 41 metrics in 6 sections (cloud connectivity, security, infrastructure, FinOps,
  governance, activity and identity). Each metric: value, unit, definition, source, calculation, timestamp (as_of), scope,
  availability (available / not_collected / stale / failed), reason, breakdown, link, tone, note.
- Missing data is `null` + "Not collected", never 0. Stale and failed collections are labelled. Sections are filtered by the
  caller's permissions (finops:read, vuln:read, audit:read, access:read, budget:read …) on the server.
- VM states: healthy / degraded / unhealthy / stopped / unmonitored / unknown; running VMs without metrics in 2 h are
  unmonitored (never healthy).
- `MetricCard`: count-up from the previous value (jumps with reduced motion), click-through to the page behind it, ⓘ panel
  with definition / source / calculation / scope / timestamp / availability / breakdown.
- Tests: `tests/integration/test_executive_metrics.py` (empty platform = not collected; values from data; RBAC sections).

## D – Cloud topology (`components/TopologyScene.tsx`, Cloud Accounts → 3D topology)
- Built only from `/accounts/tree` (cloud → organization / management group / folder → account / subscription / project →
  region / resource group). Radial 3D layout (positions are a layout, not geography). Red / orange nodes = open critical /
  high findings. Drag to rotate, scroll to zoom, hover for counts, click to open the node in the detail panel.
- Tree view stays the default and the keyboard path; > 2,500 nodes hides the region level in 3D; no WebGL → tree.

## E – Security Center and SOC
- Finding panel: "Potential risk (posture / configuration)" vs "Threat detection: possible malicious activity — not a
  confirmed compromise until an analyst confirms it" banner. Native ID, provider payload, evidence and history were already there.
- Live activity: states plainly that sources are polled; a new event is highlighted ("new") only when it actually arrives;
  event time and collection time stay separate.

## F – Identity relationship graph (Identity & Access → click a person)
- `components/graph.tsx` `RelationGraph`: Identity → access level (role) → account → scope, from that identity's collected
  assignments only; dashed = inherited / group grants; privileged in red; expiring access in amber; keyboard-selectable nodes
  with a details panel. MFA and individual permissions are not shown because they are not collected.

## G / H – Consistency across workspaces
- Every page eyebrow uses the 12 section names; status pills, freshness and severity colours are theme tokens (correct in
  light and dark). Backend product name in e-mails, reports and messages: "LV NEXUS" / "LV NEXUS · LatentView Analytics"
  (AWS role names such as CloudNexusReadOnly are unchanged on purpose: they exist in your accounts).

## I – Validation (this environment, fictional demo data)
- Backend: 374 passed, 1 skipped; ruff clean.
- Frontend: tsc, vite build, oxlint 0 errors.
- Playwright: 36 routes × light and dark: heading rendered, exactly one active navigation entry, no JavaScript errors.
  Mobile 390 px: no horizontal overflow on Overview, Cloud Accounts, Cost, Security, Access, Onboard a cloud, Live activity.
  Reduced motion: still frame, logo visible. No WebGL: 2D fallback on sign-in, tree on Cloud Accounts, no errors.

## Not done / dependencies
- Official logo files (LatentView Analytics, LV NEXUS) not supplied: slots are ready in `public/brand/`.
- Not verified against live AWS / Azure / GCP data in this environment (demo data only).
- Deeper per-page redesigns still possible: Infrastructure VM detail pages with threshold charts, FinOps forecast charts,
  report templates with the LatentView letterhead (needs the logo), a security-resource relationship graph (needs
  resource-to-identity data that is not collected today).
- Data not collected (shown as unavailable): MFA per user, per-event processing time, VM agent health.
