# LV NEXUS redesign – Phase A: design tokens, themes, shell (24 Nov 2026)

## Changed
- `src/theme/tokens.css`: palette of the brief. Light: page #F5F7FB, sidebar/cards #FFFFFF, text #172033 / #64748B,
  border #E2E8F0, primary #2563EB, teal #0F766E. Dark: page #0B1220, sidebar #101A2B, cards #142033, text #F1F5F9 / #A3B2C7,
  border #29374B, primary #60A5FA, teal #2DD4BF. Semantic scale critical / high / medium / low / healthy / unknown
  (`--critical --serious --warning --low --good --unknown`), type scale (`--fs-page 26`, `--fs-section 20`, `--fs-card 15`,
  `--fs-kpi 30`, `--fs-body 14`), `--brand-gradient` for white-on-colour fills (≥ 4.5:1).
- `src/theme/theme.ts`: Light / Dark / System preference (default System, follows the OS live); stored only as the
  preference name under the existing `cn-theme` key.
- Shell (`src/layouts/AppLayout.tsx`): the 12 sections of the brief (Executive Overview, Cloud Accounts, Security Center,
  Live Cloud Activity, Identity & Access, Cloud Resources, Infrastructure Health, FinOps, Governance & Compliance,
  Reports & Alerts, Integrations, Administration); collapsible groups (open state kept for the session), collapsed icon
  rail, one active entry per URL (longest match), white sidebar in light theme; header with global search, data
  freshness chip (oldest last successful collection of the enabled clouds, from `/sync/status`; amber > 6 h or failing,
  red > 24 h or never), assistant, notifications, theme menu, settings, user menu.
- Branding: product name LV NEXUS everywhere in the UI; `ProductLogo` shows the official LV NEXUS logo file when present
  in `public/brand/`, otherwise the product mark + text; company line uses the official LatentView Analytics logo file
  when present. No logo is drawn or approximated.
- Status pills, page / card titles use the new tokens and type scale.

## Validated (this environment)
- `tsc -b`, `vite build`, `oxlint` (0 errors).
- Playwright sweep of 33 routes in the new shell: every page renders its heading, no JavaScript errors, exactly one
  active navigation entry per page (including tab sub-pages). Light, dark and system themes; mobile drawer at 390 px.
- Expected 404s: the four logo file probes in `/brand/` until the official files are added.

## Not changed
- No backend change, no API change, authentication and RBAC untouched. Pages keep their content (redesigned in later phases).

## Waiting for
- Official logo files (see `public/brand/README.txt`) for Phase B (3D login).
