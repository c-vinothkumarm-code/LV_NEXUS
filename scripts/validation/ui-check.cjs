// UI/UX evidence: screenshots (light, dark, phone, tablet), console errors, WCAG 2 A/AA scan (axe-core),
// sign-in / sign-out flow and login-animation cost. Read-only: it only views pages.
//
//   cd frontend && npm i --no-save playwright axe-core && npx playwright install chromium
//   node ../scripts/validation/ui-check.cjs http://localhost:8000 ../evidence/ui
//
// The sign-in steps assume AUTH_MODE=dev. With Entra ID, sign in once in the opened browser instead.
const { chromium, devices } = require('playwright')
const fs = require('fs'), path = require('path')
const [base = 'http://localhost:8000', outDir = 'ui-evidence'] = process.argv.slice(2)
const axe = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8')
const pages = ['', 'dashboard', 'inventory', 'finops', 'soc', 'monitoring', 'automation', 'governance', 'reports', 'notifications', 'access']
fs.mkdirSync(outDir, { recursive: true })
;(async () => {
  const b = await chromium.launch(); const report = { base, at: new Date().toISOString(), errors: [], axe: {}, timings_ms: {}, flows: {} }
  const watch = (p, tag) => { p.on('console', (m) => m.type() === 'error' && report.errors.push(`${tag}: ${m.text()}`)); p.on('pageerror', (e) => report.errors.push(`${tag}: ${e.message}`)) }
  for (const theme of ['light', 'dark']) {
    const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, bypassCSP: true })
    await ctx.addInitScript((t) => { try { localStorage.setItem('cn-theme', t) } catch {} }, theme)
    const p = await ctx.newPage(); watch(p, theme)
    for (const route of pages) {
      const t0 = Date.now(); await p.goto(`${base}/${route}`, { waitUntil: 'networkidle' }); report.timings_ms[`${theme}:${route || 'overview'}`] = Date.now() - t0
      await p.waitForTimeout(700); await p.screenshot({ path: path.join(outDir, `${theme}-${route || 'overview'}.png`), fullPage: true })
      await p.addScriptTag({ content: axe })
      report.axe[`${theme}:${route || 'overview'}`] = await p.evaluate(async () => (await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa'] })).violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length })))
    }
    await ctx.close()
  }
  for (const [name, dev] of [['phone', devices['iPhone 13']], ['tablet', devices['iPad Mini']]]) {
    const ctx = await b.newContext({ ...dev }); const p = await ctx.newPage(); watch(p, name)
    for (const route of ['', 'dashboard', 'soc', 'monitoring']) { await p.goto(`${base}/${route}`, { waitUntil: 'networkidle' }); await p.waitForTimeout(600); await p.screenshot({ path: path.join(outDir, `${name}-${route || 'overview'}.png`) }) }
    await ctx.close()
  }
  const ctx = await b.newContext({ viewport: { width: 1440, height: 900 } }); const p = await ctx.newPage(); watch(p, 'flow')
  await p.goto(base, { waitUntil: 'networkidle' })
  const menu = p.getByRole('button', { name: /admin|analyst|viewer|operator|developer/i }).first()
  if (await menu.count()) {
    await menu.click(); await p.getByRole('menuitem', { name: 'Sign out' }).click(); await p.waitForTimeout(800)
    report.flows.sign_out_shows_login = (await p.locator('#signin-title').count()) > 0
    await p.screenshot({ path: path.join(outDir, 'login.png') })
    report.flows.login_animation = await p.evaluate(() => new Promise((res) => { let f = 0; const t0 = performance.now(); const tick = () => { f++; performance.now() - t0 < 3000 ? requestAnimationFrame(tick) : res({ fps: Math.round(f / 3) }) }; requestAnimationFrame(tick) }))
    await p.reload({ waitUntil: 'networkidle' }); report.flows.still_signed_out_after_reload = (await p.locator('#signin-title').count()) > 0
  }
  fs.writeFileSync(path.join(outDir, 'ui-report.json'), JSON.stringify(report, null, 2))
  const violations = Object.values(report.axe).reduce((n, v) => n + v.length, 0)
  console.log(`pages scanned: ${Object.keys(report.axe).length}, accessibility violations: ${violations}, console errors: ${report.errors.length}`)
  await b.close(); process.exit(violations || report.errors.length ? 1 : 0)
})()
