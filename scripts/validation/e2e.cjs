// LV NEXUS end-to-end UI test (Playwright). Usage, with the app running on BASE (default http://localhost:5173):
//   node scripts/validation/e2e.cjs [BASE] [report.md]
// Checks: every route renders (no console / page errors, no failed API calls, no blank page), every sidebar link,
// Back keeps filters, breadcrumbs, 404, the assistant (question, follow-up, link-through), CSV export downloads a file,
// and no decorative controls (buttons without a name, links to "#"). Writes a markdown report with each case and result.
const { chromium } = require('playwright')
const fs = require('fs')
const path = require('path')

const BASE = process.argv[2] || 'http://localhost:5173'
const REPORT = process.argv[3] || path.join(__dirname, '..', '..', 'docs', 'review', 'e2e-report.md')
const ROUTES = JSON.parse(fs.readFileSync(path.join(__dirname, 'routes.json'), 'utf8'))
const cases = []
const record = (name, expected, actual, pass, defect = '') => { cases.push({ name, expected, actual, pass, defect }); console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : ' :: ' + actual}`) }

;(async () => {
  const browser = await chromium.launch()
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true })
  const page = await ctx.newPage()
  let issues = null
  page.on('console', (m) => { if (issues && m.type() === 'error') issues.push('console: ' + m.text().slice(0, 160)) })
  page.on('pageerror', (e) => { if (issues) issues.push('page error: ' + String(e).slice(0, 160)) })
  page.on('response', (r) => { if (issues && r.url().includes('/api/') && r.status() >= 500) issues.push(`API ${r.status()} ${r.url().replace(/^https?:\/\/[^/]+/, '')}`) })
  const open = async (url) => { issues = []; await page.goto(BASE + url, { waitUntil: 'networkidle' }); await page.waitForTimeout(400); return issues }

  // 1. every route
  for (const r of ROUTES) {
    const errs = await open(r)
    const text = (await page.locator('main').innerText().catch(() => '')).trim()
    const blank = text.length < 40
    const notFound = /Page not found/.test(text)
    const ok = !errs.length && !blank && !notFound
    record(`Page ${r} renders`, 'content, no errors, no failed API calls', ok ? `ok (${text.length} chars)` : [...errs, blank ? 'blank page' : '', notFound ? 'not found' : ''].filter(Boolean).join('; '), ok)
    // decorative controls
    const dead = await page.evaluate(() => {
      const out = []
      document.querySelectorAll('main a[href="#"], main a:not([href])').forEach((a) => { if (!a.getAttribute('role')) out.push('link without target: ' + (a.textContent || '').trim().slice(0, 40)) })
      document.querySelectorAll('main button').forEach((b) => { const n = (b.getAttribute('aria-label') || b.textContent || b.title || '').trim(); if (!n) out.push('button without a name') })
      return out
    })
    if (dead.length) record(`Page ${r}: no decorative controls`, 'every button named, every link has a target', dead.slice(0, 3).join('; '), false, 'decorative control')
  }
  record('Decorative-control scan on all pages', 'no unnamed buttons / dead links', `${cases.filter((c) => c.defect === 'decorative control').length} page(s) with issues`,
    !cases.some((c) => c.defect === 'decorative control'))

  // 2. sidebar: every link leads to a working page
  await open('/')
  await page.getByRole('button', { name: /^More/ }).click().catch(() => {})
  const links = await page.locator('aside a[href^="/"]').evaluateAll((as) => [...new Set(as.map((a) => a.getAttribute('href')))])
  for (const href of links) {
    const errs = await open(href)
    const h1 = await page.locator('main h1').first().innerText().catch(() => '')
    record(`Sidebar link ${href}`, 'opens a page with a title', h1 ? `"${h1.slice(0, 50)}"` : 'no page title' + (errs.length ? '; ' + errs[0] : ''), !!h1 && !errs.length)
  }

  // 3. Back keeps filters
  await open('/vulnerabilities/findings?severity=Critical')
  await page.locator('aside a[href="/accounts"]').first().click(); await page.waitForURL('**/accounts'); await page.waitForTimeout(300)
  await page.getByRole('button', { name: 'Go back' }).click(); await page.waitForTimeout(500)
  record('Back button returns with filters', '/vulnerabilities/findings?severity=Critical', page.url().replace(BASE, ''), page.url().endsWith('/vulnerabilities/findings?severity=Critical'))
  await open('/budgets/alerts')
  await page.getByRole('button', { name: 'Go back' }).click(); await page.waitForTimeout(400)
  record('Back on a directly opened page goes to its parent', '/budgets', page.url().replace(BASE, ''), page.url().endsWith('/budgets'))
  await open('/vulnerabilities/findings')
  const crumbs = await page.locator('nav[aria-label="Breadcrumb"] ol').innerText().catch(() => '')
  record('Breadcrumbs', 'Home > Vulnerabilities > All findings', crumbs.replace(/\s+/g, ' '), /Home.*Vulnerabilities.*All findings/s.test(crumbs))
  await open('/this-page-does-not-exist')
  record('Unknown address shows a 404 page with a way back', 'Page not found + Go back + Home', (await page.locator('main').innerText()).slice(0, 60),
    await page.getByRole('button', { name: 'Go back' }).count() > 0 && await page.getByText('Page not found').count() > 0)
  for (const [old, now] of [['/dashboard', '/cost/overview'], ['/finops', '/cost/analysis'], ['/soc', '/audit'], ['/operations', '/executive'], ['/cost', '/cost/analysis'], ['/budgets/requests', '/budgets#approvals']]) {
    await open(old)
    record(`Old address ${old} redirects`, now, page.url().replace(BASE, ''), page.url().endsWith(now))
  }

  // 4. assistant
  await open('/executive')
  await page.getByRole('button', { name: /Open the LV NEXUS assistant/ }).click()
  await page.getByRole('button', { name: 'Give me the current executive overview.' }).click()
  await page.getByText('Verified data').first().waitFor({ timeout: 15000 }).catch(() => {})
  const ans = await page.locator('aside[aria-label="LV NEXUS assistant"]').innerText()
  record('Assistant answers from verified data', 'Executive overview with sources', ans.includes('Executive overview') && ans.includes('Source:') ? 'answered with sources' : ans.slice(0, 120),
    ans.includes('Executive overview') && ans.includes('Source:'))
  await page.locator('textarea[aria-label="Your question"]').fill('and for AWS only?'); await page.keyboard.press('Enter')
  await page.getByText(/Follow-up to/).first().waitFor({ timeout: 15000 }).catch(() => {})
  const fu = await page.locator('aside[aria-label="LV NEXUS assistant"]').innerText()
  record('Assistant follow-up keeps context', 'Follow-up to … AWS only', /Follow-up to .* AWS only/.test(fu) ? 'follow-up recognised' : 'not recognised', /Follow-up to .* AWS only/.test(fu))
  await page.locator('aside[aria-label="LV NEXUS assistant"] a[href="/accounts"]').first().click().catch(() => {})
  await page.waitForTimeout(500)
  record('Assistant links open the source page', '/accounts', page.url().replace(BASE, ''), page.url().endsWith('/accounts'))

  // 5. export downloads a real file
  await open('/vulnerabilities/findings')
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 15000 }).catch(() => null), page.getByRole('button', { name: 'CSV' }).first().click()])
  let size = 0
  if (dl) { const p = await dl.path(); size = p ? fs.statSync(p).size : 0 }
  record('Export to CSV downloads a file', 'non-empty CSV', dl ? `${dl.suggestedFilename()} (${size} bytes)` : 'no download', !!dl && size > 0)

  await browser.close()
  const failed = cases.filter((c) => !c.pass)
  const md = ['# End-to-end UI test report (scripts/validation/e2e.cjs)', '', `Run: ${new Date().toISOString()} against ${BASE}`, '',
    `Cases: ${cases.length}, passed: ${cases.length - failed.length}, failed: ${failed.length}`, '',
    '| # | Test case | Expected | Actual | Result | Defect |', '|---|---|---|---|---|---|',
    ...cases.map((c, i) => `| ${i + 1} | ${c.name} | ${c.expected} | ${String(c.actual).replace(/\|/g, '/')} | ${c.pass ? 'PASS' : 'FAIL'} | ${c.defect || (c.pass ? '' : 'see actual')} |`)]
  fs.mkdirSync(path.dirname(REPORT), { recursive: true })
  fs.writeFileSync(REPORT, md.join('\n') + '\n')
  console.log(`\n${cases.length - failed.length}/${cases.length} passed. Report: ${REPORT}`)
  process.exit(failed.length ? 1 : 0)
})()
