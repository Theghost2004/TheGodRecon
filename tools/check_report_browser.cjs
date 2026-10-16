/* Optional browser verification. Requires Playwright and a local Chromium.
 * Usage: node tools/check_report_browser.cjs REPORT.html SCREENSHOT_DIRECTORY [EMPTY_REPORT.html]
 * RECONMAP_PLAYWRIGHT_MODULE and RECONMAP_CHROMIUM may select existing installs.
 * Report HTML is read locally; no target/provider URL is navigated or loaded.
 */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.RECONMAP_PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const [report, directory, emptyReport] = process.argv.slice(2);
  assert(report && directory, 'Provide the loopback workflow report and a new screenshot directory');
  fs.mkdirSync(path.dirname(path.resolve(directory)), { recursive: true });
  fs.mkdirSync(directory); // Preserve screenshots from earlier verification runs.
  const browser = await chromium.launch({ headless: true, ...(process.env.RECONMAP_CHROMIUM ? { executablePath: process.env.RECONMAP_CHROMIUM } : {}) });
  const checks = [], errors = [], external = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    page.on('pageerror', error => errors.push(String(error)));
    page.on('console', message => { if(message.type() === 'error') errors.push(message.text()); });
    await page.route(/https?:\/\//, route => { external.push(route.request().url()); return route.abort(); });
    await page.setContent(fs.readFileSync(report, 'utf8'));
    const visible = () => page.locator('[data-record]:visible');
    const select = (id, value) => page.locator('#' + id).selectOption(value);
    async function reset() {
      await page.locator('#search').fill('');
      for (const id of ['filter', 'status', 'confidence', 'source']) await select(id, '');
      await page.locator('#priority').fill('');
    }
    async function check(name, action) { await action(); checks.push(name); }
    await check('four primary views', async () => {
      for (const label of ['Live Assets', 'Interesting Endpoints', 'Potential Exposures', 'All Results'])
        assert.equal(await page.locator('h2').filter({ hasText: label }).count(), 1);
    });
    await page.screenshot({ path: path.join(directory, 'overview.png') });
    await check('static asset absent from shortlist', async () => {
      await select('filter', 'Interesting Endpoints');
      await page.locator('#search').fill('adminlte');
      assert.equal(await visible().count(), 0);
      assert.equal(await page.locator('#filter-summary').innerText(), '0 matching records');
    });
    await check('inventory search reveals collapsed matches', async () => {
      await select('filter', 'All Results');
      assert.equal(await visible().count(), 1);
      assert.equal(await page.locator('#filter-summary').innerText(), '1 matching record');
      assert.equal(await page.locator('[data-view]:visible').count(), 1);
    });
    await check('unknown query gives an explicit empty state', async () => {
      await page.locator('#search').fill('no-such-value-7d81');
      assert.equal(await visible().count(), 0);
      assert.equal(await page.locator('[data-view]:visible').count(), 0);
      assert.equal(await page.locator('#filter-summary').innerText(), '0 matching records');
    });
    await check('reset preserves default collapsed inventory', async () => {
      await reset();
      assert.equal(await page.locator('#all-results > details').getAttribute('open'), null);
      assert.equal(await page.locator('[data-view][hidden]').count(), 0);
    });
    await check('correlated exposure and inspectable supporting evidence', async () => {
      await select('filter', 'Potential Exposures');
      await page.locator('#search').fill('.git/HEAD');
      assert.equal(await visible().count(), 1);
      const card = visible().first();
      await card.locator(':scope > summary').click();
      await card.locator('details > summary').click();
      assert(await card.locator('pre').isVisible());
      assert((await card.locator('pre').innerText()).includes('observation_id'));
      await card.locator('details > summary').click();
      await page.screenshot({ path: path.join(directory, 'exposure.png'), fullPage: true });
      await card.locator(':scope > summary').click();
    });
    await check('individual source filters include correlated records', async () => {
      await reset();
      const source = await page.evaluate(() => {
        const rows = JSON.parse(document.getElementById('data').textContent);
        return rows.find(r => r.section === 'All Results' && r.sources?.length > 1)?.sources[0];
      });
      assert(source, 'Fixture must have correlated sources');
      await select('filter', 'All Results');
      await select('source', source);
      assert(await visible().count() > 0);
      assert(await page.evaluate(value => {
        const rows = JSON.parse(document.getElementById('data').textContent);
        return [...document.querySelectorAll('[data-record]:not([hidden])')].every(el => rows[Number(el.dataset.record)].sources.includes(value));
      }, source));
    });
    await check('confidence and priority filters show observed login', async () => {
      await reset();
      await select('filter', 'Interesting Endpoints');
      await select('confidence', 'high');
      await page.locator('#priority').fill('60');
      assert.equal(await visible().count(), 1);
      assert((await visible().first().innerText()).includes('/admin/login'));
    });
    await check('restricted surfaces retain manual review labels', async () => {
      await reset();
      await select('filter', 'Interesting Endpoints');
      await select('status', 'restricted');
      assert(await visible().count() > 0);
      await visible().first().locator(':scope > summary').click();
      assert((await visible().first().innerText()).includes('not an access-control failure'));
      await visible().first().locator(':scope > summary').click();
    });
    await check('secondary evidence filters reveal nested rows', async () => {
      await reset();
      await select('filter', 'observations');
      await page.locator('#search').fill('/api/users/1');
      assert(await visible().count() > 0);
      assert(await page.locator('[data-collection-details]').getAttribute('open') !== null);
    });
    await check('navigation reveals selected inventory', async () => {
      await reset();
      await page.locator('nav a').filter({ hasText: 'All Results' }).click();
      assert.equal(await page.locator('#filter').inputValue(), 'All Results');
      assert(await visible().count() > 0);
    });
    await reset();
    await select('filter', 'Interesting Endpoints');
    await visible().filter({ hasText: '/admin/login' }).first().locator(':scope > summary').click();
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: path.join(directory, 'shortlist.png'), fullPage: true });
    await check('narrow viewport has no horizontal overflow', async () => {
      await page.setViewportSize({ width: 390, height: 844 });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({ path: path.join(directory, 'mobile.png'), fullPage: true });
    });
    if(emptyReport) await check('empty partial report filters without errors', async () => {
      await page.goto('about:blank');
      await page.setContent(fs.readFileSync(emptyReport, 'utf8'));
      await select('filter', 'All Results');
      assert.equal(await visible().count(), 0);
      assert.equal(await page.locator('#filter-summary').innerText(), '0 matching records');
      await page.locator('#search').fill('no-such-value');
      assert.equal(await visible().count(), 0);
    });
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    checks.push('zero browser errors', 'zero external requests');
    const result = { browser: await browser.version(), mode: 'headless local HTML setContent', report: path.resolve(report), checks, errors, external_requests: external };
    fs.writeFileSync(path.join(directory, 'verification.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
