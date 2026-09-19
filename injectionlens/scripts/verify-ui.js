// UI verification: drive the real app in headless Chrome, run an analysis, screenshot.
const { chromium } = require('playwright-core');
const fs = require('fs');

const CHROME = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].find((p) => fs.existsSync(p));

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto('http://localhost:7100', { waitUntil: 'networkidle' });
  await page.screenshot({ path: 'shots/01-initial.png' });

  // pick the white-on-white + comment attack fixture and analyze
  await page.selectOption('select', '/fixtures/attack-hidden-whitewhite-comment.html');
  await page.click('button.analyze');
  await page.waitForSelector('.finding', { timeout: 60000 });
  await page.waitForTimeout(800);
  await page.screenshot({ path: 'shots/02-findings.png', fullPage: false });

  // click the first (critical) finding to trigger node highlight in human view
  await page.click('.finding >> nth=0');
  await page.waitForTimeout(1200);
  await page.screenshot({ path: 'shots/03-highlight.png' });

  // switch to reader/markdown tab
  await page.click('button:has-text("Reader/Markdown")');
  await page.waitForTimeout(400);
  await page.screenshot({ path: 'shots/04-reader.png' });

  // full page with matrix
  await page.click('button:has-text("Human view")');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/05-matrix.png' });

  // cloaking fixture
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.selectOption('select', '/fixtures/cloaking.html');
  await page.click('button.analyze');
  await page.waitForSelector('.cloak-banner', { timeout: 60000 });
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/06-cloaking.png' });

  console.log('JS errors:', errors.length ? errors : 'none');
  await browser.close();
})();
