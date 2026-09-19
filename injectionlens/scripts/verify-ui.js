// UI verification: drive the real app in headless Chrome, run an analysis, screenshot.
const { chromium } = require('playwright-core');
const fs = require('fs');

const CHROME = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].find((p) => fs.existsSync(p));

// An analysis runs the four pipelines plus one HTTP probe per configured
// AI-agent token (8 today), so the wait must allow for all of them.
const ANALYZE_TIMEOUT_MS = Number(process.env.VERIFY_UI_TIMEOUT_MS) || 180000;

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  await page.goto('http://127.0.0.1:7100', { waitUntil: 'networkidle' });
  await page.screenshot({ path: 'shots/01-initial.png' });

  // Start the judge-facing demo from the first screen: one click, default
  // target and default capability, no URL to type.
  await page.click('button.demo');
  await page.waitForSelector('.verdict', { timeout: ANALYZE_TIMEOUT_MS });
  await page.waitForTimeout(800);
  await page.screenshot({ path: 'shots/02-demo-verdict.png' });

  // Switching capability re-runs the real analysis; the values must change.
  await page.click('button.cap:has-text("Coding agent")');
  await page.waitForSelector('.verdict', { timeout: ANALYZE_TIMEOUT_MS });
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/03-capability-switch.png' });

  // pick the white-on-white + comment attack fixture and analyze.
  // React state updates are asynchronous, so the select needs a moment before
  // the Analyze click reads it; otherwise the click analyses the previous target.
  await page.selectOption('select', '/fixtures/attack-hidden-whitewhite-comment.html');
  await page.waitForFunction(
    () => document.querySelector('select') && document.querySelector('select').value === '/fixtures/attack-hidden-whitewhite-comment.html',
    null,
    { timeout: 10000 },
  );
  await page.waitForTimeout(300);
  await page.click('button.analyze');
  await page.waitForSelector('.finding', { timeout: ANALYZE_TIMEOUT_MS });
  await page.waitForTimeout(800);
  await page.screenshot({ path: 'shots/04-findings.png', fullPage: false });

  // click the first finding to trigger node highlight in human view
  await page.click('.finding >> nth=0');
  await page.waitForTimeout(1200);
  await page.screenshot({ path: 'shots/05-highlight.png' });

  // switch to reader/markdown tab
  await page.click('button:has-text("Reader/Markdown")');
  await page.waitForTimeout(400);
  await page.screenshot({ path: 'shots/06-reader.png' });

  // full page with matrix
  await page.click('button:has-text("Human view")');
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/07-matrix.png' });

  // cloaking fixture: the UA-conditional local pair
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.selectOption('select', '/fixtures/cloaking.html');
  await page.waitForFunction(
    () => document.querySelector('select') && document.querySelector('select').value === '/fixtures/cloaking.html',
    null,
    { timeout: 10000 },
  );
  await page.waitForTimeout(300);
  await page.click('button.analyze');
  await page.waitForSelector('.cloak-banner', { timeout: ANALYZE_TIMEOUT_MS });
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/08-cloaking.png' });

  // the P1 channel checks: the AI-summary-link and fragment replica
  await page.selectOption('select', '/fixtures/replica-ai-summary-link.html');
  await page.waitForFunction(
    () => document.querySelector('select') && document.querySelector('select').value === '/fixtures/replica-ai-summary-link.html',
    null,
    { timeout: 10000 },
  );
  await page.waitForTimeout(300);
  await page.click('button.analyze');
  await page.waitForSelector('.channel-row', { timeout: ANALYZE_TIMEOUT_MS });
  await page.waitForTimeout(600);
  await page.screenshot({ path: 'shots/09-channel-checks.png' });

  console.log('JS errors:', errors.length ? errors : 'none');
  await browser.close();
})();
