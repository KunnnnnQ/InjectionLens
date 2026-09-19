// Shared headless Chrome instance (system Chrome via playwright-core — no browser download needed)
const { chromium } = require('playwright-core');

const CHROME_CANDIDATES = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
];

const fs = require('fs');
const executablePath = CHROME_CANDIDATES.find((p) => fs.existsSync(p));

if (!executablePath) {
  console.warn('[InjectionLens] No system Chrome/Edge found. Rendered-DOM and accessibility-tree pipelines will fail.');
}

let browserPromise = null;

function getBrowser() {
  if (!browserPromise) {
    browserPromise = chromium.launch({ executablePath, headless: true }).catch((err) => {
      browserPromise = null;
      throw err;
    });
  }
  return browserPromise;
}

async function withPage(fn) {
  const browser = await getBrowser();
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    return await fn(page, context);
  } finally {
    await context.close().catch(() => {});
  }
}

module.exports = { getBrowser, withPage, executablePath };
