#!/usr/bin/env node
// Offline readiness smoke, without target traffic or external navigation.
const puppeteer = require('puppeteer-core');
const executablePath = process.env.CHROMIUM || '/usr/bin/chromium';
let browser;
const deadline = setTimeout(() => {
  console.error('browser_smoke_timeout');
  process.exit(124);
}, 18000);
(async () => {
  try {
    browser = await puppeteer.launch({
      executablePath, headless: true,
      args: [
        '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
        '--disable-background-networking', '--disable-extensions',
        '--no-first-run', '--disable-component-update',
        '--renderer-process-limit=2',
      ],
    });
    const page = await browser.newPage();
    await page.goto('about:blank');
    await page.setContent('<html><body><main id="ready">ndt-browser-ready</main></body></html>');
    const value = await page.$eval('#ready', el => el.textContent);
    if (value !== 'ndt-browser-ready') throw new Error('browser_render_mismatch');
    console.log('browser_smoke=ok executable=' + executablePath);
    await page.close();
  } catch (e) {
    console.error('browser_smoke=error type=' + (e && e.name || 'Unknown'));
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close().catch(() => {});
    clearTimeout(deadline);
  }
})();
