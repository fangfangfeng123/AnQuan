const { chromium } = require('C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const OUT = 'E:/xuexi/AnQuan/AnQuanPingGu/6组--赵瑞立';
const PROJECT = '01M201GPJ5PT8ZAM9QCMRATZE8';

async function waitText(page, text, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await page.evaluate((needle) => document.body.innerText.includes(needle), text)) return true;
    await page.waitForTimeout(1000);
  }
  return false;
}

async function main() {
  const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto('http://127.0.0.1:8080', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => localStorage.setItem('sec_auth_token', 'admingly:admin:dev-api-token-change-in-production'));
  await page.goto(`http://127.0.0.1:8080/projects/${PROJECT}`, { waitUntil: 'networkidle' });
  const ready = await waitText(page, '处理器使用率', 120000);
  console.log('resource_ready=' + ready);
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/补齐_04_实时资源消耗.png` });
  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
