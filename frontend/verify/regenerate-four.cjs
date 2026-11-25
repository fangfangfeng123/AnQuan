const { chromium } = require('C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');

const OUT = 'E:/xuexi/AnQuan/AnQuanPingGu/6组--赵瑞立';
const PROJECT = '01M201GPJ5PT8ZAM9QCMRATZE8';

async function shot(page, name) {
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false });
  console.log('saved ' + name);
}

async function findText(page, text) {
  const found = await page.evaluate((needle) => {
    const nodes = Array.from(document.querySelectorAll('h1,h2,h3,h4,div,span,strong,th'));
    const target = nodes.find((el) => el.childNodes.length === 1 && el.textContent && el.textContent.trim() === needle);
    if (!target) return false;
    target.scrollIntoView({ behavior: 'instant', block: 'start' });
    return true;
  }, text);
  if (!found) throw new Error('text not found: ' + text);
  await page.waitForTimeout(700);
}

async function main() {
  const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto('http://127.0.0.1:8080', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => localStorage.setItem('sec_auth_token', 'admingly:admin:dev-api-token-change-in-production'));
  await page.goto(`http://127.0.0.1:8080/projects/${PROJECT}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2500);

  const sizeChanger = page.locator('.ant-pagination-options-size-changer');
  await sizeChanger.click();
  await page.getByText('100 条/页', { exact: true }).click();
  await page.waitForTimeout(1500);
  const row = page.locator('.ant-table-row').filter({ hasText: '命令注入' }).filter({ hasText: '已验证' }).first();
  await row.locator('.ant-table-row-expand-icon').click();
  await page.waitForTimeout(1500);

  await findText(page, '污点传播路径');
  await shot(page, '补齐_01_污点传播路径');
  await findText(page, '动态验证证据');
  await shot(page, '补齐_02_成功验证');

  await page.goto('http://127.0.0.1:8080/reports', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.getByRole('button', { name: /预览/ }).first().click();
  await page.waitForTimeout(1800);
  await findText(page, '整体风险');
  await shot(page, '补齐_03_报告中心预览与导出');

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
