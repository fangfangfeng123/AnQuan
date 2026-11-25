const { chromium } = require('C:/Users/Administrator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');

const OUT = 'E:/xuexi/AnQuan/AnQuanPingGu/docs/acceptance-screenshots';
const PROJECT = '01M201GPJ5PT8ZAM9QCMRATZE8';

async function shot(page, name) {
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false });
}

async function scrollToText(page, text, block = 'start') {
  const found = await page.evaluate((needle) => {
    const nodes = Array.from(document.querySelectorAll('h1,h2,h3,h4,div,span,strong,th'));
    const node = nodes.find((el) => {
      const own = el.childNodes.length === 1 && el.textContent;
      return own && own.trim() === needle;
    });
    if (!node) return false;
    node.scrollIntoView({ behavior: 'instant', block: 'start' });
    return true;
  }, text);
  if (!found) throw new Error(`scroll target not found: ${text}`);
  await page.waitForTimeout(800);
  return found;
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  await page.goto('http://127.0.0.1:8080', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    localStorage.setItem('sec_auth_token', 'admingly:admin:dev-api-token-change-in-production');
  });
  await page.goto(`http://127.0.0.1:8080/projects/${PROJECT}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(3500);

  const body = await page.evaluate(() => document.body.innerText);
  console.log('has_current_task=' + body.includes('任务 ID'));

  await page.waitForTimeout(500);
  await shot(page, '01-评估工作台总览');

  await scrollToText(page, '环境侦察结果');
  await shot(page, '02-技术栈识别与环境配置');

  await scrollToText(page, '漏洞列表');
  await shot(page, '03-漏洞列表与验证状态');

  const row = page.locator('.ant-table-row').filter({ hasText: '命令注入' }).filter({ hasText: '已验证' }).first();
  console.log('verified_row_count=' + await row.count());
  await row.locator('.ant-table-row-expand-icon').click();
  await page.waitForTimeout(1800);
  await scrollToText(page, '污点入口 → 危险汇聚点');
  await shot(page, '04-污点入口汇聚点与动态证据');

  await scrollToText(page, '智能修复补丁');
  await page.waitForTimeout(500);
  await shot(page, '05-Diff修复补丁');

  await scrollToText(page, '攻击链拓扑');
  await shot(page, '06-攻击链拓扑');

  await scrollToText(page, '五阶段流水线');
  await shot(page, '07-流水线实时日志');

  await page.goto('http://127.0.0.1:8080/reports', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await shot(page, '08-报告中心列表');

  const preview = page.getByRole('button', { name: /预览/ }).first();
  await preview.click();
  await page.waitForTimeout(2000);
  await scrollToText(page, '执行摘要');
  await shot(page, '09-报告预览与导出');

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
