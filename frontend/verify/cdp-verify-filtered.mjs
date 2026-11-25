// 补充验证：筛选条件下（多页）点击箭头翻页是否保留筛选并正确翻页。
// 同时验证"仅 1 页时下一页被正确禁用"。仅用于本地验证。
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PAGE_URL = 'http://127.0.0.1:8099/';
const DEBUG_PORT = 9335;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROFILE = path.join(HERE, '.chrome-profile-filter');
const SHOTS = path.join(HERE, 'shots');

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} | ${name} | ${detail}`);
}

mkdirSync(SHOTS, { recursive: true });
rmSync(PROFILE, { recursive: true, force: true });

const chrome = spawn(CHROME, [
  '--headless=new', `--remote-debugging-port=${DEBUG_PORT}`, `--user-data-dir=${PROFILE}`,
  '--window-size=1600,1100', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
  '--disable-gpu', 'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getWsUrl() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
      const page = (await res.json()).find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* 等待 */ }
    await sleep(500);
  }
  throw new Error('无法连接 Chrome 调试端口');
}

const ws = new WebSocket(await getWsUrl());
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    msgId += 1;
    pending.set(msgId, { resolve, reject });
    ws.send(JSON.stringify({ id: msgId, method, params }));
  });
}
async function evaluate(expression) {
  const res = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (res.exceptionDetails) throw new Error(res.exceptionDetails.exception?.description || 'evaluate failed');
  return res.result.value;
}
async function screenshot(name) {
  const res = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(path.join(SHOTS, `${name}.png`), Buffer.from(res.data, 'base64'));
}

const PAGINATION_ROOT = `
  const homeBtn = Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('title') === '首页');
  const root = homeBtn ? homeBtn.parentElement : null;
`;

async function readPagination() {
  return evaluate(`(() => {
    ${PAGINATION_ROOT}
    if (!root) return null;
    const norm = s => (s || '').replace(/\\s+/g, '');
    const buttons = Array.from(root.querySelectorAll('button')).map(b => ({
      text: norm(b.textContent), title: b.getAttribute('title') || '',
      disabled: b.disabled, primary: b.classList.contains('ant-btn-primary'),
    }));
    const active = buttons.find(b => b.primary && /^\\d+$/.test(b.text));
    return {
      currentPage: active ? Number(active.text) : null,
      texts: Array.from(root.querySelectorAll('.ant-typography')).map(e => e.textContent.trim()).filter(Boolean),
      buttons,
      rowCount: document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length,
      lastRequest: globalThis.__lastRequest || null,
    };
  })()`);
}

async function clickButton({ title, text }) {
  const info = await evaluate(`(() => {
    ${PAGINATION_ROOT}
    if (!root) return null;
    const norm = s => (s || '').replace(/\\s+/g, '');
    const target = Array.from(root.querySelectorAll('button')).find(b =>
      ${title ? `b.getAttribute('title') === ${JSON.stringify(title)}` : `norm(b.textContent) === ${JSON.stringify(text)}`}
    );
    if (!target) return null;
    target.scrollIntoView({ block: 'center' });
    const r = target.getBoundingClientRect();
    return { x: Math.round(r.x + r.width / 2), y: Math.round(r.y + r.height / 2), disabled: target.disabled };
  })()`);
  const label = title || text;
  if (!info) throw new Error(`未找到分页按钮: ${label}`);
  if (info.disabled) return { disabled: true, label };
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: info.x, y: info.y });
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: info.x, y: info.y, button: 'left', clickCount: 1 });
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: info.x, y: info.y, button: 'left', clickCount: 1 });
  return { clicked: true, label };
}

async function waitFor(cond, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await readPagination();
    if (state && cond(state)) return state;
    await sleep(200);
  }
  return state;
}

async function pickPageSize(label) {
  await evaluate(`(() => {
    const h = Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('title') === '首页');
    h.parentElement.querySelector('.ant-select-selector').dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    return true;
  })()`);
  await sleep(700);
  const r = await evaluate(`(() => {
    const opts = Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option'));
    const t = opts.find(o => o.textContent.includes(${JSON.stringify(label)}));
    if (!t) return { error: 'not found', available: opts.map(o => o.textContent) };
    t.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    t.click();
    return { ok: true, text: t.textContent };
  })()`);
  await sleep(1600);
  return r;
}

try {
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: PAGE_URL });
  for (let i = 0; i < 50; i += 1) {
    if ((await evaluate(`document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length`)) > 0) break;
    await sleep(300);
  }
  await sleep(800);

  // ── A. 筛选 + 每页20条（37条 → 2页），点箭头翻页 ──
  await evaluate(`(() => {
    document.querySelectorAll('.ant-card-body')[0].querySelector('.ant-select-selector')
      .dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    return true;
  })()`);
  await sleep(700);
  const actionPick = await evaluate(`(() => {
    const opts = Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option'));
    const t = opts.find(o => o.textContent.includes('启动'));
    if (!t) return { error: 'not found', available: opts.map(o => o.textContent) };
    t.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    t.click();
    return { ok: true, text: t.textContent };
  })()`);
  await sleep(500);
  await evaluate(`(() => {
    Array.from(document.querySelectorAll('button'))
      .find(b => (b.textContent || '').replace(/\\s+/g,'') === '查询').click();
    return true;
  })()`);
  const f20 = await waitFor((s) => s.lastRequest?.action === 'start' && s.lastRequest?.size === 20);
  console.log('筛选(启动)+每页20条:', JSON.stringify({ page: f20?.currentPage, texts: f20?.texts, req: f20?.lastRequest, rows: f20?.rowCount }, null, 1));
  console.log('按钮:', f20?.buttons.map(b => `${b.title || b.text}${b.disabled ? '(禁用)' : ''}${b.primary ? '[当前]' : ''}`).join(' / '));
  await screenshot('11-筛选-每页20条-第1页');

  const total37 = (f20?.texts || []).find((t) => t.includes('共'));
  record('筛选后为每页20条、共37条、2页',
    f20?.lastRequest?.size === 20 && total37 === '共 37 条' && f20.currentPage === 1 && f20.rowCount === 20,
    `每页=${f20?.lastRequest?.size}, 总数文案=${total37}, 当前页=${f20?.currentPage}, 行数=${f20?.rowCount}`);

  const nextF = f20?.buttons.find(b => b.title === '下一页');
  record('筛选后"下一页"箭头为可点击状态', nextF?.disabled === false, `下一页.disabled=${nextF?.disabled}`);

  const clickRes = await clickButton({ text: '下一页' });
  const f20p2 = await waitFor((s) => s.currentPage === 2 && s.lastRequest?.page === 2 && s.lastRequest?.action === 'start');
  record('筛选条件下点击"下一页"翻到第2页并保留筛选',
    f20p2?.currentPage === 2 && f20p2.lastRequest?.page === 2 && f20p2.lastRequest?.action === 'start' && f20p2.rowCount === 17,
    `点击=${JSON.stringify(clickRes)}, 当前页=${f20p2?.currentPage}, 请求=${JSON.stringify(f20p2?.lastRequest)}, 行数=${f20p2?.rowCount}`);
  await screenshot('12-筛选-第2页');

  const nextLast = f20p2?.buttons.find(b => b.title === '下一页');
  record('筛选后第2页为末页，"下一页"正确禁用', nextLast?.disabled === true, `下一页.disabled=${nextLast?.disabled}`);

  await clickButton({ text: '上一页' });
  const f20back = await waitFor((s) => s.currentPage === 1 && s.lastRequest?.action === 'start');
  record('筛选条件下点击"上一页"退回第1页',
    f20back?.currentPage === 1 && f20back.lastRequest?.page === 1 && f20back.lastRequest?.action === 'start',
    `当前页=${f20back?.currentPage}, 请求=${JSON.stringify(f20back?.lastRequest)}`);

  // ── B. 筛选 + 每页50条（37条 → 仅1页），下一页应禁用 ──
  await pickPageSize('50');
  const f50 = await waitFor((s) => s.lastRequest?.size === 50 && s.lastRequest?.action === 'start');
  const next50 = f50?.buttons.find(b => b.title === '下一页');
  const end50 = f50?.buttons.find(b => b.title === '末页');
  record('筛选后共37条/每页50条=仅1页，"下一页/末页"正确禁用',
    f50?.currentPage === 1 && f50.rowCount === 37 && next50?.disabled === true && end50?.disabled === true,
    `当前页=${f50?.currentPage}, 行数=${f50?.rowCount}, 总数文案=${JSON.stringify(f50?.texts)}, 下一页.disabled=${next50?.disabled}, 末页.disabled=${end50?.disabled}`);
  await screenshot('13-筛选-每页50条-单页');

  // ── C. 清除筛选恢复全量 253 条 ──
  await evaluate(`(() => {
    const clear = document.querySelectorAll('.ant-card-body')[0].querySelector('.ant-select-clear');
    if (clear) { clear.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); return 'cleared'; }
    return 'no-clear-btn';
  })()`);
  await sleep(600);
  await evaluate(`(() => {
    Array.from(document.querySelectorAll('button'))
      .find(b => (b.textContent || '').replace(/\\s+/g,'') === '查询').click();
    return true;
  })()`);
  await pickPageSize('20');
  const restored = await waitFor((s) => s.lastRequest?.size === 20 && !s.lastRequest?.action && s.lastRequest?.page === 1);
  record('清除筛选后恢复全量253条、13页、第1页',
    restored?.currentPage === 1 && restored.rowCount === 20 && (restored?.texts || []).includes('共 253 条') && restored.lastRequest?.action === undefined,
    `当前页=${restored?.currentPage}, 行数=${restored?.rowCount}, 总数文案=${JSON.stringify(restored?.texts)}, 请求=${JSON.stringify(restored?.lastRequest)}`);

  const endBtn = restored?.buttons.find(b => b.title === '末页');
  record('恢复全量后"末页"箭头重新可点击', endBtn?.disabled === false, `末页.disabled=${endBtn?.disabled}`);
  await screenshot('14-恢复全量');
} catch (err) {
  console.error('验证过程出错:', err.message);
  record('验证脚本执行', false, err.message);
} finally {
  const passed = results.filter((r) => r.ok).length;
  console.log(`\n===== 补充验证汇总: ${passed}/${results.length} 通过 =====`);
  results.forEach((r) => console.log(`${r.ok ? 'PASS' : 'FAIL'} | ${r.name} | ${r.detail}`));
  writeFileSync(path.join(SHOTS, 'result-filtered.json'), JSON.stringify(results, null, 2));
  ws.close();
  chrome.kill();
  process.exit(0);
}
