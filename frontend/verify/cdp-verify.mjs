// 通过 Chrome DevTools Protocol 驱动无头 Chrome，真实点击审计日志页的分页箭头，
// 验证翻页行为与数字跳页功能。仅用于本地验证，不参与生产构建。
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PAGE_URL = 'http://127.0.0.1:8099/';
const DEBUG_PORT = 9333;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROFILE = path.join(HERE, '.chrome-profile');
const SHOTS = path.join(HERE, 'shots');

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} | ${name} | ${detail}`);
}

mkdirSync(SHOTS, { recursive: true });
rmSync(PROFILE, { recursive: true, force: true });

const chrome = spawn(CHROME, [
  '--headless=new',
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${PROFILE}`,
  '--window-size=1600,1100',
  '--hide-scrollbars',
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-gpu',
  'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getWsUrl() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* 等待 Chrome 就绪 */ }
    await sleep(500);
  }
  throw new Error('无法连接 Chrome 调试端口');
}

const ws = new WebSocket(await getWsUrl());
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
const consoleErrors = [];

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    return;
  }
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    consoleErrors.push(msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text || 'unknown');
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
  const file = path.join(SHOTS, `${name}.png`);
  writeFileSync(file, Buffer.from(res.data, 'base64'));
  return file;
}

// 分页条根容器：以 title="首页" 的按钮的父元素定位，避免误选筛选区卡片
const PAGINATION_ROOT = `
  const homeBtn = Array.from(document.querySelectorAll('button'))
    .find(b => b.getAttribute('title') === '首页');
  const root = homeBtn ? homeBtn.parentElement : null;
`;

async function readPagination() {
  return evaluate(`(() => {
    ${PAGINATION_ROOT}
    if (!root) return null;
    const norm = s => (s || '').replace(/\\s+/g, '');
    const buttons = Array.from(root.querySelectorAll('button')).map(b => {
      const r = b.getBoundingClientRect();
      return {
        text: norm(b.textContent),
        title: b.getAttribute('title') || '',
        disabled: b.disabled,
        primary: b.classList.contains('ant-btn-primary'),
        x: Math.round(r.x + r.width / 2),
        y: Math.round(r.y + r.height / 2),
      };
    });
    const active = buttons.find(b => b.primary && /^\\d+$/.test(b.text));
    const jumper = root.querySelector('.ant-input-number-input');
    return {
      currentPage: active ? Number(active.text) : null,
      texts: Array.from(root.querySelectorAll('.ant-typography')).map(e => e.textContent.trim()).filter(Boolean),
      jumperValue: jumper ? jumper.value : null,
      jumperMax: jumper ? jumper.getAttribute('aria-valuemax') : null,
      buttons,
      rowCount: document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length,
      lastRequest: globalThis.__lastRequest || null,
    };
  })()`);
}

/** 派发真实鼠标点击到指定按钮（按 title 或规范化文本匹配） */
async function clickPaginationButton({ title, text }) {
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

async function waitForPage(expected, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let state = null;
  while (Date.now() < deadline) {
    state = await readPagination();
    if (state?.currentPage === expected && state.lastRequest?.page === expected) return state;
    await sleep(200);
  }
  return state;
}

async function setJumper(value) {
  return evaluate(`(() => {
    ${PAGINATION_ROOT}
    const input = root.querySelector('.ant-input-number-input');
    if (!input) return null;
    input.focus();
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${JSON.stringify(String(value))});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return input.value;
  })()`);
}

try {
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Page.navigate', { url: PAGE_URL });

  for (let i = 0; i < 50; i += 1) {
    const rows = await evaluate(`document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length`);
    if (rows > 0) break;
    await sleep(300);
  }
  await sleep(800);

  const initial = await readPagination();
  if (!initial) throw new Error('未能定位分页条，页面渲染异常');
  console.log('初始分页状态:', JSON.stringify({ currentPage: initial.currentPage, texts: initial.texts, lastRequest: initial.lastRequest, rowCount: initial.rowCount, jumperMax: initial.jumperMax }, null, 1));
  console.log('分页按钮:', initial.buttons.map(b => `${b.title || b.text}${b.disabled ? '(禁用)' : ''}${b.primary ? '[当前]' : ''}`).join(' / '));
  await screenshot('01-初始状态');

  // 1. 初始加载
  record('初始加载为第1页、每页20条',
    initial.currentPage === 1 && initial.lastRequest?.page === 1 && initial.lastRequest?.size === 20 && initial.rowCount === 20,
    `当前页=${initial.currentPage}, 请求=${JSON.stringify(initial.lastRequest)}, 表格行数=${initial.rowCount}, 总数文案=${JSON.stringify(initial.texts)}`);

  // 2. 第1页时前向箭头应禁用
  const home0 = initial.buttons.find(b => b.title === '首页');
  const prev0 = initial.buttons.find(b => b.title === '上一页');
  const next0 = initial.buttons.find(b => b.title === '下一页');
  const end0 = initial.buttons.find(b => b.title === '末页');
  record('第1页时"首页/上一页"禁用、"下一页/末页"可点',
    home0?.disabled === true && prev0?.disabled === true && next0?.disabled === false && end0?.disabled === false,
    `首页=${home0?.disabled}, 上一页=${prev0?.disabled}, 下一页=${next0?.disabled}, 末页=${end0?.disabled}`);

  // 3. 点击"下一页"箭头
  await clickPaginationButton({ text: '下一页' });
  const p2 = await waitForPage(2);
  record('点击"下一页"箭头翻到第2页',
    p2?.currentPage === 2 && p2.lastRequest?.page === 2 && p2.rowCount === 20,
    `当前页=${p2?.currentPage}, 请求=${JSON.stringify(p2?.lastRequest)}, 表格行数=${p2?.rowCount}`);
  await screenshot('02-下一页-第2页');

  // 4. 再次点击"下一页"
  await clickPaginationButton({ text: '下一页' });
  const p3 = await waitForPage(3);
  record('再次点击"下一页"翻到第3页', p3?.currentPage === 3, `当前页=${p3?.currentPage}`);

  // 5. 点击"上一页"箭头
  await clickPaginationButton({ text: '上一页' });
  const back2 = await waitForPage(2);
  record('点击"上一页"箭头退回第2页',
    back2?.currentPage === 2 && back2.lastRequest?.page === 2,
    `当前页=${back2?.currentPage}, 请求=${JSON.stringify(back2?.lastRequest)}`);
  await screenshot('03-上一页-第2页');

  // 6. 点击"末页"箭头（253 条 / 20 = 13 页，末页 13 条）
  await clickPaginationButton({ title: '末页' });
  const last = await waitForPage(13);
  record('点击"末页"箭头跳到第13页(末页仅剩3条)',
    last?.currentPage === 13 && last.lastRequest?.page === 13 && last.rowCount === 13,
    `当前页=${last?.currentPage}, 请求=${JSON.stringify(last?.lastRequest)}, 表格行数=${last?.rowCount}`);
  const nextL = last.buttons.find(b => b.title === '下一页');
  const endL = last.buttons.find(b => b.title === '末页');
  const prevL = last.buttons.find(b => b.title === '上一页');
  record('末页时"下一页/末页"禁用、"上一页"仍可点',
    nextL?.disabled === true && endL?.disabled === true && prevL?.disabled === false,
    `下一页=${nextL?.disabled}, 末页=${endL?.disabled}, 上一页=${prevL?.disabled}`);
  await screenshot('04-末页-第13页');

  // 7. 点击"首页"箭头
  await clickPaginationButton({ title: '首页' });
  const home = await waitForPage(1);
  record('点击"首页"箭头回到第1页', home?.currentPage === 1, `当前页=${home?.currentPage}`);

  // 8. 数字输入 + 点击"跳转"
  const setVal7 = await setJumper('7');
  await clickPaginationButton({ text: '跳转' });
  const jump = await waitForPage(7);
  record('输入数字7并点击"跳转"按钮翻到第7页',
    jump?.currentPage === 7 && jump.lastRequest?.page === 7,
    `输入框写入值=${setVal7}, 当前页=${jump?.currentPage}, 请求=${JSON.stringify(jump?.lastRequest)}`);
  await screenshot('05-数字跳转-第7页');

  // 9. 数字输入 + 回车
  await setJumper('11');
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
  const enter = await waitForPage(11);
  record('输入数字11后按回车翻到第11页',
    enter?.currentPage === 11 && enter.lastRequest?.page === 11,
    `当前页=${enter?.currentPage}, 请求=${JSON.stringify(enter?.lastRequest)}`);

  // 10. 越界输入自动收敛到末页
  await setJumper('999');
  await clickPaginationButton({ text: '跳转' });
  const clamp = await waitForPage(13);
  record('输入越界值999自动收敛到末页13',
    clamp?.currentPage === 13 && clamp.lastRequest?.page === 13,
    `当前页=${clamp?.currentPage}, 输入框显示值=${clamp?.jumperValue}, 上限=${clamp?.jumperMax}`);
  await screenshot('06-越界收敛');

  // 11. 页码按钮直接点击（先跳到第6页让页码5出现在窗口内）
  await setJumper('6');
  await clickPaginationButton({ text: '跳转' });
  await waitForPage(6);
  const win6 = await readPagination();
  console.log('第6页时的页码窗口:', win6.buttons.filter(b => /^\d+$/.test(b.text)).map(b => b.text).join(','), '| 省略号数:', await evaluate(`(() => { const h=Array.from(document.querySelectorAll('button')).find(b=>b.getAttribute('title')==='首页'); return h? Array.from(h.parentElement.querySelectorAll('.ant-typography')).filter(e=>e.textContent.includes('•••')).length : -1; })()`));
  await clickPaginationButton({ text: '5' });
  const num5 = await waitForPage(5);
  record('点击页码按钮"5"翻到第5页', num5?.currentPage === 5, `当前页=${num5?.currentPage}`);

  // 12. 切换每页条数（分页条内的 Select）
  await evaluate(`(() => {
    const h = Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('title') === '首页');
    const sel = h.parentElement.querySelector('.ant-select-selector');
    sel.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    return true;
  })()`);
  await sleep(700);
  const sizePick = await evaluate(`(() => {
    const opts = Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option'));
    const target = opts.find(o => o.textContent.includes('50'));
    if (!target) return { error: '未找到50条/页选项', available: opts.map(o => o.textContent) };
    target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    target.click();
    return { ok: true, text: target.textContent };
  })()`);
  await sleep(1500);
  const afterSize = await readPagination();
  record('切换每页条数为50后分页正常',
    afterSize?.lastRequest?.size === 50 && afterSize.rowCount === 50 && afterSize.currentPage === 5,
    `选择=${JSON.stringify(sizePick)}, 每页条数=${afterSize?.lastRequest?.size}, 表格行数=${afterSize?.rowCount}, 当前页=${afterSize?.currentPage}`);
  await screenshot('07-切换每页50条');

  // 13. 每页50条时点箭头仍能翻页（253条 → 6页）
  await clickPaginationButton({ text: '下一页' });
  const size50p2 = await waitForPage(6);
  record('每页50条时点击"下一页"翻到第6页(共6页)',
    size50p2?.currentPage === 6 && size50p2.lastRequest?.page === 6 && size50p2.lastRequest?.size === 50 && size50p2.rowCount === 3,
    `当前页=${size50p2?.currentPage}, 请求=${JSON.stringify(size50p2?.lastRequest)}, 表格行数=${size50p2?.rowCount}`);

  // 14. 筛选条件下翻页
  await evaluate(`(() => {
    const cards = document.querySelectorAll('.ant-card-body');
    const sel = cards[0].querySelector('.ant-select-selector');
    sel.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    return true;
  })()`);
  await sleep(700);
  const actionPick = await evaluate(`(() => {
    const opts = Array.from(document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option'));
    const target = opts.find(o => o.textContent.includes('启动'));
    if (!target) return { error: '未找到启动选项', available: opts.map(o => o.textContent) };
    target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    target.click();
    return { ok: true, text: target.textContent };
  })()`);
  await sleep(500);
  await evaluate(`(() => {
    const btn = Array.from(document.querySelectorAll('button')).find(b => (b.textContent || '').replace(/\\s+/g,'') === '查询');
    btn.click();
    return true;
  })()`);
  await sleep(1800);
  const filtered = await readPagination();
  record('按动作筛选查询后回到第1页',
    filtered?.lastRequest?.action === 'start' && filtered.currentPage === 1,
    `选择=${JSON.stringify(actionPick)}, 请求=${JSON.stringify(filtered?.lastRequest)}, 当前页=${filtered?.currentPage}, 总数文案=${JSON.stringify(filtered?.texts)}`);
  await screenshot('08-筛选后分页');

  // 注意：此时每页条数已被前面步骤改为 50，筛选后共 37 条 → 仅 1 页，
  // 因此"下一页"应处于禁用态。多页场景由 cdp-verify-filtered.mjs 覆盖。
  const filteredTotal = await evaluate(`(() => { const h=Array.from(document.querySelectorAll('button')).find(b=>b.getAttribute('title')==='首页'); return h.parentElement.querySelector('.ant-typography').textContent.trim(); })()`);
  const nextFiltered = filtered?.buttons.find(b => b.title === '下一页');
  record('筛选后共37条/每页50条=仅1页，"下一页"正确禁用',
    filteredTotal === '共 37 条' && filtered?.rowCount === 37 && nextFiltered?.disabled === true,
    `总数文案=${filteredTotal}, 行数=${filtered?.rowCount}, 下一页.disabled=${nextFiltered?.disabled}`);
  await screenshot('09-筛选后单页');

  record('页面无 JS 运行时报错', consoleErrors.length === 0,
    consoleErrors.length ? consoleErrors.slice(0, 5).join(' || ') : '无报错');

  await screenshot('10-最终状态');
} catch (err) {
  console.error('验证过程出错:', err.message);
  record('验证脚本执行', false, err.message);
} finally {
  const passed = results.filter((r) => r.ok).length;
  console.log(`\n===== 汇总: ${passed}/${results.length} 通过 =====`);
  results.forEach((r) => console.log(`${r.ok ? 'PASS' : 'FAIL'} | ${r.name} | ${r.detail}`));
  writeFileSync(path.join(SHOTS, 'result.json'), JSON.stringify(results, null, 2));
  ws.close();
  chrome.kill();
  process.exit(0);
}
