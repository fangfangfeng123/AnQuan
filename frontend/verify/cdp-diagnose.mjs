// 诊断脚本：打印验证页在浏览器中的实际渲染结果与控制台报错。
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { rmSync } from 'node:fs';

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PAGE_URL = 'http://127.0.0.1:8099/';
const DEBUG_PORT = 9334;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROFILE = path.join(HERE, '.chrome-profile-diag');

rmSync(PROFILE, { recursive: true, force: true });

const chrome = spawn(CHROME, [
  '--headless=new',
  `--remote-debugging-port=${DEBUG_PORT}`,
  `--user-data-dir=${PROFILE}`,
  '--window-size=1600,1200',
  '--no-first-run',
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
    } catch { /* 等待 */ }
    await sleep(500);
  }
  throw new Error('无法连接 Chrome 调试端口');
}

const ws = new WebSocket(await getWsUrl());
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
const logs = [];

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    return;
  }
  if (msg.method === 'Runtime.consoleAPICalled') {
    logs.push(`[console.${msg.params.type}] ` + msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    logs.push('[exception] ' + (msg.params.exceptionDetails?.exception?.description || msg.params.exceptionDetails?.text));
  }
  if (msg.method === 'Log.entryAdded') {
    logs.push(`[log.${msg.params.entry.level}] ${msg.params.entry.text} ${msg.params.entry.url || ''}`);
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
  if (res.exceptionDetails) throw new Error(res.exceptionDetails.exception?.description || 'eval failed');
  return res.result.value;
}

try {
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.navigate', { url: PAGE_URL });
  await sleep(6000);

  console.log('=== 控制台日志 ===');
  logs.forEach((l) => console.log(l));

  console.log('\n=== DOM 概览 ===');
  console.log(await evaluate(`JSON.stringify({
    readyState: document.readyState,
    rootChildren: document.getElementById('root')?.childElementCount,
    bodyText: document.body.innerText.slice(0, 600),
    cardBodyCount: document.querySelectorAll('.ant-card-body').length,
    tableRows: document.querySelectorAll('.ant-table-tbody tr.ant-table-row').length,
    buttons: Array.from(document.querySelectorAll('button')).map(b => (b.getAttribute('title')||'') + '|' + (b.textContent||'').trim() + '|' + b.disabled),
    lastRequest: globalThis.__lastRequest || null,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
  }, null, 1)`));
} catch (err) {
  console.error('诊断出错:', err.message);
} finally {
  ws.close();
  chrome.kill();
  process.exit(0);
}
