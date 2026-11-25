// 验证专用 Vite 配置：把 ../api/auditLogs 指向模拟数据，
// 以便在没有后端服务的情况下验证审计日志页的翻页交互。
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const root = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  root,
  plugins: [react()],
  resolve: {
    alias: [
      {
        find: /^\.\.\/api\/auditLogs$/,
        replacement: fileURLToPath(new URL('./mock-auditLogs.ts', import.meta.url)),
      },
    ],
  },
  server: {
    host: '127.0.0.1',
    port: 8099,
    strictPort: true,
  },
});
