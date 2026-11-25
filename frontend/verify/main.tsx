// 验证入口：以真实 AuditLogPage 组件 + 模拟数据渲染审计日志页面。
import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import AuditLogPage from '../src/pages/AuditLogPage';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN}>
      <div style={{ padding: 24, background: '#fff', minHeight: '100vh' }}>
        <AuditLogPage />
      </div>
    </ConfigProvider>
  </React.StrictMode>
);
