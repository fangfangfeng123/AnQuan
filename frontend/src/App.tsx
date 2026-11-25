import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, Spin } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import AppLayout from './components/layout/AppLayout';
import LoginPage from './pages/LoginPage';
import ProjectListPage from './pages/ProjectListPage';
import TaskWorkbenchPage from './pages/TaskWorkbenchPage';
import DashboardPage from './pages/DashboardPage';
import ReportCenterPage from './pages/ReportCenterPage';
import AuditLogPage from './pages/AuditLogPage';
import { useAuthStore } from './stores/auth';

const AppContent: React.FC = () => {
  const user = useAuthStore((state) => state.user);
  const loading = useAuthStore((state) => state.loading);
  const loadFromStorage = useAuthStore((state) => state.loadFromStorage);

  useEffect(() => {
    loadFromStorage();
  }, []);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<ProjectListPage />} />
        <Route path="/projects/:id" element={<TaskWorkbenchPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/reports" element={<ReportCenterPage />} />
        <Route
          path="/audit-logs"
          element={
            user.role === 'admin' ? (
              <AuditLogPage />
            ) : (
              <Navigate to="/projects" replace />
            )
          }
        />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Routes>
    </AppLayout>
  );
};

const App: React.FC = () => (
  <ConfigProvider locale={zhCN}>
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  </ConfigProvider>
);

export default App;
