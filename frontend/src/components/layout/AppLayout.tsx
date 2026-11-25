import React from 'react';
import { Layout } from 'antd';
import AppSidebar from './AppSidebar';
import AppHeader from './AppHeader';

const { Content } = Layout;

const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Layout style={{ minHeight: '100vh' }}>
    <AppSidebar />
    <Layout>
      <AppHeader />
      <Content style={{ margin: '16px', padding: '24px', background: '#fff', borderRadius: '8px' }}>
        {children}
      </Content>
    </Layout>
  </Layout>
);

export default AppLayout;
