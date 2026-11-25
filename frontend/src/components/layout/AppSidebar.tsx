import React from 'react';
import { Layout, Menu } from 'antd';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  ProjectOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  DashboardOutlined,
} from '@ant-design/icons';
import { useAuthStore } from '../../stores/auth';

const { Sider } = Layout;

const allItems = [
  { key: '/projects', icon: React.createElement(ProjectOutlined), label: '项目管理' },
  { key: '/dashboard', icon: React.createElement(DashboardOutlined), label: '仪表盘' },
  { key: '/reports', icon: React.createElement(FileTextOutlined), label: '报告中心' },
  { key: '/audit-logs', icon: React.createElement(ExperimentOutlined), label: '审计日志' },
];

const AppSidebar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const role = useAuthStore((state) => state.user?.role);

  const selectedKey = '/' + location.pathname.split('/')[1];
  const menuItems =
    role === 'admin'
      ? allItems
      : allItems.filter((item) => item.key !== '/audit-logs');

  return (
    <Sider width={200} style={{ background: '#001529' }}>
      <div
        style={{
          height: '48px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#fff',
          fontSize: '16px',
          fontWeight: 'bold',
        }}
      >
        安全评估系统
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[selectedKey]}
        items={menuItems}
        onClick={({ key }) => navigate(key)}
      />
    </Sider>
  );
};

export default AppSidebar;
