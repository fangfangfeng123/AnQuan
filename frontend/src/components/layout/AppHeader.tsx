import React from 'react';
import { Layout, Typography } from 'antd';
import { Button, Space } from 'antd';
import { LogoutOutlined } from '@ant-design/icons';
import { useAuthStore } from '../../stores/auth';

const { Header } = Layout;
const { Text } = Typography;

const AppHeader: React.FC = () => {
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);

  return (
    <Header
      style={{
        background: '#fff',
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <Text strong style={{ fontSize: '16px' }}>
        智能安全评估平台
      </Text>
      <Space>
        <Text type="secondary">
          {user?.display_name || user?.username || '未登录'}
        </Text>
        <Button
          size="small"
          icon={<LogoutOutlined />}
          onClick={() => logout()}
        >
          退出登录
        </Button>
      </Space>
    </Header>
  );
};

export default AppHeader;
