import React, { useState } from 'react';
import { Button, Card, Form, Input, Typography, message } from 'antd';
import {
  LockOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useAuthStore } from '../stores/auth';

const { Title, Text } = Typography;

const LoginPage: React.FC = () => {
  const login = useAuthStore((state) => state.login);
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      await login(values.username, values.password);
    } catch (e) {
      if ((e as { errorFields?: unknown }).errorFields) return;
      message.error((e as Error).message || '登录失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#f0f2f5',
        padding: 24,
      }}
    >
      <div style={{ width: 460 }}>
        <Card>
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            <SafetyCertificateOutlined
              style={{ fontSize: 44, color: '#1677ff', marginBottom: 8 }}
            />
            <Title level={3} style={{ margin: '0 0 8px' }}>
              智能安全评估平台
            </Title>
            <Text type="secondary">请输入账号和密码登录</Text>
          </div>

          <Form form={form} layout="vertical" onFinish={handleLogin}>
            <Form.Item
              name="username"
              label="账号"
              rules={[{ required: true, message: '请输入账号' }]}
            >
              <Input prefix={<UserOutlined />} placeholder="请输入账号" />
            </Form.Item>
            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password
                prefix={<LockOutlined />}
                placeholder="请输入密码"
              />
            </Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              block
              loading={loading}
              style={{ marginBottom: 16 }}
            >
              登录
            </Button>
          </Form>

        </Card>
      </div>
    </div>
  );
};

export default LoginPage;
