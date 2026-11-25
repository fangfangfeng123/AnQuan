import React from 'react';
import { Card, Descriptions, Tag, Empty, Spin, Space, Tooltip } from 'antd';
import {
  CodeOutlined,
  ApartmentOutlined,
  DatabaseOutlined,
  ApiOutlined,
  PlayCircleOutlined,
  GlobalOutlined,
} from '@ant-design/icons';
import type { ReconSummary } from '../../api/recon';
import {
  dbTypeLabels,
  frameworkLabels,
  languageLabels,
} from '../../utils/labels';

interface ReconResultCardProps {
  summary: ReconSummary | null;
  loading: boolean;
}

/** 语言 -> 颜色映射 */
const LANG_COLORS: Record<string, string> = {
  python: 'blue',
  javascript: 'gold',
  java: 'volcano',
  go: 'cyan',
  php: 'purple',
  ruby: 'red',
  unknown: 'default',
};

/** 框架 -> 颜色映射 */
const FW_COLORS: Record<string, string> = {
  flask: 'blue',
  fastapi: 'cyan',
  django: 'green',
  express: 'gold',
  'spring-boot': 'volcano',
  gin: 'cyan',
  laravel: 'purple',
  rails: 'red',
  unknown: 'default',
};

/** 数据库类型 -> 颜色映射 */
const DB_COLORS: Record<string, string> = {
  postgresql: 'blue',
  mysql: 'orange',
  sqlite: 'green',
  mongodb: 'green',
  redis: 'red',
  not_detected: 'default',
};

/**
 * 环境侦察结果卡片。
 * 展示 Recon 阶段识别出的语言、框架、依赖数量、入口文件、端口和数据库类型。
 */
const ReconResultCard: React.FC<ReconResultCardProps> = ({
  summary,
  loading,
}) => {
  if (loading) {
    return (
      <Card title="环境侦察结果" style={{ marginBottom: 16 }}>
        <div style={{ textAlign: 'center', padding: '24px' }}>
          <Spin tip="正在分析项目技术栈..." />
        </div>
      </Card>
    );
  }

  if (!summary) {
    return (
      <Card
        title="环境侦察结果"
        style={{ marginBottom: 16 }}
      >
        <Empty
          description="尚未完成环境侦察，启动任务后将自动识别技术栈"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          style={{ padding: '24px 0' }}
        />
      </Card>
    );
  }

  const langColor = LANG_COLORS[summary.language] || 'default';
  const fwColor = FW_COLORS[summary.framework] || 'default';
  const dbColor = DB_COLORS[summary.db_type] || 'default';

  return (
    <Card
      title={
        <Space>
          <ApartmentOutlined />
          <span>环境侦察结果</span>
        </Space>
      }
      style={{ marginBottom: 16 }}
    >
      <Descriptions column={3} size="small" bordered>
        <Descriptions.Item
          label={
            <Space>
              <CodeOutlined />
              主语言
            </Space>
          }
        >
          <Tag color={langColor} style={{ fontWeight: 600 }}>
            {languageLabels[summary.language] || summary.language || '未识别'}
          </Tag>
        </Descriptions.Item>

        <Descriptions.Item
          label={
            <Space>
              <ApartmentOutlined />
              主框架
            </Space>
          }
        >
          <Tag color={fwColor} style={{ fontWeight: 600 }}>
            {frameworkLabels[summary.framework] || summary.framework || '未识别'}
          </Tag>
        </Descriptions.Item>

        <Descriptions.Item
          label={
            <Space>
              <DatabaseOutlined />
              数据库
            </Space>
          }
        >
          <Tag color={dbColor}>
            {dbTypeLabels[summary.db_type] || summary.db_type || '未识别'}
          </Tag>
        </Descriptions.Item>

        <Descriptions.Item label="依赖数量">
          <span style={{ fontSize: '18px', fontWeight: 600 }}>
            {summary.dependency_count}
          </span>
        </Descriptions.Item>

        <Descriptions.Item label="入口文件数">
          <span style={{ fontSize: '18px', fontWeight: 600 }}>
            {summary.entry_point_count}
          </span>
        </Descriptions.Item>

        <Descriptions.Item
          label={
            <Space>
              <GlobalOutlined />
              服务端口
            </Space>
          }
        >
          {summary.service_ports && summary.service_ports.length > 0 ? (
            <Space wrap>
              {summary.service_ports.map((port, i) => (
                <Tag key={i} color="blue">
                  {port}
                </Tag>
              ))}
            </Space>
          ) : (
            <span style={{ color: '#999' }}>未检测到</span>
          )}
        </Descriptions.Item>

        <Descriptions.Item
          label={
            <Space>
              <PlayCircleOutlined />
              启动命令
            </Space>
          }
          span={3}
        >
          {summary.run_command ? (
            <Tooltip title="根据框架和入口文件推断">
              <code
                style={{
                  background: '#f5f5f5',
                  padding: '4px 8px',
                  borderRadius: 4,
                  fontSize: '13px',
                }}
              >
                {summary.run_command}
              </code>
            </Tooltip>
          ) : (
            <span style={{ color: '#999' }}>无法推断</span>
          )}
        </Descriptions.Item>
      </Descriptions>

      {summary.language !== 'unknown' && (
        <div style={{ marginTop: 12, color: '#888', fontSize: '12px' }}>
          <ApiOutlined style={{ marginRight: 4 }} />
          识别结果将用于后续代码审计阶段选择对应语言的扫描规则
        </div>
      )}
    </Card>
  );
};

export default ReconResultCard;
