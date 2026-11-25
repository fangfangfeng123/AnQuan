import React, { useEffect, useState } from 'react';
import {
  Table,
  Button,
  Modal,
  Form,
  Input,
  Upload,
  Tabs,
  message,
  Popconfirm,
  Tag,
  Space,
  Empty,
} from 'antd';
import {
  UploadOutlined,
  PlusOutlined,
  FolderOpenOutlined,
  FileOutlined,
  DeleteOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import type { UploadFile } from 'antd/es/upload/interface';
import { useProjectStore } from '../stores/project';
import { useAuthStore } from '../stores/auth';
import { purgeProject, type ProjectListItem } from '../api/projects';
import { listTargets, type TargetItem } from '../api/targets';
import {
  projectStatusLabels,
  sourceTypeLabels,
} from '../utils/labels';

const sourceTypeTagColor: Record<string, string> = {
  git: 'blue',
  archive: 'green',
  directory: 'orange',
  file: 'cyan',
  local_path: 'purple',
};

const targetColumns = [
  {
    title: '名称',
    dataIndex: 'name',
    key: 'name',
    render: (name: string, record: TargetItem) => (
      <Space>
        {record.kind === 'directory' ? <FolderOpenOutlined /> : <FileOutlined />}
        <span>{name}</span>
      </Space>
    ),
  },
  {
    title: '类型',
    dataIndex: 'kind',
    key: 'kind',
    width: 110,
    render: (kind: TargetItem['kind']) => (
      <Tag
        color={
          kind === 'directory'
            ? 'orange'
            : kind === 'archive'
            ? 'green'
            : 'cyan'
        }
      >
        {kind === 'directory' ? '文件夹' : kind === 'archive' ? '压缩包文件' : '文件'}
      </Tag>
    ),
  },
  {
    title: '文件数',
    dataIndex: 'file_count',
    key: 'file_count',
    width: 90,
    render: (value: number) => value,
  },
  {
    title: '大小',
    dataIndex: 'total_size_kb',
    key: 'total_size_kb',
    width: 110,
    render: (value: number) => `${value} KB`,
  },
];

const ProjectListPage: React.FC = () => {
  const navigate = useNavigate();
  const role = useAuthStore((state) => state.user?.role);
  const { projects, total, loading, fetchList, create, upload, clone, ingestPath } =
    useProjectStore();
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();
  const [activeTab, setActiveTab] = useState('git');
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [page, setPage] = useState(1);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [targetLoading, setTargetLoading] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<TargetItem | null>(null);

  const canManageProject =
    role === 'admin' || role === 'security_auditor';
  const canDeleteProject = role === 'admin';

  useEffect(() => {
    fetchList({ page, size: 5 });
  }, [page]);

  useEffect(() => {
    if (!modalOpen || targets.length > 0) return;
    setTargetLoading(true);
    listTargets()
      .then((data) => {
        setTargets(data.items);
        setSelectedTarget(data.items[0] || null);
        if (data.items[0]) {
          form.setFieldsValue({ project_name: data.items[0].name });
        }
      })
      .catch((e) => message.error((e as Error).message || '内置靶场加载失败'))
      .finally(() => setTargetLoading(false));
  }, [modalOpen]);

  const handleCreate = async () => {
    try {
      // 多个 tab 共用同一个 form 实例，必须按当前 tab 校验，避免跨 tab 校验失败
      const fieldNames =
        activeTab === 'git'
          ? ['project_name', 'git_url']
          : activeTab === 'targets'
          ? ['project_name']
          : activeTab === 'local'
          ? ['project_name', 'local_path']
          : ['project_name'];
      const values = await form.validateFields(fieldNames);
      setSubmitting(true);

      if (activeTab === 'git') {
        const project = await create({
          project_name: values.project_name,
          source_type: 'git',
          source_input: values.git_url,
          source_ref: values.ref || null,
        });
        message.success('项目创建成功');
        await clone(project.id, values.git_url, values.ref || undefined);
        message.success('源码克隆完成');
      } else if (activeTab === 'archive') {
        if (fileList.length === 0) {
          message.error('请选择压缩包文件');
          setSubmitting(false);
          return;
        }
        const uploadFile = fileList[0];
        const rawFile = uploadFile.originFileObj;
        if (!rawFile) {
          message.error('文件读取失败，请重新选择压缩包文件');
          setSubmitting(false);
          return;
        }
        const project = await create({
          project_name: values.project_name,
          source_type: 'archive',
          source_input: 'zip-upload',
        });
        message.success('项目创建成功');
        await upload(project.id, rawFile as File);
        message.success('源码上传完成');
      } else if (activeTab === 'local') {
        const project = await create({
          project_name: values.project_name,
          source_type: 'local_path',
          source_input: values.local_path,
        });
        message.success('项目创建成功');
        await ingestPath(project.id, values.local_path);
        message.success('本地文件/文件夹识别完成');
      } else if (activeTab === 'targets') {
        if (!selectedTarget) {
          message.error('请选择内置靶场文件或文件夹');
          setSubmitting(false);
          return;
        }
        const project = await create({
          project_name: values.project_name,
          source_type: selectedTarget.kind,
          source_input: selectedTarget.path,
        });
        message.success('项目创建成功');
        await ingestPath(project.id, selectedTarget.path);
        message.success('内置靶场导入完成');
      }

      setModalOpen(false);
      form.resetFields();
      setFileList([]);
      setSelectedTarget(null);
      fetchList({ page, size: 5 });
    } catch (e) {
      // antd validateFields 失败时返回 { errorFields, values }，没有 .message
      // 需要从中提取字段错误信息展示给用户
      const err = e as { errorFields?: { errors?: string[] }[]; message?: string };
      if (err.errorFields && err.errorFields.length > 0) {
        const firstError = err.errorFields[0]?.errors?.[0];
        if (firstError) {
          message.error(firstError);
        }
      } else if (err.message) {
        message.error(err.message);
      } else {
        message.error('操作失败，请检查输入');
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handlePurge = async (record: ProjectListItem) => {
    setDeletingId(record.id);
    try {
      await purgeProject(record.id);
      message.success(`项目“${record.project_name}”已彻底删除`);
      fetchList({ page, size: 5 });
    } catch (e) {
      message.error((e as Error).message || '项目删除失败');
    } finally {
      setDeletingId(null);
    }
  };

  const columns = [
    {
      title: '项目名称',
      dataIndex: 'project_name',
      key: 'project_name',
      render: (text: string, record: ProjectListItem) => (
        <a onClick={() => navigate(`/projects/${record.id}`)}>{text}</a>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source_type',
      key: 'source_type',
      render: (val: string) => (
        <Tag color={sourceTypeTagColor[val] || 'default'}>
          {sourceTypeLabels[val] || val}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (val: string) => (
        <Tag color={val === 'active' ? 'green' : 'default'}>
          {projectStatusLabels[val] || val}
        </Tag>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (val: string) => new Date(val).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: unknown, record: ProjectListItem) => (
        <Space>
          <Button
            size="small"
            icon={<FolderOpenOutlined />}
            onClick={() => navigate(`/projects/${record.id}`)}
          >
            查看
          </Button>
          {canDeleteProject && (
            <Popconfirm
              title="彻底删除项目"
              description={`将删除“${record.project_name}”关联的任务、漏洞、报告，并清理源码快照目录和报告文件，不可恢复。`}
              okText="确认删除"
              cancelText="取消"
              okButtonProps={{ danger: true }}
              onConfirm={() => handlePurge(record)}
            >
              <Button
                size="small"
                danger
                icon={<DeleteOutlined />}
                loading={deletingId === record.id}
              >
                删除
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>项目列表</h2>
        {canManageProject && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
            新建项目
          </Button>
        )}
      </div>

      <Table
        columns={columns}
        dataSource={projects}
        rowKey="id"
        loading={loading}
        pagination={{
          current: page,
          total,
          pageSize: 5,
          showQuickJumper: true,
          onChange: (p) => setPage(p),
          showTotal: (t) => `共 ${t} 条`,
        }}
      />

      <Modal
        title="新建项目"
        open={modalOpen}
        onCancel={() => {
          setModalOpen(false);
          setSelectedTarget(null);
        }}
        onOk={handleCreate}
        confirmLoading={submitting}
        width={600}
        okText="创建"
        cancelText="取消"
      >
        <Tabs
          activeKey={activeTab}
          onChange={(key) => {
            setActiveTab(key);
            if (key === 'targets' && selectedTarget) {
              form.setFieldsValue({ project_name: selectedTarget.name });
            }
          }}
          items={[
            {
              key: 'git',
              label: '代码仓库克隆',
              children: (
                <Form form={form} layout="vertical">
                  <Form.Item
                    name="project_name"
                    label="项目名称"
                    rules={[{ required: true, message: '请输入项目名称' }]}
                  >
                    <Input placeholder="如: my-app-security-audit" />
                  </Form.Item>
                  <Form.Item
                    name="git_url"
                    label="仓库地址"
                    rules={[{ required: true, message: '请输入代码仓库地址' }]}
                  >
                    <Input placeholder="https://github.com/user/repo.git" />
                  </Form.Item>
                  <Form.Item name="ref" label="分支/Tag/Commit（可选）">
                    <Input placeholder="main / v1.0 / abc123" />
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'archive',
              label: '压缩包上传',
              children: (
                <Form form={form} layout="vertical">
                  <Form.Item
                    name="project_name"
                    label="项目名称"
                    rules={[{ required: true, message: '请输入项目名称' }]}
                  >
                    <Input placeholder="如: my-app-security-audit" />
                  </Form.Item>
                  <Form.Item label="压缩包文件" required>
                    <Upload
                      accept=".zip"
                      maxCount={1}
                      fileList={fileList}
                      beforeUpload={() => false}
                      onChange={({ fileList }) => setFileList(fileList)}
                    >
                      <Button icon={<UploadOutlined />}>选择压缩包文件</Button>
                    </Upload>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'local',
              label: '本地文件/文件夹',
              children: (
                <Form form={form} layout="vertical">
                  <Form.Item
                    name="project_name"
                    label="项目名称"
                    rules={[{ required: true, message: '请输入项目名称' }]}
                  >
                    <Input placeholder="如: my-local-project" />
                  </Form.Item>
                  <Form.Item
                    name="local_path"
                    label="本地文件/文件夹路径"
                    rules={[{ required: true, message: '请输入本地路径' }]}
                  >
                    <Input
                      addonBefore={<FileOutlined />}
                      placeholder="E:\src\demo 或 E:\demo.py"
                    />
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'targets',
              label: '内置靶场',
              children: (
                <Form form={form} layout="vertical">
                  <Form.Item
                    name="project_name"
                    label="项目名称"
                    rules={[{ required: true, message: '请输入项目名称' }]}
                  >
                    <Input placeholder="如: vulnerability-level-suite" />
                  </Form.Item>
                  {targets.length === 0 && !targetLoading ? (
                    <Empty description="当前 targets 目录下没有可导入内容" />
                  ) : (
                    <Table<TargetItem>
                      rowKey="name"
                      size="small"
                      columns={targetColumns}
                      dataSource={targets}
                      loading={targetLoading}
                      pagination={false}
                      scroll={{ y: 260 }}
                      rowSelection={{
                        type: 'radio',
                        selectedRowKeys: selectedTarget ? [selectedTarget.name] : [],
                        onChange: (_keys, rows) => {
                          const selected = rows[0];
                          setSelectedTarget(selected || null);
                          if (selected) {
                            form.setFieldsValue({ project_name: selected.name });
                          }
                        },
                      }}
                    />
                  )}
                </Form>
              ),
            },
          ]}
        />
      </Modal>
    </div>
  );
};

export default ProjectListPage;
