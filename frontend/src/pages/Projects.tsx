import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Space, message } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons';
import { projectApi } from '../services/api';
import { useT } from '../i18n';

interface ProjectRecord {
    id: string;
    name: string;
    path: string;
    created_at: string;
    last_scan_at?: string;
}

export default function Projects() {
    const [projects, setProjects] = useState<ProjectRecord[]>([]);
    const [loading, setLoading] = useState(false);
    const [modalOpen, setModalOpen] = useState(false);
    const [form] = Form.useForm();
    const t = useT();

    useEffect(() => { loadProjects(); }, []);

    async function loadProjects() {
        setLoading(true);
        try {
            const res = await projectApi.list();
            setProjects(res.data?.projects ?? res.data ?? []);
        } catch { message.error(t('加载项目列表失败', 'Failed to load projects')); } // i18n: user-facing
        finally { setLoading(false); }
    }

    async function handleCreate(values: any) {
        try {
            await projectApi.create(values);
            message.success(t('项目已添加', 'Project added')); // i18n: user-facing
            setModalOpen(false);
            form.resetFields();
            loadProjects();
        } catch { message.error(t('添加项目失败', 'Failed to add project')); } // i18n: user-facing
    }

    async function handleDelete(id: string) {
        try { await projectApi.delete(id); message.success(t('已删除', 'Deleted')); loadProjects(); } // i18n: user-facing
        catch { message.error(t('删除失败', 'Failed to delete')); } // i18n: user-facing
    }

    const columns = [
        { title: t('项目名', 'Name'), dataIndex: 'name', key: 'name' }, // i18n: user-facing
        { title: t('路径', 'Path'), dataIndex: 'path', key: 'path', ellipsis: true }, // i18n: user-facing
        { title: t('创建时间', 'Created'), dataIndex: 'created_at', key: 'created_at' }, // i18n: user-facing
        { title: t('最近扫描', 'Last scan'), dataIndex: 'last_scan_at', key: 'last_scan_at' }, // i18n: user-facing
        { title: t('操作', 'Actions'), key: 'action', render: (_: any, r: ProjectRecord) => <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)}>{t('删除', 'Delete')}</Button> }, // i18n: user-facing
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>{t('项目管理', 'Projects')}</h2>{/* i18n: user-facing */}
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={loadProjects}>{t('刷新', 'Refresh')}</Button>{/* i18n: user-facing */}
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>{t('添加项目', 'Add project')}</Button>{/* i18n: user-facing */}
                </Space>
            </div>
            <Table dataSource={projects} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 10 }} />
            <Modal title={t('添加项目', 'Add project')} open={modalOpen} onCancel={() => setModalOpen(false)} onOk={() => form.submit()}>{/* i18n: user-facing */}
                <Form form={form} layout="vertical" onFinish={handleCreate}>
                    <Form.Item name="name" label={t('项目名称', 'Project name')} rules={[{ required: true, message: t('请输入名称', 'Name is required') }]}>{/* i18n: user-facing */}
                        <Input placeholder="my-project" />
                    </Form.Item>
                    <Form.Item name="path" label={t('项目路径', 'Project path')} rules={[{ required: true, message: t('请输入路径', 'Path is required') }]}>{/* i18n: user-facing */}
                        <Input placeholder="/path/to/project" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
}
