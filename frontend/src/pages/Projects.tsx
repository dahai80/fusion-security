import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Space, message } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons';
import { projectApi } from '../services/api';

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

    useEffect(() => { loadProjects(); }, []);

    async function loadProjects() {
        setLoading(true);
        try {
            const res = await projectApi.list();
            setProjects(res.data?.projects ?? res.data ?? []);
        } catch { message.error('加载项目列表失败'); }
        finally { setLoading(false); }
    }

    async function handleCreate(values: any) {
        try {
            await projectApi.create(values);
            message.success('项目已添加');
            setModalOpen(false);
            form.resetFields();
            loadProjects();
        } catch { message.error('添加项目失败'); }
    }

    async function handleDelete(id: string) {
        try { await projectApi.delete(id); message.success('已删除'); loadProjects(); }
        catch { message.error('删除失败'); }
    }

    const columns = [
        { title: '项目名', dataIndex: 'name', key: 'name' },
        { title: '路径', dataIndex: 'path', key: 'path', ellipsis: true },
        { title: '创建时间', dataIndex: 'created_at', key: 'created_at' },
        { title: '最近扫描', dataIndex: 'last_scan_at', key: 'last_scan_at' },
        { title: '操作', key: 'action', render: (_: any, r: ProjectRecord) => <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)}>删除</Button> },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>项目管理</h2>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={loadProjects}>刷新</Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>添加项目</Button>
                </Space>
            </div>
            <Table dataSource={projects} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 10 }} />
            <Modal title="添加项目" open={modalOpen} onCancel={() => setModalOpen(false)} onOk={() => form.submit()}>
                <Form form={form} layout="vertical" onFinish={handleCreate}>
                    <Form.Item name="name" label="项目名称" rules={[{ required: true, message: '请输入名称' }]}>
                        <Input placeholder="my-project" />
                    </Form.Item>
                    <Form.Item name="path" label="项目路径" rules={[{ required: true, message: '请输入路径' }]}>
                        <Input placeholder="/path/to/project" />
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
}
