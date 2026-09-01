import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, Space, message } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons';
import { scanApi } from '../services/api';

interface ScanRecord {
    id: string;
    path: string;
    status: string;
    files_scanned: number;
    total_vulnerabilities: number;
    created_at: string;
}

export default function Scans() {
    const [scans, setScans] = useState<ScanRecord[]>([]);
    const [loading, setLoading] = useState(false);
    const [modalOpen, setModalOpen] = useState(false);
    const [form] = Form.useForm();

    useEffect(() => { loadScans(); }, []);

    async function loadScans() {
        setLoading(true);
        try {
            const res = await scanApi.list();
            setScans(res.data?.scans ?? res.data ?? []);
        } catch { message.error('加载扫描列表失败'); }
        finally { setLoading(false); }
    }

    async function handleCreate(values: any) {
        try {
            await scanApi.create(values);
            message.success('扫描任务已创建');
            setModalOpen(false);
            form.resetFields();
            loadScans();
        } catch { message.error('创建扫描失败'); }
    }

    async function handleDelete(scanId: string) {
        try { await scanApi.delete(scanId); message.success('已删除'); loadScans(); }
        catch { message.error('删除失败'); }
    }

    const statusColor: Record<string, string> = { running: 'processing', completed: 'success', failed: 'error', pending: 'default' };

    const columns = [
        { title: '扫描ID', dataIndex: 'id', key: 'id', ellipsis: true },
        { title: '目标路径', dataIndex: 'path', key: 'path', ellipsis: true },
        { title: '状态', dataIndex: 'status', key: 'status', render: (s: string) => <Tag color={statusColor[s] ?? 'default'}>{s}</Tag> },
        { title: '文件数', dataIndex: 'files_scanned', key: 'files_scanned' },
        { title: '漏洞数', dataIndex: 'total_vulnerabilities', key: 'total_vulnerabilities' },
        { title: '创建时间', dataIndex: 'created_at', key: 'created_at' },
        { title: '操作', key: 'action', render: (_: any, r: ScanRecord) => <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)}>删除</Button> },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>扫描任务</h2>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={loadScans}>刷新</Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>新建扫描</Button>
                </Space>
            </div>
            <Table dataSource={scans} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 10 }} />
            <Modal title="新建扫描" open={modalOpen} onCancel={() => setModalOpen(false)} onOk={() => form.submit()}>
                <Form form={form} layout="vertical" onFinish={handleCreate}>
                    <Form.Item name="path" label="目标路径" rules={[{ required: true, message: '请输入路径' }]}>
                        <Input placeholder="/path/to/project" />
                    </Form.Item>
                    <Form.Item name="severity" label="严重级别过滤">
                        <Select allowClear placeholder="全部级别">
                            <Select.Option value="critical">Critical</Select.Option>
                            <Select.Option value="high">High</Select.Option>
                            <Select.Option value="medium">Medium</Select.Option>
                            <Select.Option value="low">Low</Select.Option>
                        </Select>
                    </Form.Item>
                    <Form.Item name="format" label="报告格式">
                        <Select placeholder="markdown" allowClear>
                            <Select.Option value="markdown">Markdown</Select.Option>
                            <Select.Option value="json">JSON</Select.Option>
                            <Select.Option value="html">HTML</Select.Option>
                        </Select>
                    </Form.Item>
                </Form>
            </Modal>
        </div>
    );
}
