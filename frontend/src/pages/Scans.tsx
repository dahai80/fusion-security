import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, Space, message } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons';
import { scanApi } from '../services/api';
import { useT } from '../i18n';

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
    const t = useT();

    useEffect(() => { loadScans(); }, []);

    async function loadScans() {
        setLoading(true);
        try {
            const res = await scanApi.list();
            setScans(res.data?.scans ?? res.data ?? []);
        } catch { message.error(t('加载扫描列表失败', 'Failed to load scans')); }
        finally { setLoading(false); }
    }

    async function handleCreate(values: any) {
        try {
            await scanApi.create(values);
            message.success(t('扫描任务已创建', 'Scan created'));
            setModalOpen(false);
            form.resetFields();
            loadScans();
        } catch { message.error(t('创建扫描失败', 'Failed to create scan')); }
    }

    async function handleDelete(scanId: string) {
        try { await scanApi.delete(scanId); message.success(t('已删除', 'Deleted')); loadScans(); }
        catch { message.error(t('删除失败', 'Failed to delete')); }
    }

    const statusColor: Record<string, string> = { running: 'processing', completed: 'success', failed: 'error', pending: 'default' };

    const columns = [
        { title: t('扫描ID', 'Scan ID'), dataIndex: 'id', key: 'id', ellipsis: true },
        { title: t('目标路径', 'Target path'), dataIndex: 'path', key: 'path', ellipsis: true },
        { title: t('状态', 'Status'), dataIndex: 'status', key: 'status', render: (s: string) => <Tag color={statusColor[s] ?? 'default'}>{s}</Tag> },
        { title: t('文件数', 'Files'), dataIndex: 'files_scanned', key: 'files_scanned' },
        { title: t('漏洞数', 'Vulns'), dataIndex: 'total_vulnerabilities', key: 'total_vulnerabilities' },
        { title: t('创建时间', 'Created'), dataIndex: 'created_at', key: 'created_at' },
        { title: t('操作', 'Actions'), key: 'action', render: (_: any, r: ScanRecord) => <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)}>{t('删除', 'Delete')}</Button> },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>{t('扫描任务', 'Scans')}</h2>
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={loadScans}>{t('刷新', 'Refresh')}</Button>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>{t('新建扫描', 'New scan')}</Button>
                </Space>
            </div>
            <Table dataSource={scans} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 10 }} />
            <Modal title={t('新建扫描', 'New scan')} open={modalOpen} onCancel={() => setModalOpen(false)} onOk={() => form.submit()}>
                <Form form={form} layout="vertical" onFinish={handleCreate}>
                    <Form.Item name="path" label={t('目标路径', 'Target path')} rules={[{ required: true, message: t('请输入路径', 'Path is required') }]}>
                        <Input placeholder="/path/to/project" />
                    </Form.Item>
                    <Form.Item name="severity" label={t('严重级别过滤', 'Severity filter')}>
                        <Select allowClear placeholder={t('全部级别', 'All levels')}>
                            <Select.Option value="critical">Critical</Select.Option>
                            <Select.Option value="high">High</Select.Option>
                            <Select.Option value="medium">Medium</Select.Option>
                            <Select.Option value="low">Low</Select.Option>
                        </Select>
                    </Form.Item>
                    <Form.Item name="format" label={t('报告格式', 'Report format')}>
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
