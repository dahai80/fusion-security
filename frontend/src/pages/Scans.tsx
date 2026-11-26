import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, Space, Empty, message } from 'antd';
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
        } catch { message.error(t('加载扫描列表失败', 'Failed to load scans')); } // i18n: user-facing
        finally { setLoading(false); }
    }

    async function handleCreate(values: any) {
        try {
            await scanApi.create(values);
            message.success(t('扫描任务已创建', 'Scan created')); // i18n: user-facing
            setModalOpen(false);
            form.resetFields();
            loadScans();
        } catch { message.error(t('创建扫描失败', 'Failed to create scan')); } // i18n: user-facing
    }

    async function handleDelete(scanId: string) {
        try { await scanApi.delete(scanId); message.success(t('已删除', 'Deleted')); loadScans(); } // i18n: user-facing
        catch { message.error(t('删除失败', 'Failed to delete')); } // i18n: user-facing
    }

    const statusColor: Record<string, string> = { running: 'processing', completed: 'success', failed: 'error', pending: 'default' };

    const columns = [
        { title: t('扫描ID', 'Scan ID'), dataIndex: 'id', key: 'id', ellipsis: true }, // i18n: user-facing
        { title: t('目标路径', 'Target path'), dataIndex: 'path', key: 'path', ellipsis: true }, // i18n: user-facing
        { title: t('状态', 'Status'), dataIndex: 'status', key: 'status', render: (s: string) => <Tag color={statusColor[s] ?? 'default'}>{s}</Tag> }, // i18n: user-facing
        { title: t('文件数', 'Files'), dataIndex: 'files_scanned', key: 'files_scanned' }, // i18n: user-facing
        { title: t('漏洞数', 'Vulns'), dataIndex: 'total_vulnerabilities', key: 'total_vulnerabilities' }, // i18n: user-facing
        { title: t('创建时间', 'Created'), dataIndex: 'created_at', key: 'created_at' }, // i18n: user-facing
        { title: t('操作', 'Actions'), key: 'action', render: (_: any, r: ScanRecord) => <Button size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(r.id)}>{t('删除', 'Delete')}</Button> }, // i18n: user-facing
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>{t('扫描任务', 'Scans')}</h2>{/* i18n: user-facing */}
                <Space>
                    <Button icon={<ReloadOutlined />} onClick={loadScans}>{t('刷新', 'Refresh')}</Button>{/* i18n: user-facing */}
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>{t('新建扫描', 'New scan')}</Button>{/* i18n: user-facing */}
                </Space>
            </div>
            <Table
                dataSource={scans}
                columns={columns}
                rowKey="id"
                loading={loading}
                pagination={{ pageSize: 10 }}
                locale={{
                    emptyText: (
                        <Empty description={t('暂无扫描任务', 'No scans yet')}>{/* i18n: user-facing */}
                            <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
                                {t('立即发起扫描', 'Start your first scan')}{/* i18n: user-facing */}
                            </Button>
                        </Empty>
                    ),
                }}
            />
            <Modal title={t('新建扫描', 'New scan')} open={modalOpen} onCancel={() => setModalOpen(false)} onOk={() => form.submit()}>{/* i18n: user-facing */}
                <Form form={form} layout="vertical" onFinish={handleCreate}>
                    <Form.Item name="path" label={t('目标路径', 'Target path')} rules={[{ required: true, message: t('请输入路径', 'Path is required') }]}>{/* i18n: user-facing */}
                        <Input placeholder="/path/to/project" />
                    </Form.Item>
                    <Form.Item name="severity" label={t('严重级别过滤', 'Severity filter')}>{/* i18n: user-facing */}
                        <Select allowClear placeholder={t('全部级别', 'All levels')}>{/* i18n: user-facing */}
                            <Select.Option value="critical">Critical</Select.Option>
                            <Select.Option value="high">High</Select.Option>
                            <Select.Option value="medium">Medium</Select.Option>
                            <Select.Option value="low">Low</Select.Option>
                        </Select>
                    </Form.Item>
                    <Form.Item name="format" label={t('报告格式', 'Report format')}>{/* i18n: user-facing */}
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
