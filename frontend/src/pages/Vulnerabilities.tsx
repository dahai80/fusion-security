import { useEffect, useState } from 'react';
import { Table, Tag, Button, Space, Modal, message, Descriptions, Input } from 'antd';
import { ReloadOutlined, EyeOutlined } from '@ant-design/icons';
import { vulnApi, patchApi } from '../services/api';

interface VulnRecord {
    id: string;
    rule_id: string;
    severity: string;
    file_path: string;
    line_number: number;
    description: string;
    confidence: number;
    status: string;
    code_snippet?: string;
}

export default function Vulnerabilities() {
    const [vulns, setVulns] = useState<VulnRecord[]>([]);
    const [loading, setLoading] = useState(false);
    const [detail, setDetail] = useState<VulnRecord | null>(null);
    const [detailOpen, setDetailOpen] = useState(false);
    const [filterRule, setFilterRule] = useState('');

    useEffect(() => { loadVulns(); }, []);

    async function loadVulns() {
        setLoading(true);
        try {
            const params: any = {};
            if (filterRule) params.rule_id = filterRule;
            const res = await vulnApi.list(params);
            setVulns(res.data?.vulnerabilities ?? res.data ?? []);
        } catch { message.error('加载漏洞列表失败'); }
        finally { setLoading(false); }
    }

    async function showDetail(id: string) {
        try { const res = await vulnApi.get(id); setDetail(res.data); setDetailOpen(true); }
        catch { message.error('获取详情失败'); }
    }

    async function markFalsePositive(id: string) {
        try { await vulnApi.markFalsePositive(id, '手动标记'); message.success('已标记为误报'); loadVulns(); }
        catch { message.error('操作失败'); }
    }

    async function generatePatch(vulnId: string) {
        try { await patchApi.generate(vulnId); message.success('补丁已生成'); }
        catch { message.error('补丁生成失败'); }
    }

    const sevColor: Record<string, string> = { critical: '#cf1322', high: '#fa541c', medium: '#faad14', low: '#52c41a', info: '#1890ff' };

    const columns = [
        { title: '规则ID', dataIndex: 'rule_id', key: 'rule_id' },
        { title: '严重级别', dataIndex: 'severity', key: 'severity', render: (s: string) => <Tag color={sevColor[s] ?? 'default'}>{s?.toUpperCase()}</Tag> },
        { title: '文件', dataIndex: 'file_path', key: 'file_path', ellipsis: true },
        { title: '行号', dataIndex: 'line_number', key: 'line_number' },
        { title: '置信度', dataIndex: 'confidence', key: 'confidence', render: (c: number) => `${c ?? 0}%` },
        { title: '状态', dataIndex: 'status', key: 'status', render: (s: string) => <Tag>{s}</Tag> },
        {
            title: '操作', key: 'action',
            render: (_: any, r: VulnRecord) => (
                <Space>
                    <Button size="small" icon={<EyeOutlined />} onClick={() => showDetail(r.id)}>详情</Button>
                    <Button size="small" onClick={() => markFalsePositive(r.id)}>误报</Button>
                    <Button size="small" type="primary" onClick={() => generatePatch(r.id)}>补丁</Button>
                </Space>
            ),
        },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>漏洞管理</h2>
                <Space>
                    <Input.Search placeholder="按规则ID过滤" value={filterRule} onChange={e => setFilterRule(e.target.value)} onSearch={loadVulns} style={{ width: 200 }} allowClear />
                    <Button icon={<ReloadOutlined />} onClick={loadVulns}>刷新</Button>
                </Space>
            </div>
            <Table dataSource={vulns} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 15 }} />
            <Modal title="漏洞详情" open={detailOpen} onCancel={() => setDetailOpen(false)} footer={null} width={640}>
                {detail && (
                    <Descriptions column={1} bordered size="small">
                        <Descriptions.Item label="规则ID">{detail.rule_id}</Descriptions.Item>
                        <Descriptions.Item label="严重级别"><Tag color={sevColor[detail.severity]}>{detail.severity?.toUpperCase()}</Tag></Descriptions.Item>
                        <Descriptions.Item label="文件">{detail.file_path}</Descriptions.Item>
                        <Descriptions.Item label="行号">{detail.line_number}</Descriptions.Item>
                        <Descriptions.Item label="置信度">{detail.confidence}%</Descriptions.Item>
                        <Descriptions.Item label="描述">{detail.description}</Descriptions.Item>
                        <Descriptions.Item label="状态">{detail.status}</Descriptions.Item>
                        {detail.code_snippet && <Descriptions.Item label="代码片段"><pre style={{ background: '#f5f5f5', padding: 8, borderRadius: 4, fontSize: 12, overflow: 'auto' }}>{detail.code_snippet}</pre></Descriptions.Item>}
                    </Descriptions>
                )}
            </Modal>
        </div>
    );
}
