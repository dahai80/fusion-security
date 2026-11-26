import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Tag, Button, Space, Modal, message, Descriptions, Input, Empty, theme as antdTheme } from 'antd';
import { ReloadOutlined, EyeOutlined } from '@ant-design/icons';
import { vulnApi, patchApi } from '../services/api';
import { useT } from '../i18n';
import { severityTagColor } from '../severity';

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
    const t = useT();
    const navigate = useNavigate();
// Spec S1: code snippet background uses the theme token, dark-mode adaptive.
    const { token } = antdTheme.useToken();

    useEffect(() => { loadVulns(); }, []);

    async function loadVulns() {
        setLoading(true);
        try {
            const params: any = {};
            if (filterRule) params.rule_id = filterRule;
            const res = await vulnApi.list(params);
            setVulns(res.data?.vulnerabilities ?? res.data ?? []);
        } catch { message.error(t('加载漏洞列表失败', 'Failed to load vulnerabilities')); } // i18n: user-facing
        finally { setLoading(false); }
    }

    async function showDetail(id: string) {
        try { const res = await vulnApi.get(id); setDetail(res.data); setDetailOpen(true); }
        catch { message.error(t('获取详情失败', 'Failed to load detail')); } // i18n: user-facing
    }

    async function markFalsePositive(id: string) {
        try { await vulnApi.markFalsePositive(id, '手动标记'); message.success(t('已标记为误报', 'Marked as false positive')); loadVulns(); } // i18n: user-facing
        catch { message.error(t('操作失败', 'Operation failed')); } // i18n: user-facing
    }

    async function generatePatch(vulnId: string) {
        try { await patchApi.generate(vulnId); message.success(t('补丁已生成', 'Patch generated')); } // i18n: user-facing
        catch { message.error(t('补丁生成失败', 'Failed to generate patch')); } // i18n: user-facing
    }

    const columns = [
        { title: t('规则ID', 'Rule ID'), dataIndex: 'rule_id', key: 'rule_id' }, // i18n: user-facing
        { title: t('严重级别', 'Severity'), dataIndex: 'severity', key: 'severity', render: (s: string) => <Tag color={severityTagColor(s)}>{s?.toUpperCase()}</Tag> }, // i18n: user-facing
        { title: t('文件', 'File'), dataIndex: 'file_path', key: 'file_path', ellipsis: true }, // i18n: user-facing
        { title: t('行号', 'Line'), dataIndex: 'line_number', key: 'line_number' }, // i18n: user-facing
        { title: t('置信度', 'Confidence'), dataIndex: 'confidence', key: 'confidence', render: (c: number) => `${c ?? 0}%` }, // i18n: user-facing
        { title: t('状态', 'Status'), dataIndex: 'status', key: 'status', render: (s: string) => <Tag>{s}</Tag> }, // i18n: user-facing
        {
            title: t('操作', 'Actions'), key: 'action', // i18n: user-facing
            render: (_: any, r: VulnRecord) => (
                <Space>
                    <Button size="small" icon={<EyeOutlined />} onClick={() => showDetail(r.id)}>{t('详情', 'Detail')}</Button>{/* i18n: user-facing */}
                    <Button size="small" onClick={() => markFalsePositive(r.id)}>{t('误报', 'False positive')}</Button>{/* i18n: user-facing */}
                    <Button size="small" type="primary" onClick={() => generatePatch(r.id)}>{t('补丁', 'Patch')}</Button>{/* i18n: user-facing */}
                </Space>
            ),
        },
    ];

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
                <h2>{t('漏洞管理', 'Vulnerabilities')}</h2>{/* i18n: user-facing */}
                <Space>
                    <Input.Search placeholder={t('按规则ID过滤', 'Filter by rule ID')} value={filterRule} onChange={e => setFilterRule(e.target.value)} onSearch={loadVulns} style={{ width: 200 }} allowClear />{/* i18n: user-facing */}
                    <Button icon={<ReloadOutlined />} onClick={loadVulns}>{t('刷新', 'Refresh')}</Button>{/* i18n: user-facing */}
                </Space>
            </div>
            <Table
                dataSource={vulns}
                columns={columns}
                rowKey="id"
                loading={loading}
                pagination={{ pageSize: 15 }}
                locale={{
                    emptyText: (
                        <Empty description={t('暂无漏洞记录', 'No vulnerabilities yet')}>{/* i18n: user-facing */}
                            <Button type="primary" onClick={() => navigate('/scans')}>
                                {t('去发起扫描', 'Run a scan first')}{/* i18n: user-facing */}
                            </Button>
                        </Empty>
                    ),
                }}
            />
            <Modal title={t('漏洞详情', 'Vulnerability detail')} open={detailOpen} onCancel={() => setDetailOpen(false)} footer={null} width={640}>{/* i18n: user-facing */}
                {detail && (
                    <Descriptions column={1} bordered size="small">
                        <Descriptions.Item label={t('规则ID', 'Rule ID')}>{detail.rule_id}</Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('严重级别', 'Severity')}><Tag color={severityTagColor(detail.severity)}>{detail.severity?.toUpperCase()}</Tag></Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('文件', 'File')}>{detail.file_path}</Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('行号', 'Line')}>{detail.line_number}</Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('置信度', 'Confidence')}>{detail.confidence}%</Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('描述', 'Description')}>{detail.description}</Descriptions.Item>{/* i18n: user-facing */}
                        <Descriptions.Item label={t('状态', 'Status')}>{detail.status}</Descriptions.Item>{/* i18n: user-facing */}
                        {detail.code_snippet && <Descriptions.Item label={t('代码片段', 'Code snippet')}><pre style={{ background: token.colorFillTertiary, padding: 8, borderRadius: 4, fontSize: 12, overflow: 'auto' }}>{detail.code_snippet}</pre></Descriptions.Item>}{/* i18n: user-facing */}
                    </Descriptions>
                )}
            </Modal>
        </div>
    );
}
