import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Row, Col, Card, Statistic, Tag, Spin, Alert, Select, List, Button, Typography, theme as antdTheme } from 'antd';
import {
    TeamOutlined,
    FileSearchOutlined,
    KeyOutlined,
    SafetyCertificateOutlined,
    WarningOutlined,
    RightOutlined,
} from '@ant-design/icons';
import { consoleApi } from '../services/api';
import { useT } from '../i18n';

// Issue #60(CS-1):Admin Console 首页 —— 四分区聚合(成员/审计/密钥/姿态)
// + 高风险事件速览 + 租户选择器。identity 数据可降级:降级分区显示原因,
// 绝不伪造数据。双语走 sdk.i18n(shell 宿主 lang 属性),暗色由 App 级主题承担。

interface Zone {
    available?: boolean;
    reason?: string;
    route?: string;
}

interface ConsoleSummary {
    tenant_id: string;
    members: Zone & { total?: number; pending?: number; active?: number };
    audit: Zone & { today_total: number; today_high_risk: number };
    keys: { local_active: number; local_expiring_soon: number; identity_inventory: Zone & { apps?: any[] }; route: string };
    posture: Zone & { todo_count: number; items: Array<{ id: string; state: string; detail: string; route: string }> };
    high_risk_events: Array<{ action: string; actor: string; risk_level: string; timestamp: number; trace_id: string }>;
}

const POSTURE_TITLES: Record<string, [string, string]> = {
    sso: ['SSO 单点登录', 'SSO'],
    retention: ['审计保留策略', 'Audit retention'],
    rate_limit: ['API 限流', 'API rate limiting'],
    jwt_verify: ['JWT 校验', 'JWT verification'],
    master_key: ['Master key 管理', 'Master key management'],
    key_expiry: ['密钥过期策略', 'Key expiry policy'],
};

export default function AdminConsole() {
    const [summary, setSummary] = useState<ConsoleSummary | null>(null);
    const [tenants, setTenants] = useState<Array<{ tenant_id: string; display_name: string }>>([]);
    const [tenant, setTenant] = useState<string>('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const navigate = useNavigate();
    const t = useT();
    // 规范 S1:状态色走 theme token,随暗色算法自适应。
    const { token } = antdTheme.useToken();

    useEffect(() => {
        loadTenants();
    }, []);

    useEffect(() => {
        loadSummary();
    }, [tenant]);

    async function loadTenants() {
        try {
            const res = await consoleApi.getTenants();
            const rows = res.data?.tenants || [];
            setTenants(rows);
            if (rows.length && !tenant) setTenant(rows[0].tenant_id);
            else if (!rows.length && !tenant) setTenant('default');
        } catch (e) {
            console.warn('[AdminConsole] tenants unavailable:', e);
            if (!tenant) setTenant('default');
        }
    }

    async function loadSummary() {
        if (!tenant) return;
        setLoading(true);
        setError('');
        try {
            const res = await consoleApi.getSummary();
            setSummary(res.data);
        } catch (e: any) {
            setError(e.message || t('加载失败', 'Failed to load'));
        } finally {
            setLoading(false);
        }
    }

    if (loading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />;
    if (error) return <Alert type="error" message={error} />;
    if (!summary) return <Alert type="warning" message={t('无数据', 'No data')} />;

    const degraded = (z: Zone) => !z.available && z.reason;

    const zoneCard = (
        title: string,
        icon: React.ReactNode,
        z: Zone,
        main: React.ReactNode,
        sub: React.ReactNode,
        route: string,
    ) => (
        <Card
            hoverable
            onClick={() => navigate(route)}
            styles={{ body: { padding: 20 } }}
        >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 15, fontWeight: 600 }}>
                    {icon} {title}
                </span>
                <RightOutlined style={{ fontSize: 12, opacity: 0.4 }} />
            </div>
            {degraded(z) ? (
                <div style={{ marginTop: 12 }}>
                    <Tag color="default">{t('数据不可用', 'Unavailable')}</Tag>
                    <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 4 }}>
                        {z.reason}
                    </Typography.Text>
                </div>
            ) : (
                <>
                    <div style={{ marginTop: 12 }}>{main}</div>
                    <div style={{ marginTop: 8 }}>{sub}</div>
                </>
            )}
        </Card>
    );

    return (
        <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h2 style={{ margin: 0 }}>{t('管理控制台', 'Admin Console')}</h2>
                <Select
                    value={tenant}
                    onChange={setTenant}
                    style={{ minWidth: 160 }}
                    options={tenants.map((x) => ({ value: x.tenant_id, label: x.display_name || x.tenant_id }))}
                    loading={!tenants.length}
                />
            </div>

            <Row gutter={[16, 16]}>
                <Col xs={24} md={12} xl={6}>
                    {zoneCard(
                        t('成员与访问', 'Members & access'),
                        <TeamOutlined />,
                        summary.members,
                        <Statistic value={summary.members.total ?? 0} title={t('成员总数', 'Members')} />,
                        <span>
                            {t('待审批', 'Pending')} <b>{summary.members.pending ?? 0}</b> · {t('活跃', 'Active')} {summary.members.active ?? 0}
                        </span>,
                        '/console',
                    )}
                </Col>
                <Col xs={24} md={12} xl={6}>
                    {zoneCard(
                        t('审计日志', 'Audit log'),
                        <FileSearchOutlined />,
                        summary.audit,
                        <Statistic value={summary.audit.today_total} title={t('今日事件', 'Events today')} />,
                        <span>
                            {t('高风险', 'High risk')}{' '}
                            <b style={{ color: summary.audit.today_high_risk ? token.colorError : undefined }}>
                                {summary.audit.today_high_risk}
                            </b>
                        </span>,
                        '/audit',
                    )}
                </Col>
                <Col xs={24} md={12} xl={6}>
                    {zoneCard(
                        t('密钥与策略', 'Keys & policies'),
                        <KeyOutlined />,
                        summary.keys.identity_inventory,
                        <Statistic value={summary.keys.local_active} title={t('活跃服务 key', 'Active keys')} />,
                        <span>
                            {t('即将过期', 'Expiring soon')}{' '}
                            <b style={{ color: summary.keys.local_expiring_soon ? token.colorWarning : undefined }}>
                                {summary.keys.local_expiring_soon}
                            </b>
                        </span>,
                        '/keys',
                    )}
                </Col>
                <Col xs={24} md={12} xl={6}>
                    {zoneCard(
                        t('姿态合规', 'Posture & compliance'),
                        <SafetyCertificateOutlined />,
                        summary.posture,
                        <Statistic value={summary.posture.todo_count} title={t('待办项', 'Open items')} />,
                        <span>
                            {summary.posture.items.filter((c) => c.state === 'ok').length} {t('项通过', 'checks passing')}
                        </span>,
                        '/keys',
                    )}
                </Col>
            </Row>

            <Card
                title={
                    <span>
                        <WarningOutlined style={{ color: token.colorWarning }} /> {t('高风险事件', 'High-risk events')}
                    </span>
                }
                extra={
                    <Button type="link" size="small" onClick={() => navigate('/audit')}>
                        {t('全部', 'View all')}
                    </Button>
                }
                style={{ marginTop: 16 }}
            >
                {summary.high_risk_events.length === 0 ? (
                    <Typography.Text type="secondary">{t('暂无高风险事件', 'No high-risk events')}</Typography.Text>
                ) : (
                    <List
                        dataSource={summary.high_risk_events}
                        renderItem={(e) => (
                            <List.Item
                                actions={[
                                    <Button key="open" type="link" size="small" onClick={() => navigate('/audit')}>
                                        {t('处置', 'Respond')}
                                    </Button>,
                                ]}
                            >
                                <List.Item.Meta
                                    title={
                                        <span>
                                            <Tag color={e.risk_level === 'critical' ? 'red' : 'volcano'}>
                                                {e.risk_level}
                                            </Tag>
                                            {e.action} · {e.actor}
                                        </span>
                                    }
                                    description={
                                        <span>
                                            {new Date(e.timestamp * 1000).toLocaleString()}
                                            {e.trace_id ? ` · trace: ${e.trace_id}` : ''}
                                        </span>
                                    }
                                />
                            </List.Item>
                        )}
                    />
                )}
            </Card>
        </div>
    );
}
