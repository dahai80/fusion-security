import { useEffect, useState } from 'react';
import { Row, Col, Card, Statistic, Tag, Spin, Alert } from 'antd';
import {
    BugOutlined,
    CheckCircleOutlined,
    WarningOutlined,
    CloseCircleOutlined,
} from '@ant-design/icons';
import { dashboardApi } from '../services/api';

interface DashboardStats {
    total_scans: number;
    total_vulns: number;
    high_severity: number;
    critical: number;
    false_positives: number;
    fixed: number;
}

interface HealthData {
    status: string;
    components: Record<string, { status: string; detail?: string }>;
}

export default function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [health, setHealth] = useState<HealthData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        loadData();
    }, []);

    async function loadData() {
        setLoading(true);
        setError('');
        try {
            const [statsRes, healthRes] = await Promise.allSettled([
                dashboardApi.getStats(),
                dashboardApi.getHealth(),
            ]);
            if (statsRes.status === 'fulfilled') setStats(statsRes.value.data);
            if (healthRes.status === 'fulfilled') setHealth(healthRes.value.data);
        } catch (e: any) {
            setError(e.message || '加载数据失败');
        } finally {
            setLoading(false);
        }
    }

    if (loading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />;
    if (error) return <Alert type="error" message={error} />;

    const sevColor = (level: string) => {
        switch (level) {
            case 'critical': return '#cf1322';
            case 'high': return '#fa541c';
            case 'medium': return '#faad14';
            case 'low': return '#52c41a';
            default: return '#8c8c8c';
        }
    };

    return (
        <div>
            <h2>安全概览</h2>
            <Row gutter={[16, 16]}>
                <Col span={6}>
                    <Card>
                        <Statistic title="总扫描次数" value={stats?.total_scans ?? 0} prefix={<CheckCircleOutlined />} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title="发现漏洞" value={stats?.total_vulns ?? 0} prefix={<BugOutlined />} valueStyle={{ color: sevColor('high') }} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title="高危漏洞" value={stats?.high_severity ?? 0} prefix={<WarningOutlined />} valueStyle={{ color: sevColor('critical') }} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title="已修复" value={stats?.fixed ?? 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: sevColor('low') }} />
                    </Card>
                </Col>
            </Row>

            <h2 style={{ marginTop: 24 }}>系统健康</h2>
            <Row gutter={[16, 16]}>
                {health?.components && Object.entries(health.components).map(([name, info]) => (
                    <Col span={8} key={name}>
                        <Card size="small">
                            <Statistic
                                title={name}
                                value={info.status}
                                prefix={info.status === 'ok' ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
                                valueStyle={{ color: info.status === 'ok' ? '#52c41a' : '#cf1322', fontSize: 16 }}
                            />
                            {info.detail && <div style={{ marginTop: 8, color: '#8c8c8c', fontSize: 12 }}>{info.detail}</div>}
                        </Card>
                    </Col>
                ))}
                {!health && <Col><Tag>无法获取健康状态</Tag></Col>}
            </Row>
        </div>
    );
}
