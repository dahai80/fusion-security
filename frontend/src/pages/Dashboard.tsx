import { useEffect, useState } from 'react';
import { Row, Col, Card, Statistic, Tag, Spin, Alert, theme as antdTheme } from 'antd';
import {
    BugOutlined,
    CheckCircleOutlined,
    WarningOutlined,
    CloseCircleOutlined,
} from '@ant-design/icons';
import { dashboardApi } from '../services/api';
import { useT } from '../i18n';

interface DashboardStats {
    total_scans: number;
    total_vulns: number;
    high_severity: number;
    fixed: number;
}

interface HealthData {
    status: string;
    database: string;
    ai_backend: string;
    memory_percent: number | null;
    cpu_percent: number | null;
    disk_percent: number | null;
}

export default function Dashboard() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [health, setHealth] = useState<HealthData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const t = useT();
// Spec S1: status colors use AntD theme tokens, adaptive with the dark algorithm; no hardcoded hex.
    const { token } = antdTheme.useToken();

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
            setError(e.message || t('加载数据失败', 'Failed to load data')); // i18n: user-facing
        } finally {
            setLoading(false);
        }
    }

    if (loading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />;
    if (error) return <Alert type="error" message={error} />;

    return (
        <div>
            <h2>{t('安全概览', 'Security overview')}</h2>{/* i18n: user-facing */}
            <Row gutter={[16, 16]}>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('总扫描次数', 'Total scans')} value={stats?.total_scans ?? 0} prefix={<CheckCircleOutlined />} />{/* i18n: user-facing */}
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('发现漏洞', 'Vulnerabilities')} value={stats?.total_vulns ?? 0} prefix={<BugOutlined />} valueStyle={{ color: token.colorWarning }} />{/* i18n: user-facing */}
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('高危漏洞', 'High severity')} value={stats?.high_severity ?? 0} prefix={<WarningOutlined />} valueStyle={{ color: token.colorError }} />{/* i18n: user-facing */}
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('已修复', 'Fixed')} value={stats?.fixed ?? 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: token.colorSuccess }} />{/* i18n: user-facing */}
                    </Card>
                </Col>
            </Row>

            <h2 style={{ marginTop: 24 }}>{t('系统健康', 'System health')}</h2>{/* i18n: user-facing */}
            <Row gutter={[16, 16]}>
                {(() => {
// Backend /health/detailed returns a flat structure, not nested components.
                    const comps: Array<[string, string, string | null]> = [
                        [t('状态', 'Status'), health?.status ?? 'unknown', null], // i18n: user-facing
                        [t('数据库', 'Database'), health?.database ?? 'unknown', null], // i18n: user-facing
                        [t('AI 后端', 'AI backend'), health?.ai_backend ?? 'unknown', null], // i18n: user-facing
                        [t('内存', 'Memory'), health?.memory_percent != null ? `${health.memory_percent.toFixed(1)}%` : 'N/A', null], // i18n: user-facing
                        [t('CPU', 'CPU'), health?.cpu_percent != null ? `${health.cpu_percent.toFixed(1)}%` : 'N/A', null],
                        [t('磁盘', 'Disk'), health?.disk_percent != null ? `${health.disk_percent.toFixed(1)}%` : 'N/A', null], // i18n: user-facing
                    ];
                    return comps.map(([name, status]) => {
                        const ok = status === 'ok' || status === 'degraded' || name === t('状态', 'Status'); // i18n: user-facing
                        const numeric = status.endsWith('%') && parseFloat(status) < 80;
                        const healthy = name === t('状态', 'Status') ? status !== 'degraded' : (status.endsWith('%') ? numeric : status === 'ok'); // i18n: user-facing
                        return (
                            <Col span={8} key={name}>
                                <Card size="small">
                                    <Statistic
                                        title={name}
                                        value={status}
                                        prefix={healthy ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
                                        valueStyle={{ color: healthy ? token.colorSuccess : token.colorError, fontSize: 16 }}
                                    />
                                </Card>
                            </Col>
                        );
                    });
                })()}
                {!health && <Col><Tag>{t('无法获取健康状态', 'Health status unavailable')}</Tag></Col>}{/* i18n: user-facing */}
            </Row>
        </div>
    );
}
