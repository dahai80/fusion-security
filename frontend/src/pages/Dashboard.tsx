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
    // 规范 S1:状态色走 AntD theme token,随暗色算法自适应,禁硬编码 hex。
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
            setError(e.message || t('加载数据失败', 'Failed to load data'));
        } finally {
            setLoading(false);
        }
    }

    if (loading) return <Spin size="large" style={{ display: 'block', margin: '100px auto' }} />;
    if (error) return <Alert type="error" message={error} />;

    return (
        <div>
            <h2>{t('安全概览', 'Security overview')}</h2>
            <Row gutter={[16, 16]}>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('总扫描次数', 'Total scans')} value={stats?.total_scans ?? 0} prefix={<CheckCircleOutlined />} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('发现漏洞', 'Vulnerabilities')} value={stats?.total_vulns ?? 0} prefix={<BugOutlined />} valueStyle={{ color: token.colorWarning }} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('高危漏洞', 'High severity')} value={stats?.high_severity ?? 0} prefix={<WarningOutlined />} valueStyle={{ color: token.colorError }} />
                    </Card>
                </Col>
                <Col span={6}>
                    <Card>
                        <Statistic title={t('已修复', 'Fixed')} value={stats?.fixed ?? 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: token.colorSuccess }} />
                    </Card>
                </Col>
            </Row>

            <h2 style={{ marginTop: 24 }}>{t('系统健康', 'System health')}</h2>
            <Row gutter={[16, 16]}>
                {(() => {
                    // 后端 /health/detailed 返回扁平结构,非 components 嵌套。
                    const comps: Array<[string, string, string | null]> = [
                        [t('状态', 'Status'), health?.status ?? 'unknown', null],
                        [t('数据库', 'Database'), health?.database ?? 'unknown', null],
                        [t('AI 后端', 'AI backend'), health?.ai_backend ?? 'unknown', null],
                        [t('内存', 'Memory'), health?.memory_percent != null ? `${health.memory_percent.toFixed(1)}%` : 'N/A', null],
                        [t('CPU', 'CPU'), health?.cpu_percent != null ? `${health.cpu_percent.toFixed(1)}%` : 'N/A', null],
                        [t('磁盘', 'Disk'), health?.disk_percent != null ? `${health.disk_percent.toFixed(1)}%` : 'N/A', null],
                    ];
                    return comps.map(([name, status]) => {
                        const ok = status === 'ok' || status === 'degraded' || name === t('状态', 'Status');
                        const numeric = status.endsWith('%') && parseFloat(status) < 80;
                        const healthy = name === t('状态', 'Status') ? status !== 'degraded' : (status.endsWith('%') ? numeric : status === 'ok');
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
                {!health && <Col><Tag>{t('无法获取健康状态', 'Health status unavailable')}</Tag></Col>}
            </Row>
        </div>
    );
}
