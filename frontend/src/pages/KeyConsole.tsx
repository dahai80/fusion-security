import { useEffect, useState } from 'react';
import {
    Table, Card, Button, Modal, Input, InputNumber, message, Tag, Typography, DatePicker, Switch, Alert, Space, List,
} from 'antd';
import { SyncOutlined, ClockCircleOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { consoleApi } from '../services/api';
import { useT } from '../i18n';

// Issue #62 (CS-3): centralized key console — local service keys (expiry/enable) + identity
// module key ledger (rotation with grace window; revocation depends on upstream fusion-identity#35) + SSO panel
// (rendered per real identity capabilities; unreadable = explicitly disabled + roadmap note).

interface LocalKey {
    id: string;
    name: string;
    role: string;
    enabled: boolean;
    created_at: string;
    last_used_at: string;
    expires_at: string;
}

interface IdentityApp {
    app_id: string;
    versions?: number;
    current_version?: number;
    status?: string;
    grace_until?: string | null;
}

interface SsoState {
    state: 'configured' | 'not_configured' | 'unavailable';
    reason?: string;
    detail?: string;
    types?: string[];
    count?: number;
    auto_provision?: boolean;
}

export default function KeyConsole() {
    const [localKeys, setLocalKeys] = useState<LocalKey[]>([]);
    const [identity, setIdentity] = useState<{ available: boolean; reason?: string; apps: IdentityApp[] }>({ available: false, apps: [] });
    const [sso, setSso] = useState<SsoState | null>(null);
    const [loading, setLoading] = useState(false);
    const [rotateOpen, setRotateOpen] = useState(false);
    const [rotateApp, setRotateApp] = useState('');
    const [graceMinutes, setGraceMinutes] = useState(60);
    const [rotatedSecret, setRotatedSecret] = useState('');
    const [expiryKey, setExpiryKey] = useState<LocalKey | null>(null);
    const [expiryDate, setExpiryDate] = useState<any>(null);
    const t = useT();

    const load = async () => {
        setLoading(true);
        try {
            const [keysRes, ssoRes] = await Promise.allSettled([consoleApi.getKeys(), consoleApi.getSso()]);
            if (keysRes.status === 'fulfilled') {
                setLocalKeys(keysRes.value.data.local || []);
                setIdentity(keysRes.value.data.identity || { available: false, apps: [] });
            }
            if (ssoRes.status === 'fulfilled') setSso(ssoRes.value.data);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        load();
    }, []);

    const doRotate = async () => {
        if (!rotateApp.trim()) return;
        try {
            const res = await consoleApi.rotateKey({ app_id: rotateApp.trim(), grace_seconds: graceMinutes * 60 });
            setRotatedSecret(res.data.secret || '');
            setRotateOpen(false);
            message.success(t('轮换成功,旧 key 在宽限期内仍有效', 'Rotated — old key stays valid during the grace window')); // i18n: user-facing
            load();
        } catch (e: any) {
            message.error(e.message || t('轮换失败', 'Rotation failed')); // i18n: user-facing
        }
    };

    const saveExpiry = async () => {
        if (!expiryKey) return;
        try {
            await consoleApi.patchLocalKey(expiryKey.id, {
                expires_at: expiryDate ? expiryDate.toISOString() : '',
            });
            message.success(t('已更新过期时间', 'Expiry updated')); // i18n: user-facing
            setExpiryKey(null);
            setExpiryDate(null);
            load();
        } catch (e: any) {
            message.error(e.message || t('更新失败', 'Update failed')); // i18n: user-facing
        }
    };

    const toggleKey = async (k: LocalKey, enabled: boolean) => {
        try {
            await consoleApi.patchLocalKey(k.id, { enabled });
            load();
        } catch (e: any) {
            message.error(e.message || t('更新失败', 'Update failed')); // i18n: user-facing
        }
    };

    const localColumns: ColumnsType<LocalKey> = [
        { title: t('名称', 'Name'), dataIndex: 'name' }, // i18n: user-facing
        { title: t('角色', 'Role'), dataIndex: 'role', width: 100, render: (r: string) => <Tag>{r}</Tag> }, // i18n: user-facing
        { title: t('最近使用', 'Last used'), dataIndex: 'last_used_at', width: 170, render: (v: string) => (v ? new Date(v).toLocaleString() : '-') }, // i18n: user-facing
        {
            title: t('过期时间', 'Expires'), // i18n: user-facing
            dataIndex: 'expires_at',
            width: 170,
            render: (v: string) =>
                v ? (
                    <span>
                        <ClockCircleOutlined /> {new Date(v).toLocaleDateString()}
                    </span>
                ) : (
                    <Tag color="orange">{t('未设置', 'Not set')}</Tag>{/* i18n: user-facing */}
                ),
        },
        {
            title: t('启用', 'Enabled'), // i18n: user-facing
            dataIndex: 'enabled',
            width: 90,
            render: (v: boolean, k: LocalKey) => <Switch size="small" checked={v} onChange={(nv) => toggleKey(k, nv)} />,
        },
        {
            title: '',
            width: 120,
            render: (_: any, k: LocalKey) => (
                <Button size="small" onClick={() => { setExpiryKey(k); setExpiryDate(k.expires_at ? (new Date(k.expires_at) as any) : null); }}>
                    {t('设过期', 'Set expiry')}{/* i18n: user-facing */}
                </Button>
            ),
        },
    ];

    return (
        <div>
            <h2>{t('密钥与策略', 'Keys & policies')}</h2>{/* i18n: user-facing */}

            <Card title={t('模块服务 key(identity 台账)', 'Module service keys (identity ledger)')} style={{ marginBottom: 16 }}>{/* i18n: user-facing */}
                {identity.available ? (
                    <Table<IdentityApp>
                        rowKey="app_id"
                        size="small"
                        loading={loading}
                        dataSource={identity.apps}
                        pagination={false}
                        columns={[
                            { title: 'app', dataIndex: 'app_id' },
                            { title: t('当前版本', 'Current'), dataIndex: 'current_version', width: 110 }, // i18n: user-facing
                            { title: t('状态', 'Status'), dataIndex: 'status', width: 110, render: (s: string) => <Tag color={s === 'active' ? 'green' : 'orange'}>{s || '-'}</Tag> }, // i18n: user-facing
                            { title: t('宽限期至', 'Grace until'), dataIndex: 'grace_until', width: 170, render: (v: any) => (v ? new Date(v).toLocaleString() : '-') }, // i18n: user-facing
                            {
                                title: '',
                                width: 110,
                                render: (_: any, a: IdentityApp) => (
                                    <Button size="small" icon={<SyncOutlined />} onClick={() => { setRotateApp(a.app_id); setRotateOpen(true); }}>
                                        {t('轮换', 'Rotate')}{/* i18n: user-facing */}
                                    </Button>
                                ),
                            },
                        ]}
                    />
                ) : (
                    <Alert type="info" showIcon message={identity.reason || t('identity 台账不可用', 'Identity ledger unavailable')} />{/* i18n: user-facing */}
                )}
                <Space style={{ marginTop: 12 }}>
                    <Button onClick={() => { setRotateApp(''); setRotateOpen(true); }}>{t('按 app_id 轮换', 'Rotate by app_id')}</Button>{/* i18n: user-facing */}
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t(
                            '轮换 = identity 签发新版本,旧 key 进 grace 窗口;agent-studio 的 agent key 注册进同一台账(fusion-agent-studio#530)。', // i18n: user-facing
                            'Rotation issues a new version via identity; the old key enters a grace window. agent-studio agent keys join the same ledger (fusion-agent-studio#530).',
                        )}
                    </Typography.Text>
                </Space>
            </Card>

            <Card title={t('本地服务 key', 'Local service keys')} style={{ marginBottom: 16 }}>{/* i18n: user-facing */}
                <Table<LocalKey> rowKey="id" size="small" loading={loading} dataSource={localKeys} columns={localColumns} pagination={false} />
            </Card>

            <Card title={t('SSO 单点登录', 'SSO')}>{/* i18n: user-facing */}
                {!sso ? (
                    <Typography.Text type="secondary">...</Typography.Text>
                ) : sso.state === 'configured' ? (
                    <List size="small">
                        <List.Item>
                            <Tag color="green">{t('已配置', 'Configured')}</Tag> {sso.types?.join(', ')} · {t('自动开通', 'auto-provision')}: {String(sso.auto_provision)}{/* i18n: user-facing */}
                        </List.Item>
                    </List>
                ) : sso.state === 'not_configured' ? (
                    <Alert type="warning" showIcon message={t('租户未配置 IdP', 'No IdP configured for this tenant')} description={sso.detail} />{/* i18n: user-facing */}
                ) : (
                    <Alert type="info" showIcon message={t('SSO 状态不可读', 'SSO state unavailable')} description={sso.detail || sso.reason} />{/* i18n: user-facing */}
                )}
            </Card>

            <Modal
                title={`${t('轮换模块 key', 'Rotate module key')}${rotateApp ? `: ${rotateApp}` : ''}`} // i18n: user-facing
                open={rotateOpen}
                onOk={doRotate}
                onCancel={() => setRotateOpen(false)}
                okText={t('轮换', 'Rotate')} // i18n: user-facing
            >
                <Space direction="vertical" style={{ width: '100%' }}>
                    {!rotateApp && (
                        <Input placeholder="app_id (如 fusion-mlx)" value={rotateApp} onChange={(e) => setRotateApp(e.target.value)} />{/* i18n: user-facing */}
                    )}
                    <div>
                        {t('宽限期(分钟)', 'Grace window (minutes)')}:{' '}{/* i18n: user-facing */}
                        <InputNumber min={0} max={43200} value={graceMinutes} onChange={(v) => setGraceMinutes(v || 0)} />
                    </div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t('新 key 仅在轮换响应中显示一次,请立即更新到对应模块的配置。', 'The new key is shown only once — update the consuming module immediately.')}{/* i18n: user-facing */}
                    </Typography.Text>
                </Space>
            </Modal>

            <Modal
                title={t('设置过期时间', 'Set expiry')} // i18n: user-facing
                open={!!expiryKey}
                onOk={saveExpiry}
                onCancel={() => { setExpiryKey(null); setExpiryDate(null); }}
                okText={t('保存', 'Save')} // i18n: user-facing
            >
                <DatePicker
                    showTime
                    style={{ width: '100%' }}
                    value={expiryDate}
                    onChange={setExpiryDate}
                    placeholder={t('留空 = 清除过期限制', 'Empty = no expiry')} // i18n: user-facing
                />
            </Modal>

            <Modal
                title={t('新 key(仅此一次显示)', 'New key (shown once)')} // i18n: user-facing
                open={!!rotatedSecret}
                onCancel={() => setRotatedSecret('')}
                footer={<Button type="primary" onClick={() => setRotatedSecret('')}>{t('我已保存', 'Saved')}</Button>} // i18n: user-facing
            >
                <Typography.Paragraph copyable={{ text: rotatedSecret }} code>
                    {rotatedSecret}
                </Typography.Paragraph>
            </Modal>
        </div>
    );
}
