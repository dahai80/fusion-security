import { useEffect, useState } from 'react';
import {
    Table, Card, Button, Modal, Input, InputNumber, message, Tag, Typography, DatePicker, Switch, Alert, Space, List,
} from 'antd';
import { SyncOutlined, ClockCircleOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { consoleApi } from '../services/api';
import { useT } from '../i18n';

// Issue #62(CS-3):密钥集中管理台 —— 本地服务 key(过期/启停) + identity
// 模块 key 台账(轮换带 grace 窗,吊销依赖上游 fusion-identity#35) + SSO 面
// (按 identity 真实能力渲染,不可读 = 明确 disabled + roadmap 说明)。

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
            message.success(t('轮换成功,旧 key 在宽限期内仍有效', 'Rotated — old key stays valid during the grace window'));
            load();
        } catch (e: any) {
            message.error(e.message || t('轮换失败', 'Rotation failed'));
        }
    };

    const saveExpiry = async () => {
        if (!expiryKey) return;
        try {
            await consoleApi.patchLocalKey(expiryKey.id, {
                expires_at: expiryDate ? expiryDate.toISOString() : '',
            });
            message.success(t('已更新过期时间', 'Expiry updated'));
            setExpiryKey(null);
            setExpiryDate(null);
            load();
        } catch (e: any) {
            message.error(e.message || t('更新失败', 'Update failed'));
        }
    };

    const toggleKey = async (k: LocalKey, enabled: boolean) => {
        try {
            await consoleApi.patchLocalKey(k.id, { enabled });
            load();
        } catch (e: any) {
            message.error(e.message || t('更新失败', 'Update failed'));
        }
    };

    const localColumns: ColumnsType<LocalKey> = [
        { title: t('名称', 'Name'), dataIndex: 'name' },
        { title: t('角色', 'Role'), dataIndex: 'role', width: 100, render: (r: string) => <Tag>{r}</Tag> },
        { title: t('最近使用', 'Last used'), dataIndex: 'last_used_at', width: 170, render: (v: string) => (v ? new Date(v).toLocaleString() : '-') },
        {
            title: t('过期时间', 'Expires'),
            dataIndex: 'expires_at',
            width: 170,
            render: (v: string) =>
                v ? (
                    <span>
                        <ClockCircleOutlined /> {new Date(v).toLocaleDateString()}
                    </span>
                ) : (
                    <Tag color="orange">{t('未设置', 'Not set')}</Tag>
                ),
        },
        {
            title: t('启用', 'Enabled'),
            dataIndex: 'enabled',
            width: 90,
            render: (v: boolean, k: LocalKey) => <Switch size="small" checked={v} onChange={(nv) => toggleKey(k, nv)} />,
        },
        {
            title: '',
            width: 120,
            render: (_: any, k: LocalKey) => (
                <Button size="small" onClick={() => { setExpiryKey(k); setExpiryDate(k.expires_at ? (new Date(k.expires_at) as any) : null); }}>
                    {t('设过期', 'Set expiry')}
                </Button>
            ),
        },
    ];

    return (
        <div>
            <h2>{t('密钥与策略', 'Keys & policies')}</h2>

            <Card title={t('模块服务 key(identity 台账)', 'Module service keys (identity ledger)')} style={{ marginBottom: 16 }}>
                {identity.available ? (
                    <Table<IdentityApp>
                        rowKey="app_id"
                        size="small"
                        loading={loading}
                        dataSource={identity.apps}
                        pagination={false}
                        columns={[
                            { title: 'app', dataIndex: 'app_id' },
                            { title: t('当前版本', 'Current'), dataIndex: 'current_version', width: 110 },
                            { title: t('状态', 'Status'), dataIndex: 'status', width: 110, render: (s: string) => <Tag color={s === 'active' ? 'green' : 'orange'}>{s || '-'}</Tag> },
                            { title: t('宽限期至', 'Grace until'), dataIndex: 'grace_until', width: 170, render: (v: any) => (v ? new Date(v).toLocaleString() : '-') },
                            {
                                title: '',
                                width: 110,
                                render: (_: any, a: IdentityApp) => (
                                    <Button size="small" icon={<SyncOutlined />} onClick={() => { setRotateApp(a.app_id); setRotateOpen(true); }}>
                                        {t('轮换', 'Rotate')}
                                    </Button>
                                ),
                            },
                        ]}
                    />
                ) : (
                    <Alert type="info" showIcon message={identity.reason || t('identity 台账不可用', 'Identity ledger unavailable')} />
                )}
                <Space style={{ marginTop: 12 }}>
                    <Button onClick={() => { setRotateApp(''); setRotateOpen(true); }}>{t('按 app_id 轮换', 'Rotate by app_id')}</Button>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t(
                            '轮换 = identity 签发新版本,旧 key 进 grace 窗口;agent-studio 的 agent key 注册进同一台账(fusion-agent-studio#530)。',
                            'Rotation issues a new version via identity; the old key enters a grace window. agent-studio agent keys join the same ledger (fusion-agent-studio#530).',
                        )}
                    </Typography.Text>
                </Space>
            </Card>

            <Card title={t('本地服务 key', 'Local service keys')} style={{ marginBottom: 16 }}>
                <Table<LocalKey> rowKey="id" size="small" loading={loading} dataSource={localKeys} columns={localColumns} pagination={false} />
            </Card>

            <Card title={t('SSO 单点登录', 'SSO')}>
                {!sso ? (
                    <Typography.Text type="secondary">...</Typography.Text>
                ) : sso.state === 'configured' ? (
                    <List size="small">
                        <List.Item>
                            <Tag color="green">{t('已配置', 'Configured')}</Tag> {sso.types?.join(', ')} · {t('自动开通', 'auto-provision')}: {String(sso.auto_provision)}
                        </List.Item>
                    </List>
                ) : sso.state === 'not_configured' ? (
                    <Alert type="warning" showIcon message={t('租户未配置 IdP', 'No IdP configured for this tenant')} description={sso.detail} />
                ) : (
                    <Alert type="info" showIcon message={t('SSO 状态不可读', 'SSO state unavailable')} description={sso.detail || sso.reason} />
                )}
            </Card>

            <Modal
                title={`${t('轮换模块 key', 'Rotate module key')}${rotateApp ? `: ${rotateApp}` : ''}`}
                open={rotateOpen}
                onOk={doRotate}
                onCancel={() => setRotateOpen(false)}
                okText={t('轮换', 'Rotate')}
            >
                <Space direction="vertical" style={{ width: '100%' }}>
                    {!rotateApp && (
                        <Input placeholder="app_id (如 fusion-mlx)" value={rotateApp} onChange={(e) => setRotateApp(e.target.value)} />
                    )}
                    <div>
                        {t('宽限期(分钟)', 'Grace window (minutes)')}:{' '}
                        <InputNumber min={0} max={43200} value={graceMinutes} onChange={(v) => setGraceMinutes(v || 0)} />
                    </div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t('新 key 仅在轮换响应中显示一次,请立即更新到对应模块的配置。', 'The new key is shown only once — update the consuming module immediately.')}
                    </Typography.Text>
                </Space>
            </Modal>

            <Modal
                title={t('设置过期时间', 'Set expiry')}
                open={!!expiryKey}
                onOk={saveExpiry}
                onCancel={() => { setExpiryKey(null); setExpiryDate(null); }}
                okText={t('保存', 'Save')}
            >
                <DatePicker
                    showTime
                    style={{ width: '100%' }}
                    value={expiryDate}
                    onChange={setExpiryDate}
                    placeholder={t('留空 = 清除过期限制', 'Empty = no expiry')}
                />
            </Modal>

            <Modal
                title={t('新 key(仅此一次显示)', 'New key (shown once)')}
                open={!!rotatedSecret}
                onCancel={() => setRotatedSecret('')}
                footer={<Button type="primary" onClick={() => setRotatedSecret('')}>{t('我已保存', 'Saved')}</Button>}
            >
                <Typography.Paragraph copyable={{ text: rotatedSecret }} code>
                    {rotatedSecret}
                </Typography.Paragraph>
            </Modal>
        </div>
    );
}
