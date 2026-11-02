import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Table, Input, Select, DatePicker, Button, Space, Modal, message, Tag, Typography, Popconfirm, Descriptions, Checkbox, theme as antdTheme,
} from 'antd';
import {
    SearchOutlined, DownloadOutlined, SaveOutlined, BellOutlined, DeleteOutlined, StarOutlined, StarFilled,
    LinkOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { consoleApi } from '../services/api';
import { useT } from '../i18n';
import { severityTagColor } from '../severity';

// Issue #61(CS-2):审计工作台 —— 全文搜索 + 时间窗/类型/风险过滤 + 保存查询
// (重放同结果集) + CSV 导出(流式) + 告警订阅(shell 🔔) + 事件详情(trace-id)。
// Issue #65:标记复核(持久化分诊态 + 仅看已标记)+ 关联事件跳转(同 trace_id,
// 缺省回退 resource_id,命中行高亮)。

const { RangePicker } = DatePicker;

interface AuditEvent {
    action: string;
    actor: string;
    resource_type: string;
    resource_id: string;
    risk_level: string;
    trace_id: string;
    ip_address: string;
    timestamp: number;
    details: Record<string, any>;
    event_key: string;
    marked: boolean;
}

interface SavedQuery {
    id: string;
    name: string;
    definition: { search?: string; action?: string; risk?: string; start?: string; end?: string };
}

export default function AuditWorkbench() {
    const [events, setEvents] = useState<AuditEvent[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(false);
    const [page, setPage] = useState(1);
    const [search, setSearch] = useState('');
    const [action, setAction] = useState('');
    const [risk, setRisk] = useState('');
    const [range, setRange] = useState<any>(null);
    const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
    const [saveOpen, setSaveOpen] = useState(false);
    const [saveName, setSaveName] = useState('');
    const [subOpen, setSubOpen] = useState(false);
    const [subName, setSubName] = useState('');
    const [subRisk, setSubRisk] = useState('high,critical');
    const [markedOnly, setMarkedOnly] = useState(false);
    const [traceId, setTraceId] = useState('');
    const [resourceId, setResourceId] = useState('');
    const [highlightKey, setHighlightKey] = useState('');
    const navigate = useNavigate();
    const t = useT();
    // 规范 S1:标记星色走 theme token,暗色自适应。
    const { token } = antdTheme.useToken();

    const currentFilters = () => {
        const params: Record<string, string> = {};
        if (search) params.search = search;
        if (action) params.action = action;
        if (risk) params.risk = risk;
        if (traceId) params.trace_id = traceId;
        if (resourceId) params.resource_id = resourceId;
        if (markedOnly) params.marked_only = 'true';
        if (range && range[0]) params.start = String(Math.floor(range[0].valueOf() / 1000));
        if (range && range[1]) params.end = String(Math.floor(range[1].valueOf() / 1000));
        return params;
    };

    const load = async (p = page, overrides: Record<string, string> = {}) => {
        setLoading(true);
        try {
            const res = await consoleApi.getAuditEvents({
                ...currentFilters(),
                ...overrides,
                limit: 50,
                offset: (p - 1) * 50,
            });
            setEvents(res.data.items || []);
            setTotal(res.data.total || 0);
        } catch (e: any) {
            message.error(e.message || t('加载失败', 'Failed to load'));
        } finally {
            setLoading(false);
        }
    };

    const loadSaved = async () => {
        try {
            const res = await consoleApi.getSavedQueries();
            setSavedQueries(res.data.items || []);
        } catch {
            setSavedQueries([]);
        }
    };

    useEffect(() => {
        load(1);
        setPage(1);
        loadSaved();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const exportCsv = () => {
        const params = new URLSearchParams(currentFilters()).toString();
        // 流式导出走浏览器原生下载(独立模式同源;嵌入模式经 gateway 代理同源)。
        const base = location.pathname.includes('/shell/fusion-security/')
            ? '/shell/fusion-security/api/v1'
            : '/api/v1';
        window.open(`${base}/console/audit/export${params ? `?${params}` : ''}`, '_blank');
    };

    const saveQuery = async () => {
        if (!saveName.trim()) return;
        const f = currentFilters();
        try {
            await consoleApi.createSavedQuery({ name: saveName.trim(), ...f });
            message.success(t('已保存', 'Saved'));
            setSaveOpen(false);
            setSaveName('');
            loadSaved();
        } catch (e: any) {
            message.error(e.message || t('保存失败', 'Save failed'));
        }
    };

    const runSaved = async (q: SavedQuery) => {
        setSearch(q.definition.search || '');
        setAction(q.definition.action || '');
        setRisk(q.definition.risk || '');
        setRange(null);
        setTraceId('');
        setResourceId('');
        setHighlightKey('');
        try {
            const res = await consoleApi.getAuditEvents({ saved_query_id: q.id, limit: 50, offset: 0 });
            setEvents(res.data.items || []);
            setTotal(res.data.total || 0);
            setPage(1);
            message.info(`${q.name}: ${res.data.total} ${t('条', 'events')}`);
        } catch (e: any) {
            message.error(e.message || t('重放失败', 'Replay failed'));
        }
    };

    const subscribe = async () => {
        if (!subName.trim()) return;
        try {
            await consoleApi.createSubscription({ name: subName.trim(), event_class: action, risk_levels: subRisk });
            message.success(t('已订阅,匹配事件将推送到 shell 通知中心', 'Subscribed — matches push to the shell bell'));
            setSubOpen(false);
            setSubName('');
        } catch (e: any) {
            message.error(e.message || t('订阅失败', 'Subscribe failed'));
        }
    };

    const toggleMark = async (e: AuditEvent) => {
        // Issue #65:标记/取消复核 —— 后端幂等,(tenant, event_key) 唯一。
        try {
            await consoleApi.setAuditMark({ event_key: e.event_key, marked: !e.marked });
            message.success(e.marked ? t('已取消标记', 'Mark removed') : t('已标记复核', 'Marked for review'));
            load(page);
        } catch (err: any) {
            message.error(err.message || t('标记失败', 'Mark failed'));
        }
    };

    const openRelated = (e: AuditEvent) => {
        // Issue #65:同 trace_id 关联事件;缺 trace_id 时回退 resource_id。
        // state 更新异步,查询用 overrides 立即生效,避免读到旧过滤。
        if (e.trace_id) {
            setTraceId(e.trace_id);
            setResourceId('');
            setHighlightKey(e.event_key);
            setPage(1);
            load(1, { trace_id: e.trace_id, resource_id: '' });
        } else if (e.resource_id) {
            setResourceId(e.resource_id);
            setTraceId('');
            setHighlightKey(e.event_key);
            setPage(1);
            load(1, { resource_id: e.resource_id, trace_id: '' });
        } else {
            message.info(t('该事件无 trace_id / resource_id 可关联', 'No trace_id / resource_id to relate'));
        }
    };

    const columns: ColumnsType<AuditEvent> = [
        {
            title: t('时间', 'Time'),
            dataIndex: 'timestamp',
            width: 170,
            render: (ts: number) => new Date(ts * 1000).toLocaleString(),
        },
        {
            title: t('风险', 'Risk'),
            dataIndex: 'risk_level',
            width: 90,
            render: (r: string) => <Tag color={severityTagColor(r)}>{r}</Tag>,
        },
        { title: t('事件', 'Event'), dataIndex: 'action' },
        { title: t('操作者', 'Actor'), dataIndex: 'actor', width: 140 },
        {
            title: t('资源', 'Resource'),
            width: 220,
            render: (_: any, e: AuditEvent) => (
                <span>
                    {e.resource_type}
                    {e.resource_id ? `/${e.resource_id}` : ''}
                </span>
            ),
        },
        {
            title: t('复核', 'Review'),
            width: 70,
            render: (_: any, e: AuditEvent) => (
                <Button
                    size="small"
                    type="text"
                    aria-label={e.marked ? 'unmark' : 'mark'}
                    icon={e.marked ? <StarFilled style={{ color: token.colorWarning }} /> : <StarOutlined />}
                    onClick={() => toggleMark(e)}
                />
            ),
        },
    ];

    return (
        <div>
            <h2>{t('审计工作台', 'Audit workbench')}</h2>
            <Space wrap style={{ marginBottom: 16 }}>
                <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder={t('搜索事件/操作者/资源', 'Search event / actor / resource')}
                    style={{ width: 260 }}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    onPressEnter={() => load(1)}
                />
                <Input
                    allowClear
                    placeholder={t('事件类型前缀(auth. / key.)', 'Event class prefix (auth. / key.)')}
                    style={{ width: 220 }}
                    value={action}
                    onChange={(e) => setAction(e.target.value)}
                    onPressEnter={() => load(1)}
                />
                <Select
                    allowClear
                    placeholder={t('风险等级', 'Risk level')}
                    style={{ width: 140 }}
                    value={risk || undefined}
                    onChange={(v) => setRisk(v || '')}
                    options={['critical', 'high', 'medium', 'low', 'info'].map((r) => ({ value: r, label: r }))}
                />
                <RangePicker showTime value={range} onChange={setRange} />
                <Button type="primary" onClick={() => { setPage(1); load(1); }}>
                    {t('查询', 'Search')}
                </Button>
                <Button icon={<DownloadOutlined />} onClick={exportCsv}>
                    {t('导出 CSV', 'Export CSV')}
                </Button>
                <Button icon={<SaveOutlined />} onClick={() => setSaveOpen(true)}>
                    {t('保存查询', 'Save query')}
                </Button>
                <Button icon={<BellOutlined />} onClick={() => setSubOpen(true)}>
                    {t('订阅告警', 'Subscribe')}
                </Button>
                <Checkbox
                    checked={markedOnly}
                    onChange={(ev) => {
                        setMarkedOnly(ev.target.checked);
                        setPage(1);
                        load(1, { marked_only: ev.target.checked ? 'true' : '' });
                    }}
                >
                    {t('仅看已标记', 'Marked only')}
                </Checkbox>
                {traceId && (
                    <Tag
                        color="blue"
                        closable
                        onClose={() => {
                            setTraceId('');
                            setHighlightKey('');
                            load(1, { trace_id: '' });
                        }}
                    >
                        trace: {traceId}
                    </Tag>
                )}
                {resourceId && (
                    <Tag
                        color="purple"
                        closable
                        onClose={() => {
                            setResourceId('');
                            setHighlightKey('');
                            load(1, { resource_id: '' });
                        }}
                    >
                        resource: {resourceId}
                    </Tag>
                )}
            </Space>

            {savedQueries.length > 0 && (
            <Space wrap style={{ marginBottom: 16 }}>
                {savedQueries.map((q) => (
                    <Space key={q.id} size={4}>
                        <Button size="small" onClick={() => runSaved(q)}>
                            {q.name}
                        </Button>
                        <Popconfirm
                            title={t('删除该保存查询?', 'Delete this saved query?')}
                            onConfirm={async () => {
                                await consoleApi.deleteSavedQuery(q.id);
                                loadSaved();
                            }}
                        >
                            <Button size="small" type="text" icon={<DeleteOutlined />} />
                        </Popconfirm>
                    </Space>
                ))}
            </Space>
            )}

            <style>{`.fs-row-hl > td { background: rgba(250, 173, 20, 0.16) !important; }`}</style>
            <Table<AuditEvent>
                rowKey={(e) => `${e.timestamp}-${e.action}-${e.actor}`}
                size="middle"
                loading={loading}
                dataSource={events}
                columns={columns}
                rowClassName={(e) => (e.event_key && e.event_key === highlightKey ? 'fs-row-hl' : '')}
                pagination={{
                    current: page,
                    pageSize: 50,
                    total,
                    showSizeChanger: false,
                    onChange: (p) => {
                        setPage(p);
                        load(p);
                    },
                }}
                expandable={{
                    expandedRowRender: (e) => (
                        <Descriptions size="small" column={2} bordered>
                            <Descriptions.Item label="trace-id">
                                {e.trace_id ? (
                                    <Typography.Text code copyable>
                                        {e.trace_id}
                                    </Typography.Text>
                                ) : (
                                    <Typography.Text type="secondary">-</Typography.Text>
                                )}
                            </Descriptions.Item>
                            <Descriptions.Item label="IP">{e.ip_address || '-'}</Descriptions.Item>
                            <Descriptions.Item label={t('详情', 'Details')} span={2}>
                                <Typography.Text code style={{ whiteSpace: 'pre-wrap' }}>
                                    {JSON.stringify(e.details, null, 2)}
                                </Typography.Text>
                            </Descriptions.Item>
                            <Descriptions.Item span={2}>
                                <Space>
                                    <Button size="small" icon={<LinkOutlined />} onClick={() => openRelated(e)}>
                                        {t('关联事件', 'Related events')}
                                    </Button>
                                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                        {t(
                                            '按同一 trace_id(缺省回退 resource_id)过滤并高亮本源事件',
                                            'Filter by the same trace_id (fallback resource_id) and highlight the source row',
                                        )}
                                    </Typography.Text>
                                </Space>
                            </Descriptions.Item>
                        </Descriptions>
                    ),
                }}
            />

            <Modal
                title={t('保存当前过滤为查询', 'Save current filters as a query')}
                open={saveOpen}
                onOk={saveQuery}
                onCancel={() => setSaveOpen(false)}
                okText={t('保存', 'Save')}
            >
                <Input
                    placeholder={t('查询名称', 'Query name')}
                    value={saveName}
                    onChange={(e) => setSaveName(e.target.value)}
                />
            </Modal>

            <Modal
                title={t('订阅告警(推送 shell 通知中心)', 'Subscribe to alerts (pushes to the shell bell)')}
                open={subOpen}
                onOk={subscribe}
                onCancel={() => setSubOpen(false)}
                okText={t('订阅', 'Subscribe')}
            >
                <Space direction="vertical" style={{ width: '100%' }}>
                    <Input
                        placeholder={t('订阅名称', 'Subscription name')}
                        value={subName}
                        onChange={(e) => setSubName(e.target.value)}
                    />
                    <Typography.Text type="secondary">
                        {t('事件类型前缀', 'Event class prefix')}: <b>{action || t('(全部)', '(all)')}</b>
                    </Typography.Text>
                    <Input
                        placeholder="risk levels"
                        value={subRisk}
                        onChange={(e) => setSubRisk(e.target.value)}
                    />
                    <Button type="link" size="small" onClick={() => navigate('/console')}>
                        {t('告警也可在管理台查看', 'Alerts also surface on the console home')}
                    </Button>
                </Space>
            </Modal>
        </div>
    );
}
