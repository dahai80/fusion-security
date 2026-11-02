import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Menu, ConfigProvider, theme as antdTheme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import {
    DashboardOutlined,
    ScanOutlined,
    BugOutlined,
    ProjectOutlined,
    ConsoleSqlOutlined,
    FileSearchOutlined,
    KeyOutlined,
} from '@ant-design/icons';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import Projects from './pages/Projects';
import AdminConsole from './pages/AdminConsole';
import AuditWorkbench from './pages/AuditWorkbench';
import KeyConsole from './pages/KeyConsole';
import { useEffect, useState } from 'react';
import { isEmbedded, sdk } from './sdk';
import { useLang, useT } from './i18n';

const { Sider, Content } = Layout;

// Issue #60/#61/#62: Admin Console 形态 —— /console 为首页(四分区聚合),
// /audit 审计工作台、/keys 密钥台;既有扫描/漏洞/项目页保留为次级。
// 规范 S9:菜单文案双语,经 useT 跟随 shell 语言切换重渲染。
const menuItems = (t: (zh: string, en: string) => string) => [
    { key: '/console', icon: <ConsoleSqlOutlined />, label: t('管理控制台', 'Admin Console') },
    { key: '/audit', icon: <FileSearchOutlined />, label: t('审计工作台', 'Audit workbench') },
    { key: '/keys', icon: <KeyOutlined />, label: t('密钥与策略', 'Keys & policies') },
    { type: 'group' as const, label: t('安全审计', 'Security audit') },
    { key: '/dashboard', icon: <DashboardOutlined />, label: t('仪表盘', 'Dashboard') },
    { key: '/scans', icon: <ScanOutlined />, label: t('扫描任务', 'Scans') },
    { key: '/vulnerabilities', icon: <BugOutlined />, label: t('漏洞管理', 'Vulnerabilities') },
    { key: '/projects', icon: <ProjectOutlined />, label: t('项目管理', 'Projects') },
];

const routes = (
    <>
        <Route path="/console" element={<AdminConsole />} />
        <Route path="/audit" element={<AuditWorkbench />} />
        <Route path="/keys" element={<KeyConsole />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/projects" element={<Projects />} />
    </>
);

function AppContent() {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();
    const t = useT();

    return (
        <Layout style={{ minHeight: '100vh' }}>
            <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed}>
                <div style={{ height: 32, margin: 16, color: '#fff', fontWeight: 'bold', fontSize: collapsed ? 14 : 18, textAlign: 'center' }}>
                    {collapsed ? 'FS' : 'Fusion-Security'}
                </div>
                <Menu
                    theme="dark"
                    mode="inline"
                    selectedKeys={[location.pathname]}
                    items={menuItems(t)}
                    onClick={({ key }) => navigate(key)}
                />
            </Sider>
            <Layout>
                <Content style={{ margin: 16, padding: 24, background: 'transparent', borderRadius: 8, minHeight: 280 }}>
                    <Routes>
                        {routes}
                        <Route path="*" element={<Navigate to="/console" replace />} />
                    </Routes>
                </Content>
            </Layout>
        </Layout>
    );
}

export default function App() {
    // Issue #60: 双主题 —— 跟随 shell 宿主(sdk.theme)或系统 prefers-color-scheme,
    // AntD v5 algorithm 切换;中英由各页 useT 承担(规范 S9),AntD 内置文案
    // (分页/弹窗/日期)经 ConfigProvider locale 同步 shell 语言。
    const [dark, setDark] = useState(() => {
        try {
            return sdk.theme.get() === 'dark';
        } catch {
            return false;
        }
    });
    const lang = useLang();

    useEffect(() => {
        dayjs.locale(lang === 'en' ? 'en' : 'zh-cn');
    }, [lang]);

    useEffect(() => {
        try {
            return sdk.theme.subscribe((mode) => setDark(mode === 'dark'));
        } catch {
            return undefined;
        }
    }, []);

    // Issue #35: 内嵌模式(union-web shell iframe)隐藏自有侧边导航,
    // 由 shell 菜单 + manifest pages 深链承担导航;独立模式保留完整布局。
    // 经 gateway /shell/fusion-security/ 托管时,路由 basename 对齐托管前缀。
    const shellBase = /^\/shell\/fusion-security\//.test(
        typeof window !== 'undefined' ? window.location.pathname : '',
    )
        ? '/shell/fusion-security'
        : '/';
    return (
        <ConfigProvider
            locale={lang === 'en' ? undefined : zhCN}
            theme={{
                algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
            }}
        >
            <BrowserRouter basename={shellBase}>
                {isEmbedded() ? (
                    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
                        <Content style={{ padding: 16 }}>
                            <Routes>
                                {routes}
                                <Route path="*" element={<Navigate to="/console" replace />} />
                            </Routes>
                        </Content>
                    </Layout>
                ) : (
                    <AppContent />
                )}
            </BrowserRouter>
        </ConfigProvider>
    );
}
