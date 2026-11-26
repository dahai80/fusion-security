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

// Issue #60/#61/#62: Admin Console layout — /console is the home (four-zone aggregate),
// /audit audit workbench, /keys key console; existing scan/vuln/project pages remain as secondary.
// Spec S9: menu copy is bilingual, re-rendered via useT following the shell language switch.
const menuItems = (t: (zh: string, en: string) => string) => [
    { key: '/console', icon: <ConsoleSqlOutlined />, label: t('管理控制台', 'Admin Console') }, // i18n: user-facing
    { key: '/audit', icon: <FileSearchOutlined />, label: t('审计工作台', 'Audit workbench') }, // i18n: user-facing
    { key: '/keys', icon: <KeyOutlined />, label: t('密钥与策略', 'Keys & policies') }, // i18n: user-facing
    { type: 'group' as const, label: t('安全审计', 'Security audit') }, // i18n: user-facing
    { key: '/dashboard', icon: <DashboardOutlined />, label: t('仪表盘', 'Dashboard') }, // i18n: user-facing
    { key: '/scans', icon: <ScanOutlined />, label: t('扫描任务', 'Scans') }, // i18n: user-facing
    { key: '/vulnerabilities', icon: <BugOutlined />, label: t('漏洞管理', 'Vulnerabilities') }, // i18n: user-facing
    { key: '/projects', icon: <ProjectOutlined />, label: t('项目管理', 'Projects') }, // i18n: user-facing
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
// Issue #60: dual theme — follow the shell host (sdk.theme) or system prefers-color-scheme,
// switched via the AntD v5 algorithm; zh/en copy is handled per page by useT (spec S9), AntD built-in text
// (pagination/modals/dates) follows the shell language via ConfigProvider locale.
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

// Theme canvas: iframe body/html defaults to transparent white; in dark mode gaps outside components would show a white background.
// Take the token canvas color for the current algorithm and sync colorScheme (scrollbars/native controls).
    useEffect(() => {
        const canvas = antdTheme.getDesignToken({
            algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        }).colorBgLayout;
        document.documentElement.style.background = canvas;
        document.body.style.background = canvas;
        document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    }, [dark]);

// Issue #35: embedded mode (union-web shell iframe) hides its own side navigation;
// navigation is handled by the shell menu + manifest pages deep links; standalone mode keeps the full layout.
// When hosted via gateway /shell/fusion-security/, the router basename aligns with the hosting prefix.
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
