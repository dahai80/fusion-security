import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Menu, ConfigProvider, theme as antdTheme } from 'antd';
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

const { Sider, Content } = Layout;

// Issue #60/#61/#62: Admin Console 形态 —— /console 为首页(四分区聚合),
// /audit 审计工作台、/keys 密钥台;既有扫描/漏洞/项目页保留为次级。
const menuItems = [
    { key: '/console', icon: <ConsoleSqlOutlined />, label: '管理控制台' },
    { key: '/audit', icon: <FileSearchOutlined />, label: '审计工作台' },
    { key: '/keys', icon: <KeyOutlined />, label: '密钥与策略' },
    { type: 'group' as const, label: '安全审计' },
    { key: '/dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
    { key: '/scans', icon: <ScanOutlined />, label: '扫描任务' },
    { key: '/vulnerabilities', icon: <BugOutlined />, label: '漏洞管理' },
    { key: '/projects', icon: <ProjectOutlined />, label: '项目管理' },
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
                    items={menuItems}
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
    // AntD v5 algorithm 切换;中英由各页 sdk.i18n.t 承担。
    const [dark, setDark] = useState(() => {
        try {
            return sdk.theme.get() === 'dark';
        } catch {
            return false;
        }
    });

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
