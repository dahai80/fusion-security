import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Issue #35: union-web 双模式。
// - 独立开发: vite dev 于 11476(已登记 port-registry.yaml),/api 代理到
//   本服务 11454。
// - 内嵌生产: 构建产物由 gateway 托管于 /shell/fusion-security/,资源前缀
//   与之一致;iframe 沙盒按 PRD §7.2(安全模块走同源 iframe 隔离)。
export default defineConfig({
    plugins: [react()],
    base: process.env.NODE_ENV === 'production' ? '/shell/fusion-security/' : '/',
    server: {
        port: 11476,
        proxy: {
            '/api': {
                target: 'http://127.0.0.1:11454',
                changeOrigin: true,
            },
        },
    },
});
