import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Issue #35: union-web dual mode.
// - Standalone dev: vite dev on 11476 (registered in port-registry.yaml), /api proxied to
//   this service on 11454.
// - Embedded production: build output hosted by the gateway at /shell/fusion-security/, asset prefix
//   matches it; iframe sandbox per PRD §7.2 (security modules use same-origin iframe isolation).
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
