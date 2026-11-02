import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Issue #68 R3: 前端测试基建(vitest + jsdom + testing-library)。
// 独立于 vite.config.ts,不影响构建配置。
export default defineConfig({
    plugins: [react()],
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/test/setup.ts'],
    },
});
