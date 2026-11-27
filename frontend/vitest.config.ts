import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Issue #68 R3: frontend test infrastructure (vitest + jsdom + testing-library).
// Separate from vite.config.ts; does not affect the build config.
export default defineConfig({
    plugins: [react()],
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/test/setup.ts'],
    },
});
