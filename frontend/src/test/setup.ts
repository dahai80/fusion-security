import '@testing-library/jest-dom/vitest';

// AntD v5 在 jsdom 下需要 matchMedia / ResizeObserver 桩。
if (typeof window !== 'undefined' && !window.matchMedia) {
    window.matchMedia = ((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia;
}

if (typeof globalThis !== 'undefined' && !(globalThis as any).ResizeObserver) {
    (globalThis as any).ResizeObserver = class {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
}
