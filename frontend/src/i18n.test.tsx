import { describe, expect, it, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { useT } from './i18n';
import { sdk } from './sdk';

// 规范 S9:宿主切换语言(useLang 订阅 lang 事件)后,已挂载组件的文案
// 必须即时切换 —— 回归"t() 渲染时求值一次即冻结"的缺陷。

let langListener: ((lang: 'zh' | 'en') => void) | null = null;

vi.mock('./sdk', () => ({
    sdk: {
        i18n: {
            lang: () => 'zh',
            t: (zh: string, en: string) => (langListener ? undefined : zh),
            subscribe: (cb: (lang: 'zh' | 'en') => void) => {
                langListener = cb;
                return () => {
                    langListener = null;
                };
            },
        },
        theme: { get: () => 'light', subscribe: () => () => {} },
    },
}));

function Probe() {
    const t = useT();
    return <h2>{t('审计工作台', 'Audit workbench')}</h2>;
}

describe('useT follows shell language (spec S9)', () => {
    it('re-renders when the host language event fires', async () => {
        render(<Probe />);
        expect(screen.getByText('审计工作台')).toBeInTheDocument();
        act(() => langListener?.('en'));
        expect(screen.getByText('Audit workbench')).toBeInTheDocument();
        expect(sdk.i18n.lang).toBeDefined();
    });
});
