import { describe, expect, it, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { useT } from './i18n';
import { sdk } from './sdk';

// Spec S9: after the host switches language (useLang subscribes to the lang event), the copy of already-mounted components
// must switch immediately — regression guard for the "t() evaluated once at render is frozen" defect.

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
    return <h2>{t('审计工作台', 'Audit workbench')}</h2>; // i18n: user-facing
}

describe('useT follows shell language (spec S9)', () => {
    it('re-renders when the host language event fires', async () => {
        render(<Probe />);
        expect(screen.getByText('审计工作台')).toBeInTheDocument(); // i18n: user-facing
        act(() => langListener?.('en'));
        expect(screen.getByText('Audit workbench')).toBeInTheDocument();
        expect(sdk.i18n.lang).toBeDefined();
    });
});
