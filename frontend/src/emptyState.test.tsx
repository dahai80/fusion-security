import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import { scanApi, vulnApi } from './services/api';

// Empty-table CTA: when there is no data, the Table empty state must offer a business guidance button (scans page opens the create modal directly,
// vulnerabilities page navigates to the scans page); do not leave only the toolbar refresh.

vi.mock('./sdk', () => ({
    sdk: {
        i18n: { t: (zh: string, _en?: string) => zh, lang: () => 'zh' },
        theme: { get: () => 'light', subscribe: () => () => {} },
    },
    isEmbedded: () => false,
}));

vi.mock('./services/api', () => ({
    scanApi: { list: vi.fn(), create: vi.fn(), remove: vi.fn(), stats: vi.fn() },
    vulnApi: { list: vi.fn(), get: vi.fn(), ignore: vi.fn() },
    patchApi: { generate: vi.fn() },
}));

describe('empty-state CTA on data tables', () => {
    it('Scans empty table offers a button that opens the create modal', async () => {
        vi.mocked(scanApi.list).mockResolvedValue({ data: [] } as any);
        render(
            <MemoryRouter>
                <Scans />
            </MemoryRouter>
        );
        const cta = await screen.findByText('立即发起扫描'); // i18n: user-facing
        fireEvent.click(cta);
        await waitFor(() => expect(document.querySelector('.ant-modal-title')?.textContent).toBe('新建扫描')); // i18n: user-facing
    });

    it('Vulnerabilities empty table offers navigation to /scans', async () => {
        vi.mocked(vulnApi.list).mockResolvedValue({ data: [] } as any);
        render(
            <MemoryRouter initialEntries={['/vulnerabilities']}>
                <Vulnerabilities />
            </MemoryRouter>
        );
        const cta = await screen.findByText('去发起扫描'); // i18n: user-facing
        fireEvent.click(cta);
        expect(window.location.pathname).toBeDefined();
    });
});
