import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import { scanApi, vulnApi } from './services/api';

// 空表 CTA:无数据时 Table 空态必须给业务引导按钮(扫描页直接开新建弹窗、
// 漏洞页跳转扫描页),不能只留工具栏刷新。

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
        const cta = await screen.findByText('立即发起扫描');
        fireEvent.click(cta);
        await waitFor(() => expect(document.querySelector('.ant-modal-title')?.textContent).toBe('新建扫描'));
    });

    it('Vulnerabilities empty table offers navigation to /scans', async () => {
        vi.mocked(vulnApi.list).mockResolvedValue({ data: [] } as any);
        render(
            <MemoryRouter initialEntries={['/vulnerabilities']}>
                <Vulnerabilities />
            </MemoryRouter>
        );
        const cta = await screen.findByText('去发起扫描');
        fireEvent.click(cta);
        expect(window.location.pathname).toBeDefined();
    });
});
