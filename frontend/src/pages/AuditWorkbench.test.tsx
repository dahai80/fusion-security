import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AuditWorkbench from './AuditWorkbench';
import { consoleApi } from '../services/api';

// Issue #68 R3: 标记复核 / 仅看已标记 / 关联事件高亮 的冒烟覆盖。

vi.mock('../sdk', () => ({
    sdk: {
        i18n: { t: (zh: string, _en?: string) => zh, lang: () => 'zh' },
        theme: { get: () => 'light', subscribe: () => () => {} },
    },
    isEmbedded: () => false,
}));

vi.mock('../services/api', () => ({
    consoleApi: {
        getAuditEvents: vi.fn(),
        getSavedQueries: vi.fn(),
        createSavedQuery: vi.fn(),
        deleteSavedQuery: vi.fn(),
        getSubscriptions: vi.fn(),
        createSubscription: vi.fn(),
        deleteSubscription: vi.fn(),
        setAuditMark: vi.fn(),
    },
}));

const EVENT = {
    action: 'auth.invalid_key',
    actor: 'anonymous',
    resource_type: '',
    resource_id: 'k-1',
    risk_level: 'high',
    trace_id: 'tr-9',
    ip_address: '10.0.0.1',
    timestamp: 1793598851.581,
    details: { ip: '10.0.0.1' },
    event_key: 'mk_abc123',
    marked: false,
};

const mockedApi = consoleApi as unknown as Record<string, ReturnType<typeof vi.fn>>;

function renderWorkbench() {
    return render(
        <MemoryRouter>
            <AuditWorkbench />
        </MemoryRouter>,
    );
}

beforeEach(() => {
    vi.clearAllMocks();
    mockedApi.getAuditEvents.mockResolvedValue({ data: { items: [EVENT], total: 1, limit: 50, offset: 0 } });
    mockedApi.getSavedQueries.mockResolvedValue({ data: { items: [] } });
});

describe('AuditWorkbench marks (Issue #68 R3 smoke)', () => {
    it('toggleMark calls setAuditMark with the event key', async () => {
        mockedApi.setAuditMark.mockResolvedValue({ data: { ok: true, marked: true } });
        renderWorkbench();
        await waitFor(() => expect(screen.getByLabelText('mark')).toBeInTheDocument());
        fireEvent.click(screen.getByLabelText('mark'));
        await waitFor(() =>
            expect(mockedApi.setAuditMark).toHaveBeenCalledWith({ event_key: 'mk_abc123', marked: true }),
        );
    });

    it('marked-only checkbox re-queries with marked_only=true', async () => {
        renderWorkbench();
        await waitFor(() => expect(screen.getByText('仅看已标记')).toBeInTheDocument());
        fireEvent.click(screen.getByText('仅看已标记'));
        await waitFor(() => {
            const calls = mockedApi.getAuditEvents.mock.calls as Array<[Record<string, unknown>]>;
            expect(calls.some(([params]) => params && params.marked_only === 'true')).toBe(true);
        });
    });

    it('openRelated re-queries by trace_id and highlights the source row', async () => {
        renderWorkbench();
        await waitFor(() => expect(screen.getByText('auth.invalid_key')).toBeInTheDocument());
        // AntD 展开图标 → 展开行渲染"关联事件"
        const expandIcon = await waitFor(() => {
            const el = document.querySelector('.ant-table-row-expand-icon');
            if (!el) throw new Error('expand icon not rendered yet');
            return el;
        });
        fireEvent.click(expandIcon);
        fireEvent.click(await screen.findByText('关联事件'));
        await waitFor(() => {
            const calls = mockedApi.getAuditEvents.mock.calls as Array<[Record<string, unknown>]>;
            expect(calls.some(([params]) => params && params.trace_id === 'tr-9')).toBe(true);
        });
        await waitFor(() => expect(document.querySelector('.fs-row-hl')).not.toBeNull());
    });
});
