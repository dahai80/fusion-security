import axios from 'axios';
import { isEmbedded, sdk } from '../sdk';

// Dual-mode API client (Issue #35):
// - Embedded mode (iframe mounted under the shell): uses the @fusion/web-sdk http bridge; the host carries the
//   gateway session token, and the gateway /shell/fusion-security/ proxy injects the module API key upstream;
//   X-Tenant-Id is passed through by this module (tenant id is not a secret).
// - Standalone mode (local vite dev / direct deploy): axios connects same-origin /api/v1 directly, with
//   VITE_API_KEY + VITE_TENANT_ID (dev convenience only; production should use the gateway embedded mode).
// Both modes return a unified shape { status, data }; page-level code unchanged.

const TENANT_ID: string = import.meta.env.VITE_TENANT_ID || 'default';
const DEV_API_KEY: string | undefined = import.meta.env.VITE_API_KEY;
const EMBEDDED_BASE = '/shell/fusion-security/api/v1';
const STANDALONE_BASE = '/api/v1';

export const embeddedMode = isEmbedded();

const standalone = axios.create({
    baseURL: STANDALONE_BASE,
    timeout: 30000,
    headers: {
        'X-Tenant-Id': TENANT_ID,
        ...(DEV_API_KEY ? { 'X-API-Key': DEV_API_KEY } : {}),
    },
});

interface ApiResponse<T = any> {
    status: number;
    data: T;
}

async function request<T = any>(
    method: string,
    path: string,
    data?: object | null,
    params?: object,
): Promise<ApiResponse<T>> {
    if (data === null) data = undefined;
    if (embeddedMode) {
        const init: any = {
            method,
            headers: { 'X-Tenant-Id': TENANT_ID },
        };
        if (data !== undefined) init.body = data;
        if (params !== undefined) {
            const qs = new URLSearchParams(
                Object.entries(params as Record<string, any>)
                    .filter(([, v]) => v !== undefined && v !== null)
                    .map(([k, v]) => [k, String(v)]),
            ).toString();
            if (qs) path = `${path}?${qs}`;
        }
        const res = await sdk.http.request<T>(`${EMBEDDED_BASE}${path}`, init);
        return { status: res.status, data: res.data };
    }
    const res = await standalone.request<T>({
        url: path,
        method,
        ...(data !== undefined ? { data } : {}),
        ...(params !== undefined ? { params } : {}),
    });
    return { status: res.status, data: res.data };
}

export const dashboardApi = {
    getStats: () => request('GET', '/integrations/dashboard'),
// Issue #53: /system/health/detailed requires system:manage (admin); service keys with insufficient roles
// (or after permission tightening) get 403 — fall back to the public /system/health so the dashboard still
// renders (status only; subsystem items show unknown). The embedded bridge folds HTTP errors into
// 502 HttpError, so status codes cannot be distinguished precisely; any failure degrades. If the public
// endpoint also fails, the original error propagates.
    getHealth: async () => {
        try {
            return await request('GET', '/system/health/detailed');
        } catch (e) {
            console.warn('[dashboardApi] health/detailed failed, falling back to /system/health:', e);
            return await request('GET', '/system/health');
        }
    },
    getRulesets: () => request('GET', '/system/rulesets'),
};

export const scanApi = {
    list: (params?: object) => request('GET', '/scans', undefined, params),
    create: (data: object) => request('POST', '/scans', data),
    get: (id: string) => request('GET', `/scans/${id}`),
    delete: (id: string) => request('DELETE', `/scans/${id}`),
    incremental: (data: object) => request('POST', '/scans/incremental', data),
    queueStatus: () => request('GET', '/scans/queue/status'),
    enqueue: (data: object) => request('POST', '/scans/queue', data),
};

export const vulnApi = {
    list: (params?: object) => request('GET', '/vulnerabilities', undefined, params),
    get: (id: string) => request('GET', `/vulnerabilities/${id}`),
    update: (id: string, data: object) => request('PATCH', `/vulnerabilities/${id}`, data),
    markFalsePositive: (id: string, reason?: string) =>
        request('POST', `/vulnerabilities/${id}/false-positive`, null, { reason }),
    recentFindings: (hours?: number) => request('GET', '/vulnerabilities/findings/recent', undefined, { hours }),
    byRule: () => request('GET', '/vulnerabilities/findings/by-rule'),
    stats: () => request('GET', '/vulnerabilities/stats/summary'),
};

export const patchApi = {
    list: (params?: object) => request('GET', '/patches', undefined, params),
    get: (id: string) => request('GET', `/patches/${id}`),
    update: (id: string, data: object) => request('PATCH', `/patches/${id}`, data),
    apply: (id: string) => request('POST', `/patches/${id}/apply`),
    generate: (vulnId: string) => request('POST', `/patches/generate/${vulnId}`),
};

export const projectApi = {
    list: () => request('GET', '/projects'),
    create: (data: object) => request('POST', '/projects', data),
    get: (id: string) => request('GET', `/projects/${id}`),
    delete: (id: string) => request('DELETE', `/projects/${id}`),
};

export const reportApi = {
    generate: (data: object) => request('POST', '/reports/generate', data),
};

// Issue #60/#61/#62: Admin Console aggregate surface (all system:manage).
export const consoleApi = {
    getSummary: () => request('GET', '/console/summary'),
    getTenants: () => request('GET', '/console/tenants'),
    getAuditEvents: (params?: object) => request('GET', '/console/audit/events', undefined, params),
    setAuditMark: (data: object) => request('POST', '/console/audit/marks', data),
    getSavedQueries: () => request('GET', '/console/audit/saved-queries'),
    createSavedQuery: (data: object) => request('POST', '/console/audit/saved-queries', data),
    deleteSavedQuery: (id: string) => request('DELETE', `/console/audit/saved-queries/${id}`),
    getSubscriptions: () => request('GET', '/console/alerts/subscriptions'),
    createSubscription: (data: object) => request('POST', '/console/alerts/subscriptions', data),
    deleteSubscription: (id: string) => request('DELETE', `/console/alerts/subscriptions/${id}`),
    getKeys: () => request('GET', '/console/keys'),
    rotateKey: (data: object) => request('POST', '/console/keys/rotate', data),
    revokeKey: (data: object) => request('POST', '/console/keys/revoke', data),
    patchLocalKey: (id: string, data: object) => request('PATCH', `/console/keys/local/${id}`, data),
    getSso: () => request('GET', '/console/sso'),
};

export default request;
