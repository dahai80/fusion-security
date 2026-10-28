import axios from 'axios';
import { isEmbedded, sdk } from '../sdk';

// 双模式 API 客户端(Issue #35):
// - 内嵌模式(iframe 挂在 shell 下):走 @fusion/web-sdk http 桥,宿主带
//   gateway 会话 token,gateway 的 /shell/fusion-security/ 代理再注入模块
//   API Key 上游;X-Tenant-Id 由本模块透传(租户 id 非机密)。
// - 独立模式(本机 vite dev / 直连部署):axios 直连同源 /api/v1,凭
//   VITE_API_KEY + VITE_TENANT_ID(仅开发便利;生产请走 gateway 内嵌)。
// 两种模式返回统一形状 { status, data },页面层零改动。

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
    // Issue #53: /system/health/detailed 需 system:manage(admin),角色不足的
    // 服务 key(或权限收紧后)会 403 —— 降级到公开 /system/health,仪表盘仍可
    // 渲染(仅 status,子系统项显示 unknown)。嵌入桥把 HTTP 错误统一折成
    // 502 HttpError,无法按状态码精确区分,故任意失败都降级;公开端点也失败
    // 时向上抛原始错误。
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

export default request;
