import axios from 'axios';

const api = axios.create({
    baseURL: '/api/v1',
    timeout: 30000,
});

export const dashboardApi = {
    getStats: () => api.get('/integrations/dashboard'),
    getHealth: () => api.get('/system/health/detailed'),
    getRulesets: () => api.get('/system/rulesets'),
};

export const scanApi = {
    list: (params?: object) => api.get('/scans', { params }),
    create: (data: object) => api.post('/scans', data),
    get: (id: string) => api.get(`/scans/${id}`),
    delete: (id: string) => api.delete(`/scans/${id}`),
    incremental: (data: object) => api.post('/scans/incremental', data),
    queueStatus: () => api.get('/scans/queue/status'),
    enqueue: (data: object) => api.post('/scans/queue', data),
};

export const vulnApi = {
    list: (params?: object) => api.get('/vulnerabilities', { params }),
    get: (id: string) => api.get(`/vulnerabilities/${id}`),
    update: (id: string, data: object) => api.patch(`/vulnerabilities/${id}`, data),
    markFalsePositive: (id: string, reason?: string) => api.post(`/vulnerabilities/${id}/false-positive`, null, { params: { reason } }),
    recentFindings: (hours?: number) => api.get('/vulnerabilities/findings/recent', { params: { hours } }),
    byRule: () => api.get('/vulnerabilities/findings/by-rule'),
    stats: () => api.get('/vulnerabilities/stats/summary'),
};

export const patchApi = {
    list: (params?: object) => api.get('/patches', { params }),
    get: (id: string) => api.get(`/patches/${id}`),
    update: (id: string, data: object) => api.patch(`/patches/${id}`, data),
    apply: (id: string) => api.post(`/patches/${id}/apply`),
    generate: (vulnId: string) => api.post(`/patches/generate/${vulnId}`),
};

export const projectApi = {
    list: () => api.get('/projects'),
    create: (data: object) => api.post('/projects', data),
    get: (id: string) => api.get(`/projects/${id}`),
    delete: (id: string) => api.delete(`/projects/${id}`),
};

export const reportApi = {
    generate: (data: object) => api.post('/reports/generate', data),
};

export default api;
