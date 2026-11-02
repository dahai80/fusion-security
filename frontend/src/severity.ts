// 规范 §3.1/S1/S2:严重度/风险色统一 —— AntD 预设色名(暗色随 theme
// algorithm 自适应),语义全生态唯一:红=失败/严重、volcano=高、gold=中、
// 绿=正常/低、蓝=info、灰=default。禁止页面再散落硬编码 hex。

export const severityTagColor = (level?: string | null): string => {
    switch ((level || '').toLowerCase()) {
        case 'critical':
            return 'red';
        case 'high':
            return 'volcano';
        case 'medium':
            return 'gold';
        case 'low':
            return 'green';
        case 'info':
            return 'blue';
        default:
            return 'default';
    }
};
