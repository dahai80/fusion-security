// Spec §3.1/S1/S2: severity/risk colors unified — AntD preset color names (dark mode adapts via theme
// algorithm); semantics unique ecosystem-wide: red=fail/critical, volcano=high, gold=medium,
// green=normal/low, blue=info, gray=default. Pages must not scatter hardcoded hex.

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
