import { describe, expect, it } from 'vitest';
import { createThemeState } from '@fusion/web-sdk';

// Theme sync regression: the host's initial push/pull may set() once before the consumer subscribes,
// and set()'s same-value dedup swallows all later notifications of the same value — the subscriber stays stuck at the initial value.
// subscribe must call back immediately with the current value so subscribing implies sync.

describe('createThemeState.subscribe notifies immediately (theme sync race)', () => {
    it('calls new subscribers with the current mode at once', () => {
        const state = createThemeState('dark');
        state.set('light'); // host push landed before consumer subscribed
        const seen: string[] = [];
        state.subscribe((mode) => seen.push(mode));
        expect(seen).toEqual(['light']);
        expect(state.get()).toBe('light');
    });

    it('still dedupes same-value set after subscription', () => {
        const state = createThemeState('dark');
        const seen: string[] = [];
        state.subscribe((mode) => seen.push(mode));
        state.set('light');
        state.set('light');
        expect(seen).toEqual(['dark', 'light']);
    });

    it('unsubscribe stops notifications', () => {
        const state = createThemeState('dark');
        const seen: string[] = [];
        const off = state.subscribe((mode) => seen.push(mode));
        off();
        state.set('light');
        expect(seen).toEqual(['dark']);
    });
});
