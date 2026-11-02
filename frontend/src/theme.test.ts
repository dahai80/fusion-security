import { describe, expect, it } from 'vitest';
import { createThemeState } from '@fusion/web-sdk';

// 主题同步回归:宿主初始 push/pull 可能在消费方订阅前就 set 过一次,
// set() 同值去重会吞掉后续所有相同值的通知 —— 订阅方永远卡在初值。
// subscribe 必须立即用当前值回调一次,保证订阅即同步。

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
