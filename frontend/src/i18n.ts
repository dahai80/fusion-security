import { useEffect, useState } from 'react';
import { sdk } from './sdk';

// 规范 §9.1(S9 强制):界面文案跟随 shell 语言。宿主切换语言经 SDK lang
// 事件广播,组件用 useLang/useT 订阅后重渲染 —— 只调 sdk.i18n.t 不订阅的
// 写法切换后不生效(渲染时求值一次即冻结),此处统一收口。

export type Lang = 'zh' | 'en';

export function useLang(): Lang {
    const [lang, setLang] = useState<Lang>(() => {
        try {
            return sdk.i18n.lang();
        } catch {
            return 'zh';
        }
    });
    useEffect(() => {
        try {
            return sdk.i18n.subscribe(setLang);
        } catch {
            return undefined;
        }
    }, []);
    return lang;
}

export function useT() {
    const lang = useLang();
    return (zh: string, en: string) => (lang === 'en' ? en : zh);
}
