import { useEffect, useState } from 'react';
import { sdk } from './sdk';

// Spec §9.1 (S9 mandatory): UI copy follows the shell language. Host language switches are
// broadcast via the SDK lang event; components subscribe with useLang/useT to re-render —
// calling sdk.i18n.t without subscribing does not take effect after a switch (evaluated once at render), so this is unified here.

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
