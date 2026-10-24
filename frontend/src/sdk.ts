import { createShellSdk } from "@fusion/web-sdk";

// 单例 SDK(toast/tab/theme 与 shell 宿主的 postMessage 桥)。
// 数据调用在 services/api.ts:内嵌模式走 SDK http 桥(宿主带 gateway 会话
// token,gateway 再注入模块 key 上游);独立模式直连同源 /api/v1。
// ?embedded=1 由 shell 追加;独立运行保留模块自有导航。
export const embeddedParam = (): boolean => {
    try {
        return (
            new URLSearchParams(window.location.search).get("embedded") === "1"
        );
    } catch {
        return false;
    }
};

// 顶层打开的 shell 深链没有父帧,单看 iframe 会误判独立模式;
// ?embedded=1 是权威标记。
export const isEmbedded = (): boolean =>
    typeof window !== "undefined" &&
    (window.parent !== window || embeddedParam());

// SDK 自身按 window.parent 自动判定桥接/独立;此处无参构造。
export const sdk = createShellSdk();
