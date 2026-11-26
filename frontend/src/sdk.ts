import { createShellSdk } from "@fusion/web-sdk";

// Singleton SDK (toast/tab/theme postMessage bridge with the shell host).
// Data calls live in services/api.ts: embedded mode uses the SDK http bridge (host carries the gateway session
// token, gateway then injects the module key upstream); standalone mode connects same-origin /api/v1 directly.
// ?embedded=1 is appended by the shell; standalone runs keep the module's own navigation.
export const embeddedParam = (): boolean => {
    try {
        return (
            new URLSearchParams(window.location.search).get("embedded") === "1"
        );
    } catch {
        return false;
    }
};

// Shell deep links opened top-level have no parent frame; judging standalone mode from the iframe alone misfires;
// ?embedded=1 is the authoritative marker.
export const isEmbedded = (): boolean =>
    typeof window !== "undefined" &&
    (window.parent !== window || embeddedParam());

// The SDK itself decides bridged/standalone by window.parent; construct with no args here.
export const sdk = createShellSdk();
