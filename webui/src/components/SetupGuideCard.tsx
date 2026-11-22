import { createEffect, createMemo, createSignal, Show } from "solid-js";
import { t } from "../i18n";
import type { ConfigResponse } from "../types/ConfigResponse";

interface SetupGuideCardProps {
  configData: ConfigResponse | null;
}

function extractPort(addr: string | null | undefined, fallback: string): string {
  if (!addr) return fallback;
  const idx = addr.lastIndexOf(":");
  if (idx === -1) return fallback;
  const port = addr.slice(idx + 1).trim();
  return port || fallback;
}

export function SetupGuideCard(props: SetupGuideCardProps) {
  const defaultHost = () => {
    const ddr = props.configData?.ddr_hostname?.trim();
    if (ddr) return ddr;
    if (typeof window !== "undefined" && window.location.hostname) {
      return window.location.hostname;
    }
    return "dns.example.com";
  };

  const [host, setHost] = createSignal(defaultHost());
  const [hostEdited, setHostEdited] = createSignal(false);
  const [clientId, setClientId] = createSignal("");
  const [copiedKey, setCopiedKey] = createSignal("");
  const [downloading, setDownloading] = createSignal<"doh" | "dot" | null>(null);
  const [downloadError, setDownloadError] = createSignal("");

  createEffect(() => {
    if (!hostEdited()) {
      setHost(defaultHost());
    }
  });

  const cleanHost = createMemo(() => host().trim() || defaultHost());
  const cleanClientId = createMemo(() => clientId().trim());

  const dohUrl = createMemo(() => {
    const cid = cleanClientId();
    return cid
      ? `https://${cleanHost()}/dns-query/${encodeURIComponent(cid)}`
      : `https://${cleanHost()}/dns-query`;
  });

  const dotHost = createMemo(() => {
    const cid = cleanClientId();
    return cid ? `${cid}.${cleanHost()}` : cleanHost();
  });

  const doqUrl = createMemo(() => {
    const port = extractPort(props.configData?.listen_doq, "853");
    return `quic://${cleanHost()}:${port}`;
  });

  const plainDns = createMemo(() => {
    const port = extractPort(props.configData?.listen_dns, "53");
    return `${cleanHost()}:${port}`;
  });

  async function copyText(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      window.setTimeout(() => {
        if (copiedKey() === key) setCopiedKey("");
      }, 1500);
    } catch {
      // Ignore clipboard failures in restricted contexts.
    }
  }

  async function downloadMobileconfig(protocol: "doh" | "dot") {
    setDownloading(protocol);
    setDownloadError("");
    try {
      const params = new URLSearchParams({
        protocol,
        hostname: cleanHost(),
      });
      const cid = cleanClientId();
      if (cid) {
        params.set("client_id", cid);
      }
      const res = await fetch(`/api/setup/mobileconfig?${params.toString()}`);
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        setDownloadError(body?.error ?? `HTTP ${res.status}`);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = cid
        ? `crabdns-${cid}-${protocol}.mobileconfig`
        : `crabdns-${protocol}.mobileconfig`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(String(err));
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-4">
      <div>
        <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
          {t("setupGuideTitle")}
        </h3>
        <p class="text-xs text-[#666666] dark:text-[#a1a1aa] mt-0.5">{t("setupGuideDesc")}</p>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
            {t("setupGuideHostnameLabel")}
          </label>
          <input
            type="text"
            value={host()}
            onInput={(e) => {
              setHostEdited(true);
              setHost(e.currentTarget.value);
            }}
            placeholder="dns.example.com"
            class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm font-mono text-[#171717] dark:text-[#ededed] outline-none"
          />
        </div>
        <div>
          <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
            {t("setupGuideClientIdLabel")}
          </label>
          <input
            type="text"
            value={clientId()}
            onInput={(e) => setClientId(e.currentTarget.value)}
            placeholder="iphone-pro"
            class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm font-mono text-[#171717] dark:text-[#ededed] outline-none"
          />
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
        <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
          <div class="min-w-0">
            <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">DNS-over-HTTPS (DoH)</div>
            <div class="font-mono text-[#171717] dark:text-[#ededed] truncate">{dohUrl()}</div>
          </div>
          <button
            type="button"
            onClick={() => void copyText("doh", dohUrl())}
            class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
          >
            {copiedKey() === "doh" ? t("setupGuideCopied") : t("setupGuideCopy")}
          </button>
        </div>

        <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
          <div class="min-w-0">
            <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
              DNS-over-TLS (DoT / Android Private DNS)
            </div>
            <div class="font-mono text-[#171717] dark:text-[#ededed] truncate">{dotHost()}</div>
          </div>
          <button
            type="button"
            onClick={() => void copyText("dot", dotHost())}
            class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
          >
            {copiedKey() === "dot" ? t("setupGuideCopied") : t("setupGuideCopy")}
          </button>
        </div>

        <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
          <div class="min-w-0">
            <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">DNS-over-QUIC (DoQ)</div>
            <div class="font-mono text-[#171717] dark:text-[#ededed] truncate">{doqUrl()}</div>
          </div>
          <button
            type="button"
            onClick={() => void copyText("doq", doqUrl())}
            class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
          >
            {copiedKey() === "doq" ? t("setupGuideCopied") : t("setupGuideCopy")}
          </button>
        </div>

        <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
          <div class="min-w-0">
            <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">Plain DNS (UDP / TCP)</div>
            <div class="font-mono text-[#171717] dark:text-[#ededed] truncate">{plainDns()}</div>
          </div>
          <button
            type="button"
            onClick={() => void copyText("plain", plainDns())}
            class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
          >
            {copiedKey() === "plain" ? t("setupGuideCopied") : t("setupGuideCopy")}
          </button>
        </div>
      </div>

      <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("setupGuideAppleTitle")}
            </div>
            <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
              {t("setupGuideAppleDesc")}
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={downloading() !== null}
              onClick={() => void downloadMobileconfig("doh")}
              class="px-3 py-1.5 rounded-lg text-xs font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] hover:opacity-90 disabled:opacity-50 cursor-pointer"
            >
              {downloading() === "doh" ? t("setupGuideDownloading") : t("setupGuideDownloadDoh")}
            </button>
            <button
              type="button"
              disabled={downloading() !== null}
              onClick={() => void downloadMobileconfig("dot")}
              class="px-3 py-1.5 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 cursor-pointer"
            >
              {downloading() === "dot" ? t("setupGuideDownloading") : t("setupGuideDownloadDot")}
            </button>
          </div>
        </div>
        <Show when={downloadError()}>
          <div class="text-xs text-red-600 dark:text-red-400">{downloadError()}</div>
        </Show>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-[11px] text-[#666666] dark:text-[#a1a1aa]">
        <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] p-3 space-y-1">
          <div class="font-medium text-[#171717] dark:text-[#ededed]">
            {t("setupGuideAndroidTitle")}
          </div>
          <p>{t("setupGuideAndroidDesc")}</p>
        </div>
        <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] p-3 space-y-1">
          <div class="font-medium text-[#171717] dark:text-[#ededed]">
            {t("setupGuideDesktopTitle")}
          </div>
          <p>{t("setupGuideDesktopDesc")}</p>
        </div>
      </div>
    </div>
  );
}
