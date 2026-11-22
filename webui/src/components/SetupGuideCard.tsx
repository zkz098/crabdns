import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { ConfigResponse } from "../types/ConfigResponse";
import type { TlsStatusResponse } from "../types/TlsStatusResponse";

interface SetupGuideCardProps {
  configData: ConfigResponse | null;
  tlsStatus?: TlsStatusResponse | null;
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
  const [showUnavailable, setShowUnavailable] = createSignal(false);

  const hasTlsCert = createMemo(() => {
    if (props.tlsStatus) {
      return Boolean(props.tlsStatus.cert_path && props.tlsStatus.key_path);
    }
    return Boolean(props.configData?.tls_cert_path && props.configData?.tls_key_path);
  });

  const dohAvailable = createMemo(() => {
    if (props.configData?.doh_enabled === false) return false;
    if (!hasTlsCert()) return false;
    if (props.tlsStatus) return props.tlsStatus.https_enabled;
    return Boolean(props.configData?.listen_web_tls);
  });

  const dotAvailable = createMemo(() => {
    if (!hasTlsCert()) return false;
    if (props.tlsStatus) return props.tlsStatus.dot_enabled;
    return Boolean(props.configData?.listen_dot);
  });

  const doqAvailable = createMemo(() => {
    if (!hasTlsCert()) return false;
    if (props.tlsStatus) return props.tlsStatus.doq_enabled;
    return Boolean(props.configData?.listen_doq);
  });

  const hasUnavailable = createMemo(() => !dohAvailable() || !dotAvailable() || !doqAvailable());
  const hasAnyEncryptedAvailable = createMemo(
    () => dohAvailable() || dotAvailable() || doqAvailable(),
  );
  const showDoh = createMemo(() => dohAvailable() || showUnavailable());
  const showDot = createMemo(() => dotAvailable() || showUnavailable());
  const showDoq = createMemo(() => doqAvailable() || showUnavailable());
  const showClientId = createMemo(() => showDoh() || showDot());
  const showApple = createMemo(() => showDoh() || showDot());
  const showAndroid = createMemo(() => showDot());
  const showDesktop = createMemo(() => showDoh() || showDot());

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

  const endpoints = createMemo(() => {
    const items: Array<{ key: string; label: string; value: string; available: boolean }> = [];
    if (showDoh()) {
      items.push({
        key: "doh",
        label: "DNS-over-HTTPS (DoH)",
        value: dohUrl(),
        available: dohAvailable(),
      });
    }
    if (showDot()) {
      items.push({
        key: "dot",
        label: "DNS-over-TLS (DoT / Android Private DNS)",
        value: dotHost(),
        available: dotAvailable(),
      });
    }
    if (showDoq()) {
      items.push({
        key: "doq",
        label: "DNS-over-QUIC (DoQ)",
        value: doqUrl(),
        available: doqAvailable(),
      });
    }
    items.push({
      key: "plain",
      label: "Plain DNS (UDP / TCP)",
      value: plainDns(),
      available: true,
    });
    return items;
  });

  createEffect(() => {
    if (!hostEdited()) {
      setHost(defaultHost());
    }
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
      <div class="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
            {t("setupGuideTitle")}
          </h3>
          <p class="text-xs text-[#666666] dark:text-[#a1a1aa] mt-0.5">{t("setupGuideDesc")}</p>
        </div>
        <Show when={hasUnavailable()}>
          <button
            type="button"
            onClick={() => setShowUnavailable((prev) => !prev)}
            class="shrink-0 px-2.5 py-1 rounded-lg text-xs border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
          >
            {showUnavailable() ? t("setupGuideHideUnavailable") : t("setupGuideShowUnavailable")}
          </button>
        </Show>
      </div>

      <Show when={!hasAnyEncryptedAvailable() && !showUnavailable()}>
        <p class="text-xs text-[#8f8f8f] dark:text-[#71717a]">{t("setupGuideNoTlsHint")}</p>
      </Show>

      <div class={`grid grid-cols-1 ${showClientId() ? "md:grid-cols-2" : ""} gap-3`}>
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
        <Show when={showClientId()}>
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
        </Show>
      </div>

      <div
        class={`grid grid-cols-1 ${endpoints().length > 1 ? "md:grid-cols-2" : ""} gap-2.5 text-xs`}
      >
        <For each={endpoints()}>
          {(item) => (
            <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
              <div class="min-w-0">
                <div class="flex items-center gap-1.5 text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                  <span>{item.label}</span>
                  <Show when={!item.available}>
                    <span class="px-1.5 py-0.2 rounded bg-[#eaeaea] dark:bg-[#262626] text-[10px] text-[#666666] dark:text-[#a1a1aa]">
                      {t("setupGuideUnavailableTag")}
                    </span>
                  </Show>
                </div>
                <div class="font-mono text-[#171717] dark:text-[#ededed] truncate">
                  {item.value}
                </div>
              </div>
              <button
                type="button"
                onClick={() => void copyText(item.key, item.value)}
                class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
              >
                {copiedKey() === item.key ? t("setupGuideCopied") : t("setupGuideCopy")}
              </button>
            </div>
          )}
        </For>
      </div>

      <Show when={showApple()}>
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
              <Show when={showDoh()}>
                <button
                  type="button"
                  disabled={downloading() !== null}
                  onClick={() => void downloadMobileconfig("doh")}
                  class="px-3 py-1.5 rounded-lg text-xs font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] hover:opacity-90 disabled:opacity-50 cursor-pointer"
                >
                  {downloading() === "doh"
                    ? t("setupGuideDownloading")
                    : t("setupGuideDownloadDoh")}
                </button>
              </Show>
              <Show when={showDot()}>
                <button
                  type="button"
                  disabled={downloading() !== null}
                  onClick={() => void downloadMobileconfig("dot")}
                  class="px-3 py-1.5 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 cursor-pointer"
                >
                  {downloading() === "dot"
                    ? t("setupGuideDownloading")
                    : t("setupGuideDownloadDot")}
                </button>
              </Show>
            </div>
          </div>
          <Show when={downloadError()}>
            <div class="text-xs text-red-600 dark:text-red-400">{downloadError()}</div>
          </Show>
        </div>
      </Show>

      <Show when={showAndroid() || showDesktop()}>
        <div
          class={`grid grid-cols-1 ${showAndroid() && showDesktop() ? "md:grid-cols-2" : ""} gap-2.5 text-[11px] text-[#666666] dark:text-[#a1a1aa]`}
        >
          <Show when={showAndroid()}>
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] p-3 space-y-1">
              <div class="font-medium text-[#171717] dark:text-[#ededed]">
                {t("setupGuideAndroidTitle")}
              </div>
              <p>{t("setupGuideAndroidDesc")}</p>
            </div>
          </Show>
          <Show when={showDesktop()}>
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] p-3 space-y-1">
              <div class="font-medium text-[#171717] dark:text-[#ededed]">
                {t("setupGuideDesktopTitle")}
              </div>
              <p>{t("setupGuideDesktopDesc")}</p>
            </div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
