import { For, Show } from "solid-js";
import { t } from "../i18n";
import type { BlockMode } from "../types/BlockMode";
import type { ConfigResponse } from "../types/ConfigResponse";
import type { TlsStatusResponse } from "../types/TlsStatusResponse";
import type { UpdateStatusResponse } from "../types/UpdateStatusResponse";
import type { UpstreamCapabilities } from "../types/UpstreamCapabilities";
import type { UpstreamStatus } from "../types/UpstreamStatus";
import type { UpstreamStrategy } from "../types/UpstreamStrategy";

interface SettingsViewProps {
  configData: ConfigResponse | null;
  upstreamsText: string;
  onUpstreamsChange: (val: string) => void;
  bootstrapDnsText: string;
  onBootstrapDnsChange: (val: string) => void;
  upstreamStrategy: UpstreamStrategy;
  onUpstreamStrategyChange: (val: UpstreamStrategy) => void;
  upstreamHealth: UpstreamStatus[];
  probingUpstreams: boolean;
  onProbeUpstreams: () => void;
  upstreamCapabilities: UpstreamCapabilities[];
  probingCapabilities: boolean;
  probeCapabilitiesError: string;
  onProbeCapabilities: () => void;
  onReplaceUpstream: (fromInput: string, toUrl: string) => void;
  blockMode: BlockMode;
  onBlockModeChange: (val: BlockMode) => void;
  allowCidrsText: string;
  onAllowCidrsChange: (val: string) => void;
  denyCidrsText: string;
  onDenyCidrsChange: (val: string) => void;
  rateLimitQps: number;
  onRateLimitChange: (val: number) => void;
  cacheSize: number;
  onCacheSizeChange: (val: number) => void;
  upstreamTimeoutMs: number;
  onUpstreamTimeoutChange: (val: number) => void;
  logRetentionHours: number;
  onLogRetentionChange: (val: number) => void;
  optimisticCache: boolean;
  onOptimisticCacheChange: (val: boolean) => void;
  cacheMinTtlSecs: number;
  onCacheMinTtlChange: (val: number) => void;
  cacheMaxTtlSecs: number;
  onCacheMaxTtlChange: (val: number) => void;
  cachePrefetchEnabled: boolean;
  onCachePrefetchChange: (val: boolean) => void;
  cachePersistEnabled: boolean;
  onCachePersistChange: (val: boolean) => void;
  splitDnsText: string;
  onSplitDnsChange: (val: string) => void;
  cnameCloakingBlocking: boolean;
  onCnameCloakingChange: (val: boolean) => void;
  dohEnabled: boolean;
  onDohEnabledChange: (val: boolean) => void;
  allowPrivateSubscriptions: boolean;
  onAllowPrivateSubscriptionsChange: (val: boolean) => void;
  ecsEnabled: boolean;
  onEcsEnabledChange: (val: boolean) => void;
  ecsCustomIp: string;
  onEcsCustomIpChange: (val: string) => void;
  ecsIpv4Prefix: number;
  onEcsIpv4PrefixChange: (val: number) => void;
  ecsIpv6Prefix: number;
  onEcsIpv6PrefixChange: (val: number) => void;
  dnssecEnabled: boolean;
  onDnssecEnabledChange: (val: boolean) => void;
  hostsEnabled: boolean;
  onHostsEnabledChange: (val: boolean) => void;
  hostsPath: string;
  onHostsPathChange: (val: string) => void;
  dhcpLeasesEnabled: boolean;
  onDhcpLeasesEnabledChange: (val: boolean) => void;
  dhcpLeasesPath: string;
  onDhcpLeasesPathChange: (val: string) => void;
  mdnsEnabled: boolean;
  onMdnsEnabledChange: (val: boolean) => void;
  sniClientIdHostnamesText: string;
  onSniClientIdHostnamesChange: (val: string) => void;
  privatePtrEnabled: boolean;
  onPrivatePtrEnabledChange: (val: boolean) => void;
  privatePtrUpstreamsText: string;
  onPrivatePtrUpstreamsChange: (val: string) => void;
  ddrEnabled: boolean;
  onDdrEnabledChange: (val: boolean) => void;
  ddrHostname: string;
  onDdrHostnameChange: (val: string) => void;
  dnsRebindingProtection: boolean;
  onDnsRebindingProtectionChange: (val: boolean) => void;
  blockAnyQueries: boolean;
  onBlockAnyQueriesChange: (val: boolean) => void;
  trustedProxiesText: string;
  onTrustedProxiesChange: (val: string) => void;
  rdnsEnabled: boolean;
  onRdnsEnabledChange: (val: boolean) => void;
  tlsCertPath: string;
  onTlsCertPathChange: (val: string) => void;
  tlsKeyPath: string;
  onTlsKeyPathChange: (val: string) => void;
  tlsStatus: TlsStatusResponse | null;
  reloadingTls: boolean;
  tlsMessage: string;
  tlsIsError: boolean;
  onReloadTls: () => void;
  configMessage: string;
  configIsError: boolean;
  onSave: () => void;
  authEnabled: boolean;
  onAuthEnabledChange: (val: boolean) => void;
  authUsername: string;
  onAuthUsernameChange: (val: string) => void;
  authPassword: string;
  onAuthPasswordChange: (val: string) => void;
  authMessage: string;
  authIsError: boolean;
  onSaveAuth: () => void;
  onExportBackup?: () => Promise<void> | void;
  onImportBackup?: (file: File) => Promise<void> | void;
  backupMessage?: string;
  backupIsError?: boolean;
  backupBusy?: boolean;
  updateStatus?: UpdateStatusResponse | null;
  updateBusy?: boolean;
  updateMessage?: string;
  updateIsError?: boolean;
  onCheckUpdate?: () => Promise<void> | void;
  onApplyUpdate?: () => Promise<void> | void;
}

export function SettingsView(props: SettingsViewProps) {
  return (
    <div class="animate-view-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-6">
      {/* Header */}
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="space-y-1">
          <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
            {t("settingsTitle")}
          </h2>
          <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
            {t("settingsSubtitle")}
          </p>
        </div>

        <div class="flex items-center justify-end gap-3 shrink-0">
          <Show when={props.configMessage}>
            <span
              class={`animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                props.configIsError
                  ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                  : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
              }`}
            >
              <span class={props.configIsError ? "i-ri-error-warning-line" : "i-ri-check-line"} />
              {props.configMessage}
            </span>
          </Show>
          <button
            type="button"
            onClick={props.onSave}
            class="w-full sm:w-auto h-9 px-4 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center justify-center gap-1.5 cursor-pointer border-0 transition-all duration-200 active:scale-[0.97]"
          >
            <span class="i-ri-save-3-line text-sm" />
            <span>{t("settingsSave")}</span>
          </button>
        </div>
      </div>

      {/* Form Fields */}
      <div class="space-y-5">
        <div>
          <div class="flex items-center justify-between gap-2 mb-1.5">
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsUpstreamsLabel")}
            </label>
            <button
              type="button"
              disabled={props.probingCapabilities}
              onClick={props.onProbeCapabilities}
              class="h-7 px-2.5 rounded-md text-xs font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] inline-flex items-center gap-1.5 cursor-pointer hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 transition-colors"
            >
              <span
                class={
                  props.probingCapabilities
                    ? "i-ri-loader-4-line animate-spin text-xs"
                    : "i-ri-radar-line text-xs"
                }
              />
              <span>
                {props.probingCapabilities
                  ? t("settingsProbingCapabilities")
                  : t("settingsProbeCapabilities")}
              </span>
            </button>
          </div>
          <textarea
            rows={4}
            spellcheck={false}
            value={props.upstreamsText}
            onInput={(e) => props.onUpstreamsChange(e.currentTarget.value)}
            class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
          />
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-1.5">
            {t("settingsUpstreamsHint")}
          </p>

          <Show when={props.probeCapabilitiesError}>
            <p class="text-xs text-rose-600 dark:text-rose-400 mt-2">
              {props.probeCapabilitiesError}
            </p>
          </Show>

          <Show when={props.upstreamCapabilities.length > 0}>
            <div class="mt-3 space-y-2">
              <For each={props.upstreamCapabilities}>
                {(cap) => {
                  const protoLabel = () => {
                    const base =
                      cap.protocol === "doh"
                        ? "DoH"
                        : cap.protocol === "dot"
                          ? "DoT"
                          : cap.protocol.toUpperCase();
                    return cap.transport_detail ? `${base} · ${cap.transport_detail}` : base;
                  };
                  return (
                    <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 space-y-2">
                      <div class="flex flex-wrap items-center justify-between gap-2">
                        <div class="flex items-center gap-2 min-w-0">
                          <span
                            class={`h-2 w-2 rounded-full shrink-0 ${
                              cap.reachable ? "bg-emerald-500" : "bg-rose-500"
                            }`}
                          />
                          <span class="font-mono text-xs text-[#171717] dark:text-[#ededed] truncate">
                            {cap.endpoint}
                          </span>
                        </div>
                        <div class="flex items-center gap-1.5 shrink-0">
                          <span
                            class={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                              cap.encrypted
                                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                                : "bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border-zinc-500/20"
                            }`}
                          >
                            <Show when={cap.encrypted}>
                              <span class="i-ri-lock-line text-[10px]" />
                            </Show>
                            {protoLabel()}
                          </span>
                          <Show
                            when={cap.reachable && cap.latency_ms !== null}
                            fallback={
                              <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                                {t("settingsCapUnreachable")}
                              </span>
                            }
                          >
                            <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums">
                              {cap.latency_ms}ms
                            </span>
                          </Show>
                        </div>
                      </div>

                      <Show when={cap.error}>
                        <p class="text-[11px] text-rose-600 dark:text-rose-400 font-mono break-all">
                          {cap.error}
                        </p>
                      </Show>

                      <Show when={cap.reachable}>
                        <div class="flex flex-wrap items-center gap-1.5">
                          {/* EDNS0 */}
                          <Show
                            when={cap.edns === true}
                            fallback={
                              <Show when={cap.edns === false}>
                                <span class="px-2 py-0.5 rounded-md text-[11px] bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                                  {t("settingsCapNoEdns")}
                                </span>
                              </Show>
                            }
                          >
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 tabular-nums">
                              {cap.edns_udp_size ? `EDNS0 (${cap.edns_udp_size}B)` : "EDNS0"}
                            </span>
                          </Show>

                          {/* DNSSEC */}
                          <Show
                            when={cap.dnssec_validating === true}
                            fallback={
                              <Show
                                when={cap.dnssec_aware === true}
                                fallback={
                                  <Show when={cap.dnssec_aware === false}>
                                    <span class="px-2 py-0.5 rounded-md text-[11px] bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border border-zinc-500/20">
                                      {t("settingsCapNoDnssec")}
                                    </span>
                                  </Show>
                                }
                              >
                                <span class="px-2 py-0.5 rounded-md text-[11px] bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-500/20">
                                  {t("settingsCapDnssecAware")}
                                </span>
                              </Show>
                            }
                          >
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                              {t("settingsCapDnssecValidating")}
                            </span>
                          </Show>

                          {/* ECS */}
                          <Show
                            when={cap.ecs === true}
                            fallback={
                              <Show when={cap.ecs === false}>
                                <span class="px-2 py-0.5 rounded-md text-[11px] bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border border-zinc-500/20">
                                  {t("settingsCapNoEcs")}
                                </span>
                              </Show>
                            }
                          >
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                              {t("settingsCapEcs")}
                            </span>
                          </Show>

                          {/* NSID node identifier */}
                          <Show when={cap.nsid}>
                            {(nsid) => (
                              <span
                                title={`NSID: ${nsid()}`}
                                class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border border-indigo-500/20 max-w-[200px] truncate"
                              >
                                <span class="i-ri-server-line text-[10px] shrink-0" />
                                <span class="truncate">{nsid()}</span>
                              </span>
                            )}
                          </Show>

                          {/* DNS Cookies (RFC 7873) */}
                          <Show when={cap.dns_cookies === true}>
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                              {t("settingsCapCookies")}
                            </span>
                          </Show>

                          {/* EDNS Padding (RFC 7830) */}
                          <Show when={cap.edns_padding === true}>
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                              {t("settingsCapPadding")}
                            </span>
                          </Show>

                          {/* Extended DNS Errors (RFC 8914) */}
                          <Show when={cap.ede === true}>
                            <span
                              title={cap.ede_detail ?? "RFC 8914 Extended DNS Errors"}
                              class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20"
                            >
                              {t("settingsCapEde")}
                            </span>
                          </Show>

                          {/* RA warning */}
                          <Show when={cap.recursion_available === false}>
                            <span class="px-2 py-0.5 rounded-md text-[11px] bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                              {t("settingsCapNonRecursive")}
                            </span>
                          </Show>

                          {/* NXDOMAIN hijack warning */}
                          <Show when={cap.nxdomain_hijack === true}>
                            <span class="px-2 py-0.5 rounded-md text-[11px] font-medium bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                              {t("settingsCapNxdomainHijack")}
                            </span>
                          </Show>
                        </div>

                        {/* Config mismatch hints */}
                        <Show when={props.dnssecEnabled && cap.dnssec_aware === false}>
                          <p class="text-[11px] text-amber-700 dark:text-amber-400">
                            {t("settingsCapDnssecMismatchHint")}
                          </p>
                        </Show>
                        <Show when={props.ecsEnabled && cap.ecs === false}>
                          <p class="text-[11px] text-amber-700 dark:text-amber-400">
                            {t("settingsCapEcsMismatchHint")}
                          </p>
                        </Show>

                        {/* DDR encrypted upgrade suggestions */}
                        <Show when={cap.ddr_upgrades.length > 0}>
                          <div class="flex flex-wrap items-center gap-1.5 pt-0.5">
                            <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                              {t("settingsCapDdrUpgradeLabel")}
                            </span>
                            <For each={cap.ddr_upgrades}>
                              {(upgradeUrl) => (
                                <button
                                  type="button"
                                  onClick={() => props.onReplaceUpstream(cap.input, upgradeUrl)}
                                  class="px-2 py-0.5 rounded-md text-[11px] font-mono bg-white dark:bg-[#111111] border border-emerald-500/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10 cursor-pointer transition-colors"
                                >
                                  {upgradeUrl}
                                </button>
                              )}
                            </For>
                          </div>
                        </Show>
                      </Show>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>
        </div>

        <div>
          <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
            {t("settingsBootstrapDnsLabel")}
          </label>
          <textarea
            rows={2}
            spellcheck={false}
            placeholder="1.1.1.1&#10;8.8.8.8"
            value={props.bootstrapDnsText}
            onInput={(e) => props.onBootstrapDnsChange(e.currentTarget.value)}
            class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
          />
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-1.5">
            {t("settingsBootstrapDnsHint")}
          </p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsCacheSizeLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheSize}
              onInput={(e) => props.onCacheSizeChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsTimeoutLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.upstreamTimeoutMs}
              onInput={(e) => props.onUpstreamTimeoutChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsRetentionLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.logRetentionHours}
              onInput={(e) => props.onLogRetentionChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
        </div>

        {/* Custom Vercel-style Toggle Switch */}
        <div class="flex items-center justify-between gap-4 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5">
          <span class="text-sm text-[#171717] dark:text-[#ededed] leading-snug">
            {t("settingsOptimisticLabel")}
          </span>
          <button
            type="button"
            role="switch"
            aria-checked={props.optimisticCache}
            onClick={() => props.onOptimisticCacheChange(!props.optimisticCache)}
            class={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-0 p-0.5 transition-colors duration-200 ease-in-out ${
              props.optimisticCache
                ? "bg-[#171717] dark:bg-[#ededed]"
                : "bg-[#d4d4d8] dark:bg-[#3f3f46]"
            }`}
          >
            <span
              class={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white dark:bg-[#0a0a0a] shadow-sm transition-transform duration-200 ease-in-out ${
                props.optimisticCache ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>

        {/* Cache TTL, Prefetch & Persistence */}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsCacheMinTtlLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheMinTtlSecs}
              onInput={(e) => props.onCacheMinTtlChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
            />
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsCacheMaxTtlLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheMaxTtlSecs}
              onInput={(e) => props.onCacheMaxTtlChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
            />
          </div>
          <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
            <input
              type="checkbox"
              checked={props.cachePrefetchEnabled}
              onChange={(e) => props.onCachePrefetchChange(e.currentTarget.checked)}
              class="rounded border-[#eaeaea] dark:border-[#262626]"
            />
            {t("settingsCachePrefetchLabel")}
          </label>
          <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
            <input
              type="checkbox"
              checked={props.cachePersistEnabled}
              onChange={(e) => props.onCachePersistChange(e.currentTarget.checked)}
              class="rounded border-[#eaeaea] dark:border-[#262626]"
            />
            {t("settingsCachePersistLabel")}
          </label>
        </div>

        {/* Upstream Strategy & Block Response Mode */}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsStrategyLabel")}
            </label>
            <select
              value={props.upstreamStrategy}
              onChange={(e) =>
                props.onUpstreamStrategyChange(e.currentTarget.value as UpstreamStrategy)
              }
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
            >
              <option value="failover">{t("settingsStrategyFailover")}</option>
              <option value="parallel">{t("settingsStrategyParallel")}</option>
              <option value="least_latency">{t("settingsStrategyLeastLatency")}</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsBlockModeLabel")}
            </label>
            <select
              value={props.blockMode}
              onChange={(e) => props.onBlockModeChange(e.currentTarget.value as BlockMode)}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
            >
              <option value="zero_ip">{t("settingsBlockZeroIp")}</option>
              <option value="nx_domain">{t("settingsBlockNxDomain")}</option>
              <option value="no_data">{t("settingsBlockNoData")}</option>
            </select>
          </div>
        </div>

        {/* Split DNS & Feature Toggles */}
        <div class="space-y-3">
          <div>
            <div class="flex flex-wrap items-center justify-between gap-2 mb-1.5">
              <label class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                {t("settingsSplitDnsLabel")}
              </label>
              <span class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                {t("settingsSplitDnsHint")}
              </span>
            </div>
            <textarea
              value={props.splitDnsText}
              onInput={(e) => props.onSplitDnsChange(e.currentTarget.value)}
              rows={3}
              spellcheck={false}
              class="w-full font-mono text-xs bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 text-[#171717] dark:text-[#ededed] outline-none resize-y"
            />
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.cnameCloakingBlocking}
                onChange={(e) => props.onCnameCloakingChange(e.currentTarget.checked)}
              />
              <span>{t("settingsCnameCloakingLabel")}</span>
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.dohEnabled}
                onChange={(e) => props.onDohEnabledChange(e.currentTarget.checked)}
              />
              <span>{t("settingsDohEnabledLabel")}</span>
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.allowPrivateSubscriptions}
                onChange={(e) => props.onAllowPrivateSubscriptionsChange(e.currentTarget.checked)}
              />
              <span>{t("settingsAllowPrivateSubsLabel")}</span>
            </label>
          </div>
        </div>

        {/* Upstream Health */}
        <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsUpstreamHealthTitle")}
            </span>
            <button
              type="button"
              disabled={props.probingUpstreams}
              onClick={props.onProbeUpstreams}
              class="h-7 px-2.5 rounded-md text-xs font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] cursor-pointer hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50"
            >
              {t("settingsProbeNow")}
            </button>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <For each={props.upstreamHealth}>
              {(item) => (
                <div class="flex items-center justify-between gap-2 rounded-md border border-[#eaeaea] dark:border-[#222222] bg-white dark:bg-[#0a0a0a] px-2.5 py-2 text-xs">
                  <div class="flex items-center gap-2 min-w-0">
                    <span
                      class={`h-2 w-2 rounded-full shrink-0 ${
                        item.healthy ? "bg-emerald-500" : "bg-rose-500"
                      }`}
                    />
                    <span class="font-mono truncate text-[#171717] dark:text-[#ededed]">
                      {item.endpoint}
                    </span>
                  </div>
                  <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {item.healthy ? t("settingsUpstreamHealthy") : t("settingsUpstreamUnhealthy")} ·{" "}
                    {item.ewma_latency_ms}ms
                  </span>
                </div>
              )}
            </For>
          </div>
        </div>

        {/* DNS Client ACL & Rate Limiting */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
            {t("settingsAclTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsAllowCidrsLabel")}
              </label>
              <textarea
                rows={3}
                spellcheck={false}
                placeholder="192.168.0.0/16"
                value={props.allowCidrsText}
                onInput={(e) => props.onAllowCidrsChange(e.currentTarget.value)}
                class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDenyCidrsLabel")}
              </label>
              <textarea
                rows={3}
                spellcheck={false}
                placeholder="203.0.113.0/24"
                value={props.denyCidrsText}
                onInput={(e) => props.onDenyCidrsChange(e.currentTarget.value)}
                class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
          <div class="max-w-xs">
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsRateLimitLabel")}
            </label>
            <input
              type="number"
              min={0}
              value={props.rateLimitQps}
              onInput={(e) => props.onRateLimitChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
            />
          </div>
        </div>

        {/* Protocol, DNSSEC & Security */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
            {t("settingsProtocolSecurityTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.ecsEnabled}
                onChange={(e) => props.onEcsEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsEcsLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.dnssecEnabled}
                onChange={(e) => props.onDnssecEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsDnssecLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.dnsRebindingProtection}
                onChange={(e) => props.onDnsRebindingProtectionChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsDnsRebindingLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.blockAnyQueries}
                onChange={(e) => props.onBlockAnyQueriesChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsBlockAnyLabel")}
            </label>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsEcsCustomIpLabel")}
              </label>
              <input
                type="text"
                placeholder="203.0.113.0/24"
                value={props.ecsCustomIp}
                onInput={(e) => props.onEcsCustomIpChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsEcsV4PrefixLabel")}
              </label>
              <input
                type="number"
                min={0}
                max={32}
                value={props.ecsIpv4Prefix}
                onInput={(e) => props.onEcsIpv4PrefixChange(Number(e.currentTarget.value))}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsEcsV6PrefixLabel")}
              </label>
              <input
                type="number"
                min={0}
                max={128}
                value={props.ecsIpv6Prefix}
                onInput={(e) => props.onEcsIpv6PrefixChange(Number(e.currentTarget.value))}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
              />
            </div>
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsTrustedProxiesLabel")}
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="127.0.0.1/32"
              value={props.trustedProxiesText}
              onInput={(e) => props.onTrustedProxiesChange(e.currentTarget.value)}
              class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
            />
          </div>
        </div>

        {/* LAN & System Integration */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
            {t("settingsLanTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.hostsEnabled}
                onChange={(e) => props.onHostsEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsHostsLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.dhcpLeasesEnabled}
                onChange={(e) => props.onDhcpLeasesEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsDhcpLeasesLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.mdnsEnabled}
                onChange={(e) => props.onMdnsEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsMdnsLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.privatePtrEnabled}
                onChange={(e) => props.onPrivatePtrEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsPrivatePtrLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.ddrEnabled}
                onChange={(e) => props.onDdrEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsDdrLabel")}
            </label>
            <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
              <input
                type="checkbox"
                checked={props.rdnsEnabled}
                onChange={(e) => props.onRdnsEnabledChange(e.currentTarget.checked)}
                class="rounded border-[#eaeaea] dark:border-[#262626]"
              />
              {t("settingsRdnsLabel")}
            </label>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsHostsPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/etc/hosts"
                value={props.hostsPath}
                onInput={(e) => props.onHostsPathChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDhcpLeasesPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/var/lib/misc/dnsmasq.leases"
                value={props.dhcpLeasesPath}
                onInput={(e) => props.onDhcpLeasesPathChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDdrHostnameLabel")}
              </label>
              <input
                type="text"
                placeholder="dns.example.com"
                value={props.ddrHostname}
                onInput={(e) => props.onDdrHostnameChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsSniHostnamesLabel")}
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="dot.example.com"
              value={props.sniClientIdHostnamesText}
              onInput={(e) => props.onSniClientIdHostnamesChange(e.currentTarget.value)}
              class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
            />
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsPrivatePtrUpstreamsLabel")}
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="udp://192.168.1.1:53"
              value={props.privatePtrUpstreamsText}
              onInput={(e) => props.onPrivatePtrUpstreamsChange(e.currentTarget.value)}
              class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
            />
          </div>
        </div>

        {/* Native TLS & Certificate Hot Reload */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsTlsTitle")}
            </p>
            <div class="flex items-center gap-2">
              <Show when={props.tlsMessage}>
                <span
                  class={`text-xs font-medium ${
                    props.tlsIsError
                      ? "text-rose-600 dark:text-rose-400"
                      : "text-emerald-600 dark:text-emerald-400"
                  }`}
                >
                  {props.tlsMessage}
                </span>
              </Show>
              <button
                type="button"
                disabled={
                  props.reloadingTls ||
                  !(
                    props.tlsStatus?.https_enabled ||
                    props.tlsStatus?.dot_enabled ||
                    props.tlsStatus?.doq_enabled
                  )
                }
                onClick={props.onReloadTls}
                class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] cursor-pointer disabled:opacity-50"
              >
                {props.reloadingTls ? t("settingsTlsReloading") : t("settingsTlsReloadBtn")}
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsTlsCertPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/etc/crabdns/cert.pem"
                value={props.tlsCertPath}
                onInput={(e) => props.onTlsCertPathChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsTlsKeyPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/etc/crabdns/key.pem"
                value={props.tlsKeyPath}
                onInput={(e) => props.onTlsKeyPathChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>

          <Show
            when={
              props.tlsStatus &&
              (props.tlsStatus.https_enabled ||
                props.tlsStatus.dot_enabled ||
                props.tlsStatus.doq_enabled)
            }
            fallback={
              <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                {t("settingsTlsInactive")}
              </p>
            }
          >
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <div>
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsTlsFingerprint")}
                </span>
                <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed] break-all">
                  {props.tlsStatus?.cert_fingerprint_sha256 ?? "-"}
                </span>
              </div>
              <div>
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsTlsLastLoaded")}
                </span>
                <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed] break-all">
                  {props.tlsStatus?.last_loaded_at ?? "-"}
                </span>
              </div>
              <Show when={props.tlsStatus?.last_error}>
                {(err) => (
                  <div class="sm:col-span-2 text-rose-600 dark:text-rose-400 font-mono text-[11px] break-all">
                    {err()}
                  </div>
                )}
              </Show>
            </div>
          </Show>
        </div>

        {/* Web UI Authentication */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsAuthTitle")}
            </p>
            <div class="flex items-center gap-2">
              <Show when={props.authMessage}>
                <span
                  class={`text-xs font-medium ${
                    props.authIsError
                      ? "text-rose-600 dark:text-rose-400"
                      : "text-emerald-600 dark:text-emerald-400"
                  }`}
                >
                  {props.authMessage}
                </span>
              </Show>
              <button
                type="button"
                onClick={props.onSaveAuth}
                class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0"
              >
                {t("settingsAuthSave")}
              </button>
            </div>
          </div>

          <div class="flex items-center justify-between gap-4 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3">
            <span class="text-xs text-[#171717] dark:text-[#ededed]">
              {t("settingsAuthEnableLabel")}
            </span>
            <button
              type="button"
              role="switch"
              aria-checked={props.authEnabled}
              onClick={() => props.onAuthEnabledChange(!props.authEnabled)}
              class={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-0 p-0.5 transition-colors duration-200 ease-in-out ${
                props.authEnabled
                  ? "bg-[#171717] dark:bg-[#ededed]"
                  : "bg-[#d4d4d8] dark:bg-[#3f3f46]"
              }`}
            >
              <span
                class={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white dark:bg-[#0a0a0a] shadow-sm transition-transform duration-200 ease-in-out ${
                  props.authEnabled ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("authUsernameLabel")}
              </label>
              <input
                type="text"
                value={props.authUsername}
                onInput={(e) => props.onAuthUsernameChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("authNewPasswordLabel")}
              </label>
              <input
                type="password"
                value={props.authPassword}
                onInput={(e) => props.onAuthPasswordChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
        </div>

        {/* System Backup & Restore */}
        <Show when={props.onExportBackup || props.onImportBackup}>
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="space-y-1">
                <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t("backupTitle")}
                </p>
                <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
                  {t("backupSubtitle")}
                </p>
              </div>

              <div class="flex flex-wrap items-center gap-2 shrink-0">
                <Show when={props.backupMessage}>
                  <span
                    class={`text-xs font-medium ${
                      props.backupIsError
                        ? "text-rose-600 dark:text-rose-400"
                        : "text-emerald-600 dark:text-emerald-400"
                    }`}
                  >
                    {props.backupMessage}
                  </span>
                </Show>

                <Show when={props.onExportBackup}>
                  <button
                    type="button"
                    disabled={props.backupBusy}
                    onClick={() => props.onExportBackup?.()}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
                  >
                    <span class="i-ri-download-cloud-2-line text-sm" />
                    <span>{t("backupExportBtn")}</span>
                  </button>
                </Show>

                <Show when={props.onImportBackup}>
                  <label
                    class={`h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 border-0 transition-colors ${
                      props.backupBusy ? "opacity-50 pointer-events-none" : "cursor-pointer"
                    }`}
                  >
                    <input
                      type="file"
                      accept="application/json,.json"
                      disabled={props.backupBusy}
                      class="hidden"
                      onChange={(e) => {
                        const file = e.currentTarget.files?.[0];
                        if (file) {
                          void props.onImportBackup?.(file);
                          e.currentTarget.value = "";
                        }
                      }}
                    />
                    <span class="i-ri-upload-cloud-2-line text-sm" />
                    <span>{t("backupImportBtn")}</span>
                  </label>
                </Show>
              </div>
            </div>
          </div>
        </Show>

        {/* System Self-Update (SigilUp) */}
        <Show when={props.onCheckUpdate || props.onApplyUpdate}>
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="space-y-1">
                <div class="flex flex-wrap items-center gap-2">
                  <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                    {t("updateTitle")}
                  </p>
                  <Show when={props.updateStatus}>
                    {(st) => (
                      <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border border-zinc-500/20">
                        {t("updateCurrentVersion")}: v{st().current_version}
                      </span>
                    )}
                  </Show>
                  <Show
                    when={
                      props.updateStatus?.update_available && props.updateStatus?.latest_version
                    }
                  >
                    <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                      {t("updateLatestVersion")}: v{props.updateStatus?.latest_version}
                    </span>
                  </Show>
                  <Show when={props.updateStatus?.restart_pending}>
                    <span class="px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                      {t("updateRestartPendingBadge")}
                    </span>
                  </Show>
                </div>
                <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
                  {t("updateSubtitle")}
                </p>
              </div>

              <div class="flex flex-wrap items-center gap-2 shrink-0">
                <Show when={props.updateMessage}>
                  <span
                    class={`text-xs font-medium ${
                      props.updateIsError
                        ? "text-rose-600 dark:text-rose-400"
                        : "text-emerald-600 dark:text-emerald-400"
                    }`}
                  >
                    {props.updateMessage}
                  </span>
                </Show>

                <Show when={props.onCheckUpdate}>
                  <button
                    type="button"
                    disabled={props.updateBusy || props.updateStatus?.busy}
                    onClick={() => props.onCheckUpdate?.()}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
                  >
                    <span
                      class={
                        props.updateBusy
                          ? "i-ri-loader-4-line animate-spin text-sm"
                          : "i-ri-refresh-line text-sm"
                      }
                    />
                    <span>{props.updateBusy ? t("updateCheckingBtn") : t("updateCheckBtn")}</span>
                  </button>
                </Show>

                <Show
                  when={
                    props.onApplyUpdate &&
                    props.updateStatus?.update_available &&
                    !props.updateStatus?.restart_pending
                  }
                >
                  <button
                    type="button"
                    disabled={props.updateBusy || props.updateStatus?.busy}
                    onClick={() => props.onApplyUpdate?.()}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer border-0 transition-colors disabled:opacity-50"
                  >
                    <span class="i-ri-sparkling-2-line text-sm" />
                    <span>{props.updateBusy ? t("updateApplyingBtn") : t("updateApplyBtn")}</span>
                  </button>
                </Show>
              </div>
            </div>

            <Show when={props.updateStatus?.notes}>
              {(notes) => (
                <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 font-mono text-xs text-[#171717] dark:text-[#ededed] whitespace-pre-wrap">
                  {notes()}
                </div>
              )}
            </Show>
          </div>
        </Show>
      </div>

      {/* Readonly Startup Bindings */}
      <Show when={props.configData}>
        {(cfg) => (
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-2.5">
            <p class="text-xs font-medium text-[#666666] dark:text-[#a1a1aa]">
              {t("settingsReadonlyTitle")}
            </p>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 text-xs">
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDnsListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_dns}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsWebListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_web}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsWebTlsListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_web_tls ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDotListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_dot ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDoqListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_doq ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDataDir")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().data_dir}
                </span>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
