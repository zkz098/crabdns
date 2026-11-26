import { For, Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { AcmeChallengeType } from "../types/AcmeChallengeType";
import type { AcmeStatusResponse } from "../types/AcmeStatusResponse";
import type { BlockMode } from "../types/BlockMode";
import type { CfCdnStatus } from "../types/CfCdnStatus";
import type { ConfigResponse } from "../types/ConfigResponse";
import type { ConfigSnapshotMeta } from "../types/ConfigSnapshotMeta";
import type { SafeSearchConfig } from "../types/SafeSearchConfig";
import type { TlsStatusResponse } from "../types/TlsStatusResponse";
import type { UpdateStatusResponse } from "../types/UpdateStatusResponse";
import type { UpstreamCapabilities } from "../types/UpstreamCapabilities";
import type { UpstreamStatus } from "../types/UpstreamStatus";
import type { UpstreamStrategy } from "../types/UpstreamStrategy";
import { InfoTooltip } from "./InfoTooltip";
import { PortPrecheckPanel } from "./PortPrecheckPanel";
import { SetupGuideCard } from "./SetupGuideCard";
import { SplitDnsList } from "./SplitDnsList";
import { UpstreamList } from "./UpstreamList";
import type { SplitDnsRule } from "../types/SplitDnsRule";
import type { UpdateAction } from "./types";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

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
  splitDnsRules: SplitDnsRule[];
  onSplitDnsChange: (val: SplitDnsRule[]) => void;
  refreshingSplitDns?: boolean;
  onRefreshSplitDns?: () => Promise<void> | void;
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
  dhcpLeasesForwardEnabled: boolean;
  onDhcpLeasesForwardEnabledChange: (val: boolean) => void;
  dhcpLeasesDomain: string;
  onDhcpLeasesDomainChange: (val: string) => void;
  mdnsEnabled: boolean;
  onMdnsEnabledChange: (val: boolean) => void;
  sniClientIdHostnamesText: string;
  onSniClientIdHostnamesChange: (val: string) => void;
  privatePtrEnabled: boolean;
  onPrivatePtrEnabledChange: (val: boolean) => void;
  privatePtrUpstreamsText: string;
  onPrivatePtrUpstreamsChange: (val: string) => void;
  blockLocalDomains: boolean;
  onBlockLocalDomainsChange: (val: boolean) => void;
  suppressLocalDomainLogs: boolean;
  onSuppressLocalDomainLogsChange: (val: boolean) => void;
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
  safesearch: SafeSearchConfig;
  onSafesearchChange: (val: SafeSearchConfig) => void;
  dns64Enabled: boolean;
  onDns64EnabledChange: (val: boolean) => void;
  dns64PrefixesText: string;
  onDns64PrefixesChange: (val: string) => void;
  svcbStripEch: boolean;
  onSvcbStripEchChange: (val: boolean) => void;
  svcbStripHints: boolean;
  onSvcbStripHintsChange: (val: boolean) => void;
  cfCdnEnabled: boolean;
  onCfCdnEnabledChange: (val: boolean) => void;
  cfCdnIpv6Enabled: boolean;
  onCfCdnIpv6EnabledChange: (val: boolean) => void;
  cfCdnIntervalSecs: number;
  onCfCdnIntervalSecsChange: (val: number) => void;
  cfCdnTtlSecs: number;
  onCfCdnTtlSecsChange: (val: number) => void;
  cfCdnSpeedtestUrl: string;
  onCfCdnSpeedtestUrlChange: (val: string) => void;
  cfCdnExcludedDomainsText: string;
  onCfCdnExcludedDomainsChange: (val: string) => void;
  cfCdnStatus: CfCdnStatus | null;
  onRunCfCdnSpeedtest: () => void;
  tlsCertPath: string;
  onTlsCertPathChange: (val: string) => void;
  tlsKeyPath: string;
  onTlsKeyPathChange: (val: string) => void;
  tlsStatus: TlsStatusResponse | null;
  reloadingTls: boolean;
  tlsMessage: string;
  tlsIsError: boolean;
  onReloadTls: () => void;
  acmeEnabled: boolean;
  onAcmeEnabledChange: (val: boolean) => void;
  acmeDomainsText: string;
  onAcmeDomainsChange: (val: string) => void;
  acmeEmail: string;
  onAcmeEmailChange: (val: string) => void;
  acmeDirectoryUrl: string;
  onAcmeDirectoryUrlChange: (val: string) => void;
  acmeChallengeType: AcmeChallengeType;
  onAcmeChallengeTypeChange: (val: AcmeChallengeType) => void;
  acmeHttpListen: string;
  onAcmeHttpListenChange: (val: string) => void;
  acmeRenewBeforeDays: number;
  onAcmeRenewBeforeDaysChange: (val: number) => void;
  acmeStatus: AcmeStatusResponse | null;
  issuingAcme: boolean;
  acmeMessage: string;
  acmeIsError: boolean;
  onIssueAcme: () => void;
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
  configHistory?: ConfigSnapshotMeta[];
  rollbackBusy?: boolean;
  onRefreshHistory?: () => Promise<void> | void;
  onRollbackConfig?: (id: string) => Promise<void> | void;
  updateStatus?: UpdateStatusResponse | null;
  updateAction?: UpdateAction;
  updateMessage?: string;
  updateIsError?: boolean;
  onCheckUpdate?: () => Promise<void> | void;
  onApplyUpdate?: () => Promise<void> | void;
  onRestartService?: () => Promise<void> | void;
}

export function SettingsView(props: SettingsViewProps) {
  const [advancedOpen, setAdvancedOpen] = createSignal(false);

  const updatePhase = () => props.updateStatus?.phase ?? "idle";
  const isCheckingUpdate = () =>
    props.updateAction === "check" || (props.updateAction === null && updatePhase() === "checking");
  const isApplyingUpdate = () =>
    props.updateAction === "apply" ||
    updatePhase() === "downloading" ||
    updatePhase() === "installing";
  const isRestartingService = () => props.updateAction === "restart";
  const isUpdateBusy = () =>
    (props.updateAction ?? null) !== null || Boolean(props.updateStatus?.busy);

  const updateTotalBytes = () =>
    props.updateStatus?.total_bytes ?? props.updateStatus?.asset_size ?? null;
  const updateDownloadedBytes = () => props.updateStatus?.downloaded_bytes ?? 0;
  const updateProgressPercent = (): number | null => {
    if (updatePhase() === "installing") return 100;
    const total = updateTotalBytes();
    if (total !== null && total > 0) {
      return Math.min(100, Math.round((updateDownloadedBytes() / total) * 100));
    }
    return null;
  };
  const updatePhaseLabel = () => {
    const phase = updatePhase();
    if (phase === "installing") return t("updatePhaseInstalling");
    if (phase === "downloading") return t("updatePhaseDownloading");
    return t("updatePhasePreparing");
  };

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
        <UpstreamList
          upstreamsText={props.upstreamsText}
          onUpstreamsChange={props.onUpstreamsChange}
          upstreamHealth={props.upstreamHealth}
          probingUpstreams={props.probingUpstreams}
          onProbeUpstreams={props.onProbeUpstreams}
          upstreamCapabilities={props.upstreamCapabilities}
          probingCapabilities={props.probingCapabilities}
          probeCapabilitiesError={props.probeCapabilitiesError}
          onProbeCapabilities={props.onProbeCapabilities}
          onReplaceUpstream={props.onReplaceUpstream}
          dnssecEnabled={props.dnssecEnabled}
          ecsEnabled={props.ecsEnabled}
        />

        {/* Upstream Strategy & Block Response Mode */}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsStrategyLabel")}</span>
              <InfoTooltip text={t("tooltipStrategy")} align="left" />
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
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsBlockModeLabel")}</span>
              <InfoTooltip text={t("tooltipBlockMode")} />
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

        {/* Basic Cache, Timeout & Log Retention */}
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsCacheSizeLabel")}</span>
              <InfoTooltip text={t("tooltipCacheSize")} align="left" />
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
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsTimeoutLabel")}</span>
              <InfoTooltip text={t("tooltipTimeout")} />
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
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsRetentionLabel")}</span>
              <InfoTooltip text={t("tooltipRetention")} align="right" />
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

        {/* Collapsible Advanced Settings */}
        <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa]/60 dark:bg-[#050505]">
          <button
            type="button"
            aria-expanded={advancedOpen()}
            onClick={() => setAdvancedOpen((prev) => !prev)}
            class="w-full flex items-center justify-between gap-3 px-4 py-3.5 text-left cursor-pointer bg-transparent border-0 rounded-xl hover:bg-[#f4f4f5]/70 dark:hover:bg-[#111111]/70 transition-colors"
          >
            <div class="flex items-start sm:items-center gap-2.5 min-w-0">
              <span class="i-ri-equalizer-line text-base text-[#666666] dark:text-[#a1a1aa] shrink-0 mt-0.5 sm:mt-0" />
              <div class="min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="text-xs font-semibold text-[#171717] dark:text-[#ededed]">
                    {t("settingsAdvancedTitle")}
                  </span>
                  <span class="px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-[#666666] dark:text-[#a1a1aa] border border-zinc-500/15">
                    {advancedOpen() ? t("settingsAdvancedCollapse") : t("settingsAdvancedExpand")}
                  </span>
                </div>
                <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-0.5 truncate sm:whitespace-normal">
                  {t("settingsAdvancedSummary")}
                </p>
              </div>
            </div>
            <span
              class={`i-ri-arrow-down-s-line text-lg text-[#666666] dark:text-[#a1a1aa] shrink-0 transition-transform duration-200 ${
                advancedOpen() ? "rotate-180" : ""
              }`}
            />
          </button>

          <Show when={advancedOpen()}>
            <div class="border-t border-[#eaeaea] dark:border-[#262626] p-4 sm:p-5 space-y-6">
              {/* Bootstrap DNS & Cache Tuning */}
              <div class="space-y-4">
                <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t("settingsAdvancedCacheTitle")}
                </p>

                <div>
                  <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
                    <span>{t("settingsBootstrapDnsLabel")}</span>
                    <InfoTooltip text={t("tooltipBootstrapDns")} align="left" />
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

                {/* Custom Vercel-style Toggle Switch */}
                <div class="flex items-center justify-between gap-4 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5">
                  <span class="inline-flex items-center gap-1.5 text-sm text-[#171717] dark:text-[#ededed] leading-snug">
                    <span>{t("settingsOptimisticLabel")}</span>
                    <InfoTooltip text={t("tooltipOptimisticCache")} />
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
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsCacheMinTtlLabel")}</span>
                      <InfoTooltip text={t("tooltipCacheMinTtl")} align="left" />
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
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsCacheMaxTtlLabel")}</span>
                      <InfoTooltip text={t("tooltipCacheMaxTtl")} />
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
                    <span>{t("settingsCachePrefetchLabel")}</span>
                    <InfoTooltip text={t("tooltipCachePrefetch")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.cachePersistEnabled}
                      onChange={(e) => props.onCachePersistChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsCachePersistLabel")}</span>
                    <InfoTooltip text={t("tooltipCachePersist")} />
                  </label>
                </div>
              </div>

              {/* Split DNS & Feature Toggles */}
              <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-4">
                <SplitDnsList
                  rules={props.splitDnsRules}
                  onChange={props.onSplitDnsChange}
                  refreshing={props.refreshingSplitDns}
                  onRefresh={props.onRefreshSplitDns}
                />

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.cnameCloakingBlocking}
                      onChange={(e) => props.onCnameCloakingChange(e.currentTarget.checked)}
                    />
                    <span>{t("settingsCnameCloakingLabel")}</span>
                    <InfoTooltip text={t("tooltipCnameCloaking")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dohEnabled}
                      onChange={(e) => props.onDohEnabledChange(e.currentTarget.checked)}
                    />
                    <span>{t("settingsDohEnabledLabel")}</span>
                    <InfoTooltip text={t("tooltipDohEnabled")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.allowPrivateSubscriptions}
                      onChange={(e) =>
                        props.onAllowPrivateSubscriptionsChange(e.currentTarget.checked)
                      }
                    />
                    <span>{t("settingsAllowPrivateSubsLabel")}</span>
                    <InfoTooltip text={t("tooltipAllowPrivateSubs")} align="right" />
                  </label>
                </div>
              </div>

              {/* DNS Client ACL & Rate Limiting */}
              <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
                <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t("settingsAclTitle")}
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsAllowCidrsLabel")}</span>
                      <InfoTooltip text={t("tooltipAllowCidrs")} align="left" />
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
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsDenyCidrsLabel")}</span>
                      <InfoTooltip text={t("tooltipDenyCidrs")} />
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
                  <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                    <span>{t("settingsRateLimitLabel")}</span>
                    <InfoTooltip text={t("tooltipRateLimit")} align="left" />
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
                    <span>{t("settingsEcsLabel")}</span>
                    <InfoTooltip text={t("tooltipEcs")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dnssecEnabled}
                      onChange={(e) => props.onDnssecEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDnssecLabel")}</span>
                    <InfoTooltip text={t("tooltipDnssec")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dnsRebindingProtection}
                      onChange={(e) =>
                        props.onDnsRebindingProtectionChange(e.currentTarget.checked)
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDnsRebindingLabel")}</span>
                    <InfoTooltip text={t("tooltipDnsRebinding")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.blockAnyQueries}
                      onChange={(e) => props.onBlockAnyQueriesChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsBlockAnyLabel")}</span>
                    <InfoTooltip text={t("tooltipBlockAny")} />
                  </label>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsEcsCustomIpLabel")}</span>
                      <InfoTooltip text={t("tooltipEcsCustomIp")} align="left" />
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
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsEcsV4PrefixLabel")}</span>
                      <InfoTooltip text={t("tooltipEcsV4Prefix")} />
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
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsEcsV6PrefixLabel")}</span>
                      <InfoTooltip text={t("tooltipEcsV6Prefix")} align="right" />
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
                  <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                    <span>{t("settingsTrustedProxiesLabel")}</span>
                    <InfoTooltip text={t("tooltipTrustedProxies")} align="left" />
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
                    <span>{t("settingsHostsLabel")}</span>
                    <InfoTooltip text={t("tooltipHosts")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dhcpLeasesEnabled}
                      onChange={(e) => props.onDhcpLeasesEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDhcpLeasesLabel")}</span>
                    <InfoTooltip text={t("tooltipDhcpLeases")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dhcpLeasesForwardEnabled}
                      onChange={(e) =>
                        props.onDhcpLeasesForwardEnabledChange(e.currentTarget.checked)
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDhcpLeasesForwardLabel")}</span>
                    <InfoTooltip text={t("tooltipDhcpLeasesForward")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.mdnsEnabled}
                      onChange={(e) => props.onMdnsEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsMdnsLabel")}</span>
                    <InfoTooltip text={t("tooltipMdns")} align="right" />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.privatePtrEnabled}
                      onChange={(e) => props.onPrivatePtrEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsPrivatePtrLabel")}</span>
                    <InfoTooltip text={t("tooltipPrivatePtr")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.blockLocalDomains}
                      onChange={(e) => props.onBlockLocalDomainsChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsBlockLocalDomainsLabel")}</span>
                    <InfoTooltip text={t("tooltipBlockLocalDomains")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.suppressLocalDomainLogs}
                      onChange={(e) =>
                        props.onSuppressLocalDomainLogsChange(e.currentTarget.checked)
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsSuppressLocalDomainLogsLabel")}</span>
                    <InfoTooltip text={t("tooltipSuppressLocalDomainLogs")} align="right" />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.ddrEnabled}
                      onChange={(e) => props.onDdrEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDdrLabel")}</span>
                    <InfoTooltip text={t("tooltipDdr")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.rdnsEnabled}
                      onChange={(e) => props.onRdnsEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsRdnsLabel")}</span>
                    <InfoTooltip text={t("tooltipRdns")} align="right" />
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
                      {t("settingsDhcpLeasesDomainLabel")}
                    </label>
                    <input
                      type="text"
                      placeholder="lan"
                      value={props.dhcpLeasesDomain}
                      onInput={(e) => props.onDhcpLeasesDomainChange(e.currentTarget.value)}
                      class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsDdrHostnameLabel")}</span>
                      <InfoTooltip text={t("tooltipDdrHostname")} align="right" />
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
                  <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                    <span>{t("settingsSniHostnamesLabel")}</span>
                    <InfoTooltip text={t("tooltipSniHostnames")} align="left" />
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
                  <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                    <span>{t("settingsPrivatePtrUpstreamsLabel")}</span>
                    <InfoTooltip text={t("tooltipPrivatePtrUpstreams")} align="left" />
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

              {/* SafeSearch, DNS64 & HTTPS/SVCB Sanitization */}
              <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-4">
                <p class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  <span>{t("settingsSafeSearchTitle")}</span>
                  <InfoTooltip text={t("tooltipSafeSearch")} align="left" />
                </p>
                <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">
                  {t("settingsSafeSearchDesc")}
                </p>
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <label class="flex items-center gap-2 text-xs font-medium text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.enabled}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          enabled: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    {t("settingsSafeSearchEnabled")}
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.google}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          google: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    Google
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.bing}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          bing: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    Bing
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.youtube}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          youtube: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    YouTube
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.youtube_strict}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          youtube_strict: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    {t("settingsSafeSearchYoutubeStrict")}
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.duckduckgo}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          duckduckgo: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    DuckDuckGo
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.yandex}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          yandex: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    Yandex
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.pixabay}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          pixabay: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    Pixabay
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.safesearch.brave}
                      onChange={(e) =>
                        props.onSafesearchChange({
                          ...props.safesearch,
                          brave: e.currentTarget.checked,
                        })
                      }
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    Brave
                  </label>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.dns64Enabled}
                      onChange={(e) => props.onDns64EnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsDns64Label")}</span>
                    <InfoTooltip text={t("tooltipDns64")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.svcbStripEch}
                      onChange={(e) => props.onSvcbStripEchChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsSvcbStripEchLabel")}</span>
                    <InfoTooltip text={t("tooltipSvcbStripEch")} />
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.svcbStripHints}
                      onChange={(e) => props.onSvcbStripHintsChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsSvcbStripHintsLabel")}</span>
                    <InfoTooltip text={t("tooltipSvcbStripHints")} align="right" />
                  </label>
                </div>

                <Show when={props.dns64Enabled}>
                  <div>
                    <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      <span>{t("settingsDns64PrefixesLabel")}</span>
                      <InfoTooltip text={t("tooltipDns64Prefixes")} align="left" />
                    </label>
                    <textarea
                      rows={2}
                      spellcheck={false}
                      placeholder="64:ff9b::/96"
                      value={props.dns64PrefixesText}
                      onInput={(e) => props.onDns64PrefixesChange(e.currentTarget.value)}
                      class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                </Show>
              </div>

              {/* Cloudflare CDN Active Acceleration */}
              <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <p class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
                      <span>{t("settingsCfCdnTitle")}</span>
                      <InfoTooltip text={t("tooltipCfCdn")} align="left" />
                    </p>
                    <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] mt-0.5">
                      {t("settingsCfCdnDesc")}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={props.cfCdnStatus?.testing}
                    onClick={() => props.onRunCfCdnSpeedtest()}
                    class="px-3 py-1.5 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#000000] hover:bg-[#f0f0f0] dark:hover:bg-[#111111] text-xs font-medium text-[#171717] dark:text-[#ededed] disabled:opacity-50 shrink-0 cursor-pointer"
                  >
                    {props.cfCdnStatus?.testing
                      ? t("settingsCfCdnTesting")
                      : t("settingsCfCdnRunTest")}
                  </button>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.cfCdnEnabled}
                      onChange={(e) => props.onCfCdnEnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsCfCdnEnabled")}</span>
                  </label>
                  <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={props.cfCdnIpv6Enabled}
                      onChange={(e) => props.onCfCdnIpv6EnabledChange(e.currentTarget.checked)}
                      class="rounded border-[#eaeaea] dark:border-[#262626]"
                    />
                    <span>{t("settingsCfCdnIpv6Enabled")}</span>
                  </label>
                </div>

                {/* Live status summary */}
                <Show when={props.cfCdnStatus}>
                  {(st) => (
                    <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#000000] p-3 space-y-2 text-xs">
                      <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <div>
                          <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                            {t("settingsCfCdnBestIpv4")}
                          </div>
                          <div class="font-mono font-medium text-[#171717] dark:text-[#ededed] mt-0.5">
                            {st().best_ipv4 ?? "—"}
                            <Show when={st().best_ipv4_latency_ms !== null}>
                              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] ml-1.5">
                                ({st().best_ipv4_latency_ms?.toFixed(1)} ms
                                <Show when={st().best_ipv4_throughput_mbps !== null}>
                                  {` · ${st().best_ipv4_throughput_mbps?.toFixed(2)} MB/s`}
                                </Show>
                                )
                              </span>
                            </Show>
                          </div>
                        </div>
                        <div>
                          <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                            {t("settingsCfCdnBestIpv6")}
                          </div>
                          <div class="font-mono font-medium text-[#171717] dark:text-[#ededed] mt-0.5 break-all">
                            {st().best_ipv6 ?? "—"}
                            <Show when={st().best_ipv6_latency_ms !== null}>
                              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] ml-1.5">
                                ({st().best_ipv6_latency_ms?.toFixed(1)} ms
                                <Show when={st().best_ipv6_throughput_mbps !== null}>
                                  {` · ${st().best_ipv6_throughput_mbps?.toFixed(2)} MB/s`}
                                </Show>
                                )
                              </span>
                            </Show>
                          </div>
                        </div>
                        <div>
                          <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                            {t("settingsCfCdnLastRun")}
                          </div>
                          <div class="text-[#171717] dark:text-[#ededed] mt-0.5">
                            {st().last_run_unix_ms
                              ? new Date(st().last_run_unix_ms!).toLocaleString()
                              : t("settingsCfCdnNotTested")}
                          </div>
                        </div>
                      </div>
                      <Show when={st().last_error}>
                        <div class="text-[11px] text-amber-600 dark:text-amber-400">
                          {st().last_error}
                        </div>
                      </Show>
                      <Show when={st().candidates_v4.length > 0 || st().candidates_v6.length > 0}>
                        <details class="pt-1">
                          <summary class="cursor-pointer text-[11px] text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed]">
                            {t("settingsCfCdnCandidatesTitle")} (IPv4: {st().candidates_v4.length},
                            IPv6: {st().candidates_v6.length})
                          </summary>
                          <div class="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
                            <For each={[...st().candidates_v4, ...st().candidates_v6]}>
                              {(node) => (
                                <div class="flex items-center justify-between gap-2 px-2 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a]">
                                  <span class="truncate">{node.ip}</span>
                                  <span class="text-[#666666] dark:text-[#a1a1aa] shrink-0">
                                    {node.latency_ms.toFixed(1)} ms
                                    {node.throughput_mbps !== null
                                      ? ` · ${node.throughput_mbps.toFixed(2)} MB/s`
                                      : ""}
                                  </span>
                                </div>
                              )}
                            </For>
                          </div>
                        </details>
                      </Show>
                    </div>
                  )}
                </Show>

                <Show when={props.cfCdnEnabled}>
                  <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                    <div>
                      <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                        {t("settingsCfCdnIntervalLabel")}
                      </label>
                      <input
                        type="number"
                        min={60}
                        value={props.cfCdnIntervalSecs}
                        onInput={(e) =>
                          props.onCfCdnIntervalSecsChange(Number(e.currentTarget.value) || 1800)
                        }
                        class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 py-1.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                      />
                    </div>
                    <div>
                      <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                        {t("settingsCfCdnTtlLabel")}
                      </label>
                      <input
                        type="number"
                        min={1}
                        value={props.cfCdnTtlSecs}
                        onInput={(e) =>
                          props.onCfCdnTtlSecsChange(Number(e.currentTarget.value) || 60)
                        }
                        class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 py-1.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                      />
                    </div>
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsCfCdnSpeedtestUrlLabel")}
                    </label>
                    <input
                      type="text"
                      spellcheck={false}
                      value={props.cfCdnSpeedtestUrl}
                      onInput={(e) => props.onCfCdnSpeedtestUrlChange(e.currentTarget.value)}
                      class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 py-1.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsCfCdnExcludedLabel")}
                    </label>
                    <textarea
                      rows={2}
                      spellcheck={false}
                      placeholder="workers.dev"
                      value={props.cfCdnExcludedDomainsText}
                      onInput={(e) => props.onCfCdnExcludedDomainsChange(e.currentTarget.value)}
                      class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                </Show>
              </div>

              {/* Native TLS & Certificate Hot Reload */}
              <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <p class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
                    <span>{t("settingsTlsTitle")}</span>
                    <InfoTooltip text={t("tooltipTls")} align="left" />
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
                          props.tlsStatus?.doq_enabled ||
                          props.tlsStatus?.doh3_enabled
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
                      props.tlsStatus.doq_enabled ||
                      props.tlsStatus.doh3_enabled)
                  }
                  fallback={
                    <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                      {t("settingsTlsInactive")}
                    </p>
                  }
                >
                  <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
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

              <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
                <div class="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                      {t("settingsAcmeTitle")}
                    </div>
                    <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                      {t("settingsAcmeDesc")}
                    </p>
                  </div>
                  <div class="flex items-center gap-2">
                    <Show when={props.acmeMessage}>
                      <span
                        class={`text-[11px] font-medium ${
                          props.acmeIsError
                            ? "text-rose-600 dark:text-rose-400"
                            : "text-emerald-600 dark:text-emerald-400"
                        }`}
                      >
                        {props.acmeMessage}
                      </span>
                    </Show>
                    <button
                      type="button"
                      disabled={props.issuingAcme || !props.acmeDomainsText.trim()}
                      onClick={props.onIssueAcme}
                      class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] cursor-pointer disabled:opacity-50"
                    >
                      {props.issuingAcme ? t("settingsAcmeIssuing") : t("settingsAcmeIssueBtn")}
                    </button>
                  </div>
                </div>

                <label class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={props.acmeEnabled}
                    onChange={(e) => props.onAcmeEnabledChange(e.currentTarget.checked)}
                    class="rounded border-[#d4d4d8] dark:border-[#3f3f46]"
                  />
                  <span>{t("settingsAcmeEnabled")}</span>
                </label>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div class="sm:col-span-2">
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsAcmeDomainsLabel")}
                    </label>
                    <input
                      type="text"
                      placeholder="dns.example.com"
                      value={props.acmeDomainsText}
                      onInput={(e) => props.onAcmeDomainsChange(e.currentTarget.value)}
                      class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsAcmeEmailLabel")}
                    </label>
                    <input
                      type="email"
                      placeholder="admin@example.com"
                      value={props.acmeEmail}
                      onInput={(e) => props.onAcmeEmailChange(e.currentTarget.value)}
                      class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsAcmeChallengeLabel")}
                    </label>
                    <select
                      value={props.acmeChallengeType}
                      onChange={(e) =>
                        props.onAcmeChallengeTypeChange(e.currentTarget.value as AcmeChallengeType)
                      }
                      class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    >
                      <option value="http01">{t("settingsAcmeChallengeHttp01")}</option>
                      <option value="dns01_local">{t("settingsAcmeChallengeDns01")}</option>
                    </select>
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("settingsAcmeDirectoryLabel")}
                    </label>
                    <input
                      type="text"
                      value={props.acmeDirectoryUrl}
                      onInput={(e) => props.onAcmeDirectoryUrlChange(e.currentTarget.value)}
                      class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div class="grid grid-cols-2 gap-2">
                    <div>
                      <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                        {t("settingsAcmeHttpListenLabel")}
                      </label>
                      <input
                        type="text"
                        placeholder="0.0.0.0:80"
                        value={props.acmeHttpListen}
                        onInput={(e) => props.onAcmeHttpListenChange(e.currentTarget.value)}
                        class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                      />
                    </div>
                    <div>
                      <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                        {t("settingsAcmeRenewDaysLabel")}
                      </label>
                      <input
                        type="number"
                        min={1}
                        max={89}
                        value={props.acmeRenewBeforeDays}
                        onInput={(e) =>
                          props.onAcmeRenewBeforeDaysChange(Number(e.currentTarget.value) || 30)
                        }
                        class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                      />
                    </div>
                  </div>
                </div>

                <Show when={props.acmeStatus?.cert_exists || props.acmeStatus?.last_error}>
                  <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-2.5 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    <div>
                      <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                        {t("settingsAcmeExpires")}
                      </span>
                      <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                        {props.acmeStatus?.cert_expires_at ?? "-"}
                      </span>
                    </div>
                    <div>
                      <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                        {t("settingsAcmeDaysRemaining")}
                      </span>
                      <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                        {props.acmeStatus?.days_remaining !== null &&
                        props.acmeStatus?.days_remaining !== undefined
                          ? String(props.acmeStatus.days_remaining)
                          : "-"}
                      </span>
                    </div>
                    <Show when={props.acmeStatus?.last_error}>
                      {(err) => (
                        <div class="sm:col-span-2 text-rose-600 dark:text-rose-400 font-mono text-[11px] break-all">
                          {err()}
                        </div>
                      )}
                    </Show>
                  </div>
                </Show>
              </div>
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
              <div class="min-w-0 flex-1 space-y-1">
                <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t("backupTitle")}
                </p>
                <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
                  {t("backupSubtitle")}
                </p>
              </div>

              <div class="flex flex-wrap items-center gap-2 shrink-0">
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

            <Show when={props.backupMessage}>
              <div
                class={`rounded-lg border px-3 py-2 text-xs font-medium flex items-start gap-2 break-all ${
                  props.backupIsError
                    ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                    : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                }`}
              >
                <span
                  class={`${
                    props.backupIsError ? "i-ri-error-warning-line" : "i-ri-check-line"
                  } text-sm shrink-0 mt-0.5`}
                />
                <span class="min-w-0">{props.backupMessage}</span>
              </div>
            </Show>
          </div>
        </Show>

        {/* Configuration History & Rollback */}
        <Show when={props.onRollbackConfig}>
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="min-w-0 flex-1 space-y-1">
                <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t("configHistoryTitle")}
                </p>
                <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                  {t("configHistorySubtitle")}
                </p>
              </div>
              <Show when={props.onRefreshHistory}>
                <button
                  type="button"
                  disabled={props.rollbackBusy}
                  onClick={() => props.onRefreshHistory?.()}
                  class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50 shrink-0"
                >
                  <span class="i-ri-refresh-line text-sm" />
                </button>
              </Show>
            </div>
            <Show
              when={(props.configHistory?.length ?? 0) > 0}
              fallback={
                <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                  {t("configHistoryEmpty")}
                </p>
              }
            >
              <div class="max-h-52 overflow-y-auto divide-y divide-[#eaeaea] dark:divide-[#262626] border border-[#eaeaea] dark:border-[#262626] rounded-lg bg-[#fafafa] dark:bg-[#050505]">
                <For each={props.configHistory ?? []}>
                  {(snap) => (
                    <div class="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2 font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                          <span>{new Date(Number(snap.created_at) * 1000).toLocaleString()}</span>
                          <span class="px-1.5 py-0.5 rounded bg-[#eaeaea] dark:bg-[#1f1f1f] text-[10px]">
                            {snap.reason}
                          </span>
                        </div>
                        <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa] truncate">
                          {snap.listen_dns} · {snap.upstreams_count} upstreams ·{" "}
                          {snap.split_dns_count} split rules
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={props.rollbackBusy}
                        onClick={() => props.onRollbackConfig?.(snap.id)}
                        class="h-7 px-2.5 rounded-md text-[11px] font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] cursor-pointer transition-colors disabled:opacity-50 shrink-0"
                      >
                        {t("configHistoryRollbackBtn")}
                      </button>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </Show>

        {/* System Self-Update (SigilUp) */}
        <Show when={props.onCheckUpdate || props.onApplyUpdate}>
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div class="min-w-0 flex-1 space-y-1">
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
                <Show when={props.onCheckUpdate}>
                  <button
                    type="button"
                    disabled={isUpdateBusy()}
                    onClick={() => props.onCheckUpdate?.()}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
                  >
                    <span
                      class={
                        isCheckingUpdate()
                          ? "i-ri-loader-4-line animate-spin text-sm"
                          : "i-ri-refresh-line text-sm"
                      }
                    />
                    <span>{isCheckingUpdate() ? t("updateCheckingBtn") : t("updateCheckBtn")}</span>
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
                    disabled={isUpdateBusy()}
                    onClick={() => props.onApplyUpdate?.()}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer border-0 transition-colors disabled:opacity-50"
                  >
                    <span
                      class={
                        isApplyingUpdate()
                          ? "i-ri-loader-4-line animate-spin text-sm"
                          : "i-ri-sparkling-2-line text-sm"
                      }
                    />
                    <span>{isApplyingUpdate() ? t("updateApplyingBtn") : t("updateApplyBtn")}</span>
                  </button>
                </Show>

                <Show when={props.onRestartService}>
                  <button
                    type="button"
                    disabled={isUpdateBusy()}
                    onClick={() => props.onRestartService?.()}
                    class={`h-8 px-3 rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50 ${
                      props.updateStatus?.restart_pending
                        ? "bg-amber-600 hover:bg-amber-700 text-white border-0"
                        : "bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626]"
                    }`}
                  >
                    <span
                      class={
                        isRestartingService()
                          ? "i-ri-loader-4-line animate-spin text-sm"
                          : "i-ri-restart-line text-sm"
                      }
                    />
                    <span>
                      {isRestartingService() ? t("updateRestartingBtn") : t("updateRestartBtn")}
                    </span>
                  </button>
                </Show>
              </div>
            </div>

            <Show when={isApplyingUpdate()}>
              <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 space-y-2">
                <div class="flex items-center justify-between gap-2 text-xs">
                  <span class="flex items-center gap-1.5 font-medium text-[#171717] dark:text-[#ededed]">
                    <span class="i-ri-loader-4-line animate-spin text-sm shrink-0" />
                    <span>{updatePhaseLabel()}</span>
                  </span>
                  <span class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {(() => {
                      const total = updateTotalBytes();
                      const done = updateDownloadedBytes();
                      const pct = updateProgressPercent();
                      if (total !== null && total > 0 && pct !== null) {
                        return `${formatBytes(done)} / ${formatBytes(total)} (${pct}%)`;
                      }
                      if (done > 0) {
                        return formatBytes(done);
                      }
                      if (pct !== null) {
                        return `${pct}%`;
                      }
                      return "";
                    })()}
                  </span>
                </div>
                <div
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={updateProgressPercent() ?? undefined}
                  class="h-2 w-full rounded-full overflow-hidden bg-[#eaeaea] dark:bg-[#262626]"
                >
                  <Show
                    when={updateProgressPercent() !== null}
                    fallback={
                      <div class="h-full w-1/3 rounded-full bg-emerald-500 animate-pulse" />
                    }
                  >
                    <div
                      class={`h-full rounded-full transition-all duration-200 ease-out ${
                        updatePhase() === "installing"
                          ? "bg-emerald-500 animate-pulse"
                          : "bg-[#171717] dark:bg-[#ededed]"
                      }`}
                      style={{ width: `${updateProgressPercent()}%` }}
                    />
                  </Show>
                </div>
              </div>
            </Show>

            <Show when={props.updateMessage}>
              <div
                class={`rounded-lg border px-3 py-2 text-xs font-medium flex items-start gap-2 break-all ${
                  props.updateIsError
                    ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                    : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                }`}
              >
                <span
                  class={`${
                    props.updateIsError ? "i-ri-error-warning-line" : "i-ri-check-line"
                  } text-sm shrink-0 mt-0.5`}
                />
                <span class="min-w-0">{props.updateMessage}</span>
              </div>
            </Show>

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
                  {t("settingsDoh3Listen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_doh3 ?? "-"}
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
            <PortPrecheckPanel
              listenDns={cfg().listen_dns}
              listenWeb={cfg().listen_web}
              listenWebTls={cfg().listen_web_tls}
              listenDot={cfg().listen_dot}
              listenDoq={cfg().listen_doq}
            />
          </div>
        )}
      </Show>

      <SetupGuideCard configData={props.configData} tlsStatus={props.tlsStatus} />
    </div>
  );
}
