import { createEffect, createMemo, createSignal, onCleanup, onMount, Show } from "solid-js";
import { ClientsView } from "./components/ClientsView";
import { DashboardView } from "./components/DashboardView";
import { DiagnosticsView } from "./components/DiagnosticsView";
import { Header } from "./components/Header";
import { LoginView } from "./components/LoginView";
import { LogsView } from "./components/LogsView";
import { MobileNav } from "./components/MobileNav";
import { RewritesView } from "./components/RewritesView";
import { RulesView } from "./components/RulesView";
import { SettingsView } from "./components/SettingsView";
import { SetupWizardView } from "./components/SetupWizardView";
import type { TabKey, UpdateAction } from "./components/types";
import { t } from "./i18n";
import type { AcmeChallengeType } from "./types/AcmeChallengeType";
import type { AcmeStatusResponse } from "./types/AcmeStatusResponse";
import type { AuthStatusResponse } from "./types/AuthStatusResponse";
import type { BlockMode } from "./types/BlockMode";
import type { BlockingStatusResponse } from "./types/BlockingStatusResponse";
import type { CfCdnStatus } from "./types/CfCdnStatus";
import type { ClientGroupPayload } from "./types/ClientGroupPayload";
import type { ClientProfilePayload } from "./types/ClientProfilePayload";
import type { ClientsOverviewResponse } from "./types/ClientsOverviewResponse";
import type { ConfigResponse } from "./types/ConfigResponse";
import type { ConfigUpdatePayload } from "./types/ConfigUpdatePayload";
import type { CreateSubscriptionPayload } from "./types/CreateSubscriptionPayload";
import type { DnsRewriteEntry } from "./types/DnsRewriteEntry";
import type { DnsRewritePayload } from "./types/DnsRewritePayload";
import type { DnssecNta } from "./types/DnssecNta";
import type { FilterSubscription } from "./types/FilterSubscription";
import type { QueryEvent } from "./types/QueryEvent";
import type { QuickRuleResponse } from "./types/QuickRuleResponse";
import type { RulesPayload } from "./types/RulesPayload";
import type { SafeSearchConfig } from "./types/SafeSearchConfig";
import type { SetupCompletePayload } from "./types/SetupCompletePayload";
import type { SetupStatusResponse } from "./types/SetupStatusResponse";
import type { SplitDnsMatchMode } from "./types/SplitDnsMatchMode";
import type { SubscriptionProgressStatus } from "./types/SubscriptionProgressStatus";
import type { SplitDnsRefreshSummary } from "./types/SplitDnsRefreshSummary";
import type { SplitDnsRule } from "./types/SplitDnsRule";
import type { SplitDnsSourceStatus } from "./types/SplitDnsSourceStatus";
import type { ConfigSnapshotMeta } from "./types/ConfigSnapshotMeta";
import type { StatsResponse } from "./types/StatsResponse";
import type { StorageProfile } from "./types/StorageProfile";
import type { TestRuleResponse } from "./types/TestRuleResponse";
import type { TlsStatusResponse } from "./types/TlsStatusResponse";
import type { UpdateStatusResponse } from "./types/UpdateStatusResponse";
import type { UpstreamCapabilities } from "./types/UpstreamCapabilities";
import type { UpstreamGroup } from "./types/UpstreamGroup";
import type { UpstreamStatus } from "./types/UpstreamStatus";
import type { UpstreamStrategy } from "./types/UpstreamStrategy";
import type { WsLogFilter } from "./types/WsLogFilter";
import type { WsTopic } from "./types/WsTopic";
import { createWsEventClient } from "./wsClient";

export default function App() {
  const [tab, setTab] = createSignal<TabKey>("dashboard");
  const [wsConnected, setWsConnected] = createSignal(false);
  const [stats, setStats] = createSignal<StatsResponse | null>(null);
  const [logs, setLogs] = createSignal<QueryEvent[]>([]);
  const [search, setSearch] = createSignal("");
  const [outcomeFilter, setOutcomeFilter] = createSignal("");
  const [protocolFilter, setProtocolFilter] = createSignal("");
  const [qtypeFilter, setQtypeFilter] = createSignal("");
  const [clientFilter, setClientFilter] = createSignal("");
  const [rulesText, setRulesText] = createSignal("");
  const [rulesEnabled, setRulesEnabled] = createSignal(true);
  const [saveMessage, setSaveMessage] = createSignal("");

  const [subscriptions, setSubscriptions] = createSignal<FilterSubscription[]>([]);
  const [subMessage, setSubMessage] = createSignal("");
  const [subIsError, setSubIsError] = createSignal(false);
  const [refreshingIds, setRefreshingIds] = createSignal<Record<string, boolean>>({});
  const [refreshingAll, setRefreshingAll] = createSignal(false);
  const [addingSub, setAddingSub] = createSignal(false);

  const [configData, setConfigData] = createSignal<ConfigResponse | null>(null);
  const [upstreamsText, setUpstreamsText] = createSignal("");
  const [bootstrapDnsText, setBootstrapDnsText] = createSignal("");
  const [upstreamStrategy, setUpstreamStrategy] = createSignal<UpstreamStrategy>("failover");
  const [upstreamHealth, setUpstreamHealth] = createSignal<UpstreamStatus[]>([]);
  const [probingUpstreams, setProbingUpstreams] = createSignal(false);
  const [upstreamCapabilities, setUpstreamCapabilities] = createSignal<UpstreamCapabilities[]>([]);
  const [probingCapabilities, setProbingCapabilities] = createSignal(false);
  const [probeCapabilitiesError, setProbeCapabilitiesError] = createSignal("");
  const [blockMode, setBlockMode] = createSignal<BlockMode>("zero_ip");
  const [allowCidrsText, setAllowCidrsText] = createSignal("");
  const [denyCidrsText, setDenyCidrsText] = createSignal("");
  const [rateLimitQps, setRateLimitQps] = createSignal(0);
  const [cacheSize, setCacheSize] = createSignal(65536);
  const [optimisticCache, setOptimisticCache] = createSignal(true);
  const [cacheMinTtlSecs, setCacheMinTtlSecs] = createSignal(10);
  const [cacheMaxTtlSecs, setCacheMaxTtlSecs] = createSignal(86400);
  const [cachePrefetchEnabled, setCachePrefetchEnabled] = createSignal(true);
  const [cachePersistEnabled, setCachePersistEnabled] = createSignal(false);
  const [serveStaleEnabled, setServeStaleEnabled] = createSignal(true);
  const [upstreamTimeoutMs, setUpstreamTimeoutMs] = createSignal(3000);
  const [logRetentionHours, setLogRetentionHours] = createSignal(24);
  const [logMaxDiskMb, setLogMaxDiskMb] = createSignal(256);
  const [configMessage, setConfigMessage] = createSignal("");
  const [configIsError, setConfigIsError] = createSignal(false);
  const [splitDnsRules, setSplitDnsRules] = createSignal<SplitDnsRule[]>([]);
  const [upstreamGroups, setUpstreamGroups] = createSignal<UpstreamGroup[]>([]);
  const [splitDnsMatchMode, setSplitDnsMatchMode] =
    createSignal<SplitDnsMatchMode>("specificity_first");
  const [splitDnsBeforeClientUpstreams, setSplitDnsBeforeClientUpstreams] = createSignal(false);
  const [splitDnsRefreshIntervalSecs, setSplitDnsRefreshIntervalSecs] = createSignal(86400);
  const [splitDnsStatuses, setSplitDnsStatuses] = createSignal<SplitDnsSourceStatus[]>([]);
  const [cnameCloakingBlocking, setCnameCloakingBlocking] = createSignal(true);
  const [dohEnabled, setDohEnabled] = createSignal(true);
  const [allowPrivateSubscriptions, setAllowPrivateSubscriptions] = createSignal(false);
  const [ecsEnabled, setEcsEnabled] = createSignal(false);
  const [ecsCustomIp, setEcsCustomIp] = createSignal("");
  const [ecsIpv4Prefix, setEcsIpv4Prefix] = createSignal(24);
  const [ecsIpv6Prefix, setEcsIpv6Prefix] = createSignal(56);
  const [dnssecEnabled, setDnssecEnabled] = createSignal(false);
  const [dnssecStrictClock, setDnssecStrictClock] = createSignal(false);
  const [dnssecAutoRollover, setDnssecAutoRollover] = createSignal(false);
  const [dnssecTrustAnchorsText, setDnssecTrustAnchorsText] = createSignal("");
  const [dnssecNtas, setDnssecNtas] = createSignal<DnssecNta[]>([]);
  const [edeEnabled, setEdeEnabled] = createSignal(true);
  const [dnsCookiesEnabled, setDnsCookiesEnabled] = createSignal(false);
  const [dnsCookiesRequireValid, setDnsCookiesRequireValid] = createSignal(false);
  const [maxUdpPayloadSize, setMaxUdpPayloadSize] = createSignal(1232);
  const [rrlEnabled, setRrlEnabled] = createSignal(false);
  const [rrlResponsesPerSecond, setRrlResponsesPerSecond] = createSignal(10);
  const [rrlSlip, setRrlSlip] = createSignal(2);
  const [rrlWindowSecs, setRrlWindowSecs] = createSignal(15);
  const [hostsEnabled, setHostsEnabled] = createSignal(false);
  const [hostsPath, setHostsPath] = createSignal("");
  const [dhcpLeasesEnabled, setDhcpLeasesEnabled] = createSignal(false);
  const [dhcpLeasesPath, setDhcpLeasesPath] = createSignal("");
  const [dhcpLeasesForwardEnabled, setDhcpLeasesForwardEnabled] = createSignal(false);
  const [dhcpLeasesDomain, setDhcpLeasesDomain] = createSignal("lan");
  const [configHistory, setConfigHistory] = createSignal<ConfigSnapshotMeta[]>([]);
  const [rollbackBusy, setRollbackBusy] = createSignal(false);
  const [refreshingSplitDns, setRefreshingSplitDns] = createSignal(false);
  const [mdnsEnabled, setMdnsEnabled] = createSignal(false);
  const [sniClientIdHostnamesText, setSniClientIdHostnamesText] = createSignal("");
  const [privatePtrEnabled, setPrivatePtrEnabled] = createSignal(false);
  const [privatePtrUpstreamsText, setPrivatePtrUpstreamsText] = createSignal("");
  const [blockLocalDomains, setBlockLocalDomains] = createSignal(false);
  const [suppressLocalDomainLogs, setSuppressLocalDomainLogs] = createSignal(false);
  const [ddrEnabled, setDdrEnabled] = createSignal(false);
  const [ddrHostname, setDdrHostname] = createSignal("");
  const [dnsRebindingProtection, setDnsRebindingProtection] = createSignal(false);
  const [blockAnyQueries, setBlockAnyQueries] = createSignal(false);
  const [trustedProxiesText, setTrustedProxiesText] = createSignal("");
  const [tlsCertPath, setTlsCertPath] = createSignal("");
  const [tlsKeyPath, setTlsKeyPath] = createSignal("");
  const [rdnsEnabled, setRdnsEnabled] = createSignal(true);
  const [safesearch, setSafesearch] = createSignal<SafeSearchConfig>({
    enabled: false,
    google: true,
    bing: true,
    youtube: true,
    youtube_strict: false,
    duckduckgo: true,
    yandex: true,
    pixabay: true,
    brave: true,
  });
  const [dns64Enabled, setDns64Enabled] = createSignal(false);
  const [dns64PrefixesText, setDns64PrefixesText] = createSignal("64:ff9b::/96");
  const [svcbStripEch, setSvcbStripEch] = createSignal(false);
  const [svcbStripHints, setSvcbStripHints] = createSignal(false);
  const [cfCdnEnabled, setCfCdnEnabled] = createSignal(false);
  const [cfCdnIpv6Enabled, setCfCdnIpv6Enabled] = createSignal(true);
  const [cfCdnIntervalSecs, setCfCdnIntervalSecs] = createSignal(1800);
  const [cfCdnTtlSecs, setCfCdnTtlSecs] = createSignal(60);
  const [cfCdnSpeedtestUrl, setCfCdnSpeedtestUrl] = createSignal(
    "https://speed.cloudflare.com/__down?bytes=99999999",
  );
  const [cfCdnExcludedDomainsText, setCfCdnExcludedDomainsText] = createSignal("");
  const [cfCdnConcurrency, setCfCdnConcurrency] = createSignal(50);
  const [cfCdnTopN, setCfCdnTopN] = createSignal(3);
  const [cfCdnSamplesPerCidr, setCfCdnSamplesPerCidr] = createSignal(3);
  const [cfCdnCustomIpv4CidrsText, setCfCdnCustomIpv4CidrsText] = createSignal("");
  const [cfCdnCustomIpv6CidrsText, setCfCdnCustomIpv6CidrsText] = createSignal("");
  const [cfCdnStatus, setCfCdnStatus] = createSignal<CfCdnStatus | null>(null);
  const [storageProfile, setStorageProfile] = createSignal<StorageProfile>("auto");
  const [diskMinFreeMb, setDiskMinFreeMb] = createSignal(128);
  const [tlsStatus, setTlsStatus] = createSignal<TlsStatusResponse | null>(null);
  const [reloadingTls, setReloadingTls] = createSignal(false);
  const [tlsMessage, setTlsMessage] = createSignal("");
  const [tlsIsError, setTlsIsError] = createSignal(false);
  const [acmeEnabled, setAcmeEnabled] = createSignal(false);
  const [acmeDomainsText, setAcmeDomainsText] = createSignal("");
  const [acmeEmail, setAcmeEmail] = createSignal("");
  const [acmeDirectoryUrl, setAcmeDirectoryUrl] = createSignal(
    "https://acme-v02.api.letsencrypt.org/directory",
  );
  const [acmeChallengeType, setAcmeChallengeType] = createSignal<AcmeChallengeType>("http01");
  const [acmeHttpListen, setAcmeHttpListen] = createSignal("");
  const [acmeRenewBeforeDays, setAcmeRenewBeforeDays] = createSignal(30);
  const [acmeStatus, setAcmeStatus] = createSignal<AcmeStatusResponse | null>(null);
  const [issuingAcme, setIssuingAcme] = createSignal(false);
  const [acmeMessage, setAcmeMessage] = createSignal("");
  const [acmeIsError, setAcmeIsError] = createSignal(false);
  const [clientsOverview, setClientsOverview] = createSignal<ClientsOverviewResponse | null>(null);
  const [clientsMessage, setClientsMessage] = createSignal("");
  const [clientsIsError, setClientsIsError] = createSignal(false);
  const [clientsSaving, setClientsSaving] = createSignal(false);
  const [rewrites, setRewrites] = createSignal<DnsRewriteEntry[]>([]);
  const [rewritesMessage, setRewritesMessage] = createSignal("");
  const [rewritesIsError, setRewritesIsError] = createSignal(false);
  const [rewritesSaving, setRewritesSaving] = createSignal(false);
  const [blockingStatus, setBlockingStatus] = createSignal<BlockingStatusResponse | null>(null);
  const [cacheFlushedMsg, setCacheFlushedMsg] = createSignal("");
  const [statsResetMsg, setStatsResetMsg] = createSignal("");
  const [quickRuleMsg, setQuickRuleMsg] = createSignal("");
  const [backupMessage, setBackupMessage] = createSignal("");
  const [backupIsError, setBackupIsError] = createSignal(false);
  const [backupBusy, setBackupBusy] = createSignal(false);
  const [updateStatus, setUpdateStatus] = createSignal<UpdateStatusResponse | null>(null);
  const [updateAction, setUpdateAction] = createSignal<UpdateAction>(null);
  const [updateMessage, setUpdateMessage] = createSignal("");
  const [updateIsError, setUpdateIsError] = createSignal(false);
  const [subProgress, setSubProgress] = createSignal<SubscriptionProgressStatus | null>(null);

  const [setupChecked, setSetupChecked] = createSignal(false);
  const [setupStatus, setSetupStatus] = createSignal<SetupStatusResponse | null>(null);
  const [authChecked, setAuthChecked] = createSignal(false);
  const [authEnabled, setAuthEnabled] = createSignal(false);
  const [authenticated, setAuthenticated] = createSignal(true);
  const [authUsername, setAuthUsername] = createSignal("admin");
  const [authPassword, setAuthPassword] = createSignal("");
  const [authMessage, setAuthMessage] = createSignal("");
  const [authIsError, setAuthIsError] = createSignal(false);
  const [pageVisible, setPageVisible] = createSignal(
    typeof document === "undefined" ? true : document.visibilityState !== "hidden",
  );
  const [appliedLogFilter, setAppliedLogFilter] = createSignal<WsLogFilter>({
    search: null,
    outcome: null,
    protocol: null,
    qtype: null,
    client: null,
  });

  function currentLogFilter(): WsLogFilter {
    return {
      search: search().trim() || null,
      outcome: outcomeFilter().trim() || null,
      protocol: protocolFilter().trim() || null,
      qtype: qtypeFilter().trim() || null,
      client: clientFilter().trim() || null,
    };
  }

  async function fetchSetupStatus(): Promise<boolean> {
    try {
      const res = await fetch("/api/setup/status");
      if (res.ok) {
        const data: SetupStatusResponse = await res.json();
        setSetupStatus(data);
        setSetupChecked(true);
        return data.setup_required;
      }
    } catch {
      // ignore
    }
    setSetupChecked(true);
    return false;
  }

  async function handleSetupComplete(payload: SetupCompletePayload): Promise<string | null> {
    try {
      const res = await fetch("/api/setup/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errBody = (await res.json().catch(() => null)) as { error?: string } | null;
        return errBody?.error ?? t("rulesFailed");
      }
      setSetupStatus((prev) => (prev ? { ...prev, setup_required: false } : null));
      const ok = await fetchAuthStatus();
      if (ok) {
        loadDashboardData();
      }
      return null;
    } catch {
      return t("rulesNetworkError");
    }
  }

  async function fetchStats() {
    try {
      const res = await fetch("/api/stats");
      if (res.ok) setStats(await res.json());
    } catch {
      // ignore transient network errors
    }
  }

  async function fetchLogs() {
    setAppliedLogFilter(currentLogFilter());
    const params = new URLSearchParams({ limit: "200" });
    if (search()) params.set("search", search());
    if (outcomeFilter()) params.set("outcome", outcomeFilter());
    if (protocolFilter()) params.set("protocol", protocolFilter());
    if (qtypeFilter()) params.set("qtype", qtypeFilter());
    if (clientFilter()) params.set("client", clientFilter());
    try {
      const res = await fetch(`/api/logs?${params.toString()}`);
      if (res.ok) setLogs(await res.json());
    } catch {
      // ignore
    }
  }

  async function clearLogs() {
    try {
      const res = await fetch("/api/logs", { method: "DELETE" });
      if (res.ok) {
        setLogs([]);
        setQuickRuleMsg(t("logsClearedMsg"));
        setTimeout(() => setQuickRuleMsg(""), 2500);
      }
    } catch {
      // ignore
    }
  }

  function exportLogsJson() {
    const blob = new Blob([JSON.stringify(logs(), null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = url;
    a.download = `crabdns-query-logs-${stamp}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function resetStats() {
    try {
      const res = await fetch("/api/stats/reset", { method: "POST" });
      if (res.ok) {
        setStats(await res.json());
        setStatsResetMsg(t("statsResetMsg"));
        setTimeout(() => setStatsResetMsg(""), 2500);
        await fetchClients();
      }
    } catch {
      // ignore
    }
  }

  async function exportBackup() {
    setBackupBusy(true);
    setBackupIsError(false);
    setBackupMessage("");
    try {
      const res = await fetch("/api/backup");
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        const stamp = new Date().toISOString().slice(0, 10);
        a.href = url;
        a.download = `crabdns-backup-${stamp}.json`;
        a.click();
        URL.revokeObjectURL(url);
        setBackupMessage(t("backupExportedMsg"));
        setTimeout(() => setBackupMessage(""), 3000);
      } else {
        setBackupIsError(true);
        const errBody = await res.json().catch(() => null);
        setBackupMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setBackupIsError(true);
      setBackupMessage(t("rulesNetworkError"));
    } finally {
      setBackupBusy(false);
    }
  }

  async function fetchConfigHistory() {
    try {
      const res = await fetch("/api/config/history");
      if (res.ok) {
        const list: ConfigSnapshotMeta[] = await res.json();
        setConfigHistory(list);
      }
    } catch {
      // ignore
    }
  }

  async function rollbackConfigSnapshot(id: string) {
    setRollbackBusy(true);
    setBackupIsError(false);
    setBackupMessage("");
    try {
      const res = await fetch(`/api/config/rollback/${encodeURIComponent(id)}`, {
        method: "POST",
      });
      if (res.ok) {
        const updated: ConfigResponse = await res.json();
        applyConfigToForm(updated);
        await Promise.all([fetchConfigHistory(), fetchUpstreamHealth()]);
        setBackupMessage(t("configHistoryRolledBack"));
      } else {
        const errBody = await res.json().catch(() => null);
        setBackupIsError(true);
        setBackupMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setBackupIsError(true);
      setBackupMessage(t("rulesNetworkError"));
    } finally {
      setRollbackBusy(false);
    }
  }

  async function fetchSplitDnsStatus() {
    try {
      const res = await fetch("/api/split-dns/status");
      if (res.ok) {
        const list: SplitDnsSourceStatus[] = await res.json();
        setSplitDnsStatuses(list);
      }
    } catch {
      // ignore
    }
  }

  async function refreshSplitDnsLists() {
    setRefreshingSplitDns(true);
    setConfigIsError(false);
    setConfigMessage("");
    try {
      const res = await fetch("/api/split-dns/refresh", { method: "POST" });
      if (res.ok) {
        const body = (await res.json()) as SplitDnsRefreshSummary;
        if (body.sources) {
          setSplitDnsStatuses(body.sources);
        }
        const failed = body.failed ?? 0;
        const updated = body.updated ?? 0;
        const notModified = body.not_modified ?? 0;
        setConfigIsError(failed > 0 && updated === 0);
        setConfigMessage(
          `${t("splitDnsRefreshSummary")}: ${updated} updated · ${notModified} unchanged${
            failed > 0 ? ` · ${failed} failed` : ""
          }`,
        );
      } else {
        const errBody = await res.json().catch(() => null);
        setConfigIsError(true);
        setConfigMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setConfigIsError(true);
      setConfigMessage(t("rulesNetworkError"));
    } finally {
      setRefreshingSplitDns(false);
    }
  }

  async function importBackup(file: File) {
    setBackupBusy(true);
    setBackupIsError(false);
    setBackupMessage("");
    try {
      const text = await file.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        setBackupIsError(true);
        setBackupMessage(t("backupInvalidFileMsg"));
        return;
      }
      const res = await fetch("/api/backup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });
      if (res.ok) {
        const updated: ConfigResponse = await res.json();
        applyConfigToForm(updated);
        await Promise.all([
          fetchStats(),
          fetchRules(),
          fetchSubscriptions(),
          fetchRewrites(),
          fetchClients(),
          fetchUpstreamHealth(),
          fetchTlsStatus(),
          fetchAcmeStatus(),
          fetchCfCdnStatus(),
        ]);
        setBackupMessage(t("backupRestoredMsg"));
        setTimeout(() => setBackupMessage(""), 3500);
      } else {
        setBackupIsError(true);
        const errBody = await res.json().catch(() => null);
        setBackupMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setBackupIsError(true);
      setBackupMessage(t("rulesNetworkError"));
    } finally {
      setBackupBusy(false);
    }
  }

  async function fetchUpdateStatus() {
    try {
      const res = await fetch("/api/update/status", { cache: "no-store" });
      if (res.ok) {
        setUpdateStatus(await res.json());
      }
    } catch {
      // ignore
    }
  }

  const shouldConnectWs = createMemo(
    () =>
      setupChecked() &&
      !setupStatus()?.setup_required &&
      authChecked() &&
      (!authEnabled() || authenticated()),
  );

  const shouldPollUpdateProgress = createMemo(
    () => updateAction() === "apply" || Boolean(updateStatus()?.busy),
  );

  createEffect(() => {
    if (!shouldConnectWs() || !shouldPollUpdateProgress() || wsConnected()) return;
    let inFlight = false;
    const timer = setInterval(async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        await fetchUpdateStatus();
      } finally {
        inFlight = false;
      }
    }, 500);
    onCleanup(() => clearInterval(timer));
  });

  async function checkUpdate() {
    if (updateAction() !== null || updateStatus()?.busy) return;
    setUpdateAction("check");
    setUpdateIsError(false);
    setUpdateMessage("");
    try {
      const res = await fetch("/api/update/check", { method: "POST" });
      if (res.ok) {
        const data: UpdateStatusResponse = await res.json();
        setUpdateStatus(data);
        setUpdateMessage(
          data.update_available
            ? `${t("updateAvailableMsg")} (v${data.latest_version ?? ""})`
            : t("updateUpToDateMsg"),
        );
        setTimeout(() => setUpdateMessage(""), 3500);
      } else {
        setUpdateIsError(true);
        const errBody = await res.json().catch(() => null);
        setUpdateMessage(errBody?.error ?? t("rulesFailed"));
        await fetchUpdateStatus();
      }
    } catch {
      setUpdateIsError(true);
      setUpdateMessage(t("rulesNetworkError"));
    } finally {
      setUpdateAction(null);
    }
  }

  async function applyUpdate() {
    if (updateAction() !== null || updateStatus()?.busy) return;
    setUpdateAction("apply");
    setUpdateIsError(false);
    setUpdateMessage("");
    try {
      const res = await fetch("/api/update/apply", { method: "POST" });
      if (res.ok) {
        const data: UpdateStatusResponse = await res.json();
        setUpdateStatus(data);
        setUpdateMessage(t("updateAppliedMsg"));
      } else {
        setUpdateIsError(true);
        const errBody = await res.json().catch(() => null);
        setUpdateMessage(errBody?.error ?? t("rulesFailed"));
        await fetchUpdateStatus();
      }
    } catch {
      setUpdateIsError(true);
      setUpdateMessage(t("rulesNetworkError"));
    } finally {
      setUpdateAction(null);
    }
  }

  async function restartService() {
    if (updateAction() !== null || updateStatus()?.busy) return;
    setUpdateAction("restart");
    setUpdateIsError(false);
    setUpdateMessage(t("updateRestartingMsg"));
    try {
      const res = await fetch("/api/system/restart", { method: "POST" });
      if (!res.ok) {
        setUpdateIsError(true);
        const errBody = await res.json().catch(() => null);
        setUpdateMessage(errBody?.error ?? t("rulesFailed"));
        return;
      }
      // Wait briefly for the process to shut down and re-exec, then poll /api/health
      await new Promise((r) => setTimeout(r, 800));
      let reconnected = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        try {
          const healthRes = await fetch("/api/health", { cache: "no-store" });
          if (healthRes.ok) {
            reconnected = true;
            break;
          }
        } catch {
          // still restarting
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      if (reconnected) {
        await Promise.all([fetchUpdateStatus(), fetchConfig()]);
        setUpdateMessage(t("updateRestartedMsg"));
      } else {
        setUpdateIsError(true);
        setUpdateMessage(t("rulesNetworkError"));
      }
    } catch {
      setUpdateIsError(true);
      setUpdateMessage(t("rulesNetworkError"));
    } finally {
      setUpdateAction(null);
    }
  }

  async function fetchRules() {
    try {
      const res = await fetch("/api/rules");
      if (res.ok) {
        const data: RulesPayload = await res.json();
        setRulesText(data.rules_text ?? "");
        setRulesEnabled(data.enabled ?? true);
      }
    } catch {
      // ignore
    }
  }

  function showSubToast(msg: string, isError = false) {
    setSubIsError(isError);
    setSubMessage(msg);
    setTimeout(() => setSubMessage(""), 3000);
  }

  async function fetchSubscriptions() {
    try {
      const res = await fetch("/api/subscriptions");
      if (res.ok) {
        setSubscriptions(await res.json());
      }
    } catch {
      // ignore
    }
  }

  async function addSubscription(payload: CreateSubscriptionPayload): Promise<boolean> {
    setAddingSub(true);
    try {
      const res = await fetch("/api/subscriptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const created: FilterSubscription = await res.json();
        setSubscriptions((prev) => [...prev, created]);
        await fetchStats();
        if (created.last_error) {
          showSubToast(created.last_error, true);
        } else {
          showSubToast(t("subsUpdatedToast"));
        }
        return true;
      }
      const errBody = await res.json().catch(() => null);
      showSubToast(errBody?.error ?? t("rulesFailed"), true);
      return false;
    } catch {
      showSubToast(t("rulesNetworkError"), true);
      return false;
    } finally {
      setAddingSub(false);
    }
  }

  async function toggleSubscription(sub: FilterSubscription) {
    try {
      const res = await fetch(`/api/subscriptions/${encodeURIComponent(sub.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !sub.enabled }),
      });
      if (res.ok) {
        const updated: FilterSubscription = await res.json();
        setSubscriptions((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
        await fetchStats();
      } else {
        showSubToast(t("rulesFailed"), true);
      }
    } catch {
      showSubToast(t("rulesNetworkError"), true);
    }
  }

  async function refreshSubscription(id: string) {
    setRefreshingIds((prev) => ({ ...prev, [id]: true }));
    try {
      const res = await fetch(`/api/subscriptions/${encodeURIComponent(id)}/refresh`, {
        method: "POST",
      });
      if (res.ok) {
        const updated: FilterSubscription = await res.json();
        setSubscriptions((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
        await fetchStats();
        if (updated.last_error) {
          showSubToast(updated.last_error, true);
        } else {
          showSubToast(t("subsUpdatedToast"));
        }
      } else {
        showSubToast(t("rulesFailed"), true);
      }
    } catch {
      showSubToast(t("rulesNetworkError"), true);
    } finally {
      setRefreshingIds((prev) => ({ ...prev, [id]: false }));
    }
  }

  const shouldPollSubscriptionProgress = createMemo(
    () =>
      addingSub() ||
      refreshingAll() ||
      Object.values(refreshingIds()).some(Boolean) ||
      Boolean(subProgress()?.active),
  );

  async function fetchSubscriptionProgress() {
    try {
      const res = await fetch("/api/subscriptions/progress", { cache: "no-store" });
      if (res.ok) {
        setSubProgress(await res.json());
      }
    } catch {
      // ignore
    }
  }

  createEffect(() => {
    if (!shouldConnectWs() || !shouldPollSubscriptionProgress() || wsConnected()) return;
    let inFlight = false;
    const timer = setInterval(async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        await fetchSubscriptionProgress();
      } finally {
        inFlight = false;
      }
    }, 350);
    onCleanup(() => clearInterval(timer));
  });

  async function refreshAllSubscriptions() {
    setRefreshingAll(true);
    try {
      const res = await fetch("/api/subscriptions/refresh", { method: "POST" });
      if (res.ok) {
        setSubscriptions(await res.json());
        await fetchStats();
        showSubToast(t("subsUpdatedToast"));
      } else {
        showSubToast(t("rulesFailed"), true);
      }
    } catch {
      showSubToast(t("rulesNetworkError"), true);
    } finally {
      setRefreshingAll(false);
    }
  }

  async function deleteSubscription(id: string) {
    try {
      const res = await fetch(`/api/subscriptions/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setSubscriptions((prev) => prev.filter((item) => item.id !== id));
        await fetchStats();
      } else {
        showSubToast(t("rulesFailed"), true);
      }
    } catch {
      showSubToast(t("rulesNetworkError"), true);
    }
  }

  function applyConfigToForm(data: ConfigResponse) {
    setConfigData(data);
    setUpstreamsText(data.upstreams.join("\n"));
    setBootstrapDnsText((data.bootstrap_dns ?? []).join("\n"));
    setUpstreamStrategy(data.upstream_strategy);
    setBlockMode(data.block_mode);
    setAllowCidrsText(data.allow_cidrs.join("\n"));
    setDenyCidrsText(data.deny_cidrs.join("\n"));
    setRateLimitQps(data.rate_limit_qps);
    setCacheSize(data.cache_size);
    setOptimisticCache(data.optimistic_cache);
    setCacheMinTtlSecs(data.cache_min_ttl_secs);
    setCacheMaxTtlSecs(data.cache_max_ttl_secs);
    setCachePrefetchEnabled(data.cache_prefetch_enabled);
    setCachePersistEnabled(data.cache_persist_enabled);
    setServeStaleEnabled(data.serve_stale_enabled ?? true);
    setUpstreamTimeoutMs(data.upstream_timeout_ms);
    setLogRetentionHours(data.log_retention_hours);
    setLogMaxDiskMb(data.log_max_disk_mb ?? 256);
    setAuthEnabled(data.web_auth_enabled);
    setAuthUsername(data.web_username || "admin");
    setSplitDnsRules(data.split_dns ?? []);
    setUpstreamGroups(data.upstream_groups ?? []);
    setSplitDnsMatchMode(data.split_dns_match_mode ?? "specificity_first");
    setSplitDnsBeforeClientUpstreams(data.split_dns_before_client_upstreams ?? false);
    setSplitDnsRefreshIntervalSecs(data.split_dns_refresh_interval_secs ?? 86400);
    setCnameCloakingBlocking(data.cname_cloaking_blocking);
    setDohEnabled(data.doh_enabled);
    setAllowPrivateSubscriptions(data.allow_private_subscriptions);
    setEcsEnabled(data.ecs_enabled);
    setEcsCustomIp(data.ecs_custom_ip ?? "");
    setEcsIpv4Prefix(data.ecs_ipv4_prefix);
    setEcsIpv6Prefix(data.ecs_ipv6_prefix);
    setDnssecEnabled(data.dnssec_enabled);
    setDnssecStrictClock(data.dnssec_strict_clock ?? false);
    setDnssecAutoRollover(data.dnssec_auto_rollover ?? false);
    setDnssecTrustAnchorsText((data.dnssec_trust_anchors ?? []).join("\n"));
    setDnssecNtas(data.dnssec_ntas ?? []);
    setEdeEnabled(data.ede_enabled ?? true);
    setDnsCookiesEnabled(data.dns_cookies_enabled ?? false);
    setDnsCookiesRequireValid(data.dns_cookies_require_valid ?? false);
    setMaxUdpPayloadSize(data.max_udp_payload_size ?? 1232);
    setRrlEnabled(data.rrl_enabled ?? false);
    setRrlResponsesPerSecond(data.rrl_responses_per_second ?? 10);
    setRrlSlip(data.rrl_slip ?? 2);
    setRrlWindowSecs(data.rrl_window_secs ?? 15);
    setHostsEnabled(data.hosts_enabled);
    setHostsPath(data.hosts_path ?? "");
    setDhcpLeasesEnabled(data.dhcp_leases_enabled);
    setDhcpLeasesPath(data.dhcp_leases_path ?? "");
    setDhcpLeasesForwardEnabled(data.dhcp_leases_forward_enabled);
    setDhcpLeasesDomain(data.dhcp_leases_domain || "lan");
    setMdnsEnabled(data.mdns_enabled);
    setSniClientIdHostnamesText((data.sni_client_id_hostnames ?? []).join("\n"));
    setPrivatePtrEnabled(data.private_ptr_enabled);
    setPrivatePtrUpstreamsText((data.private_ptr_upstreams ?? []).join("\n"));
    setBlockLocalDomains(data.block_local_domains ?? false);
    setSuppressLocalDomainLogs(data.suppress_local_domain_logs ?? false);
    setDdrEnabled(data.ddr_enabled);
    setDdrHostname(data.ddr_hostname ?? "");
    setDnsRebindingProtection(data.dns_rebinding_protection);
    setBlockAnyQueries(data.block_any_queries);
    setTrustedProxiesText((data.trusted_proxies ?? []).join("\n"));
    setTlsCertPath(data.tls_cert_path ?? "");
    setTlsKeyPath(data.tls_key_path ?? "");
    setAcmeEnabled(data.acme_enabled ?? false);
    setAcmeDomainsText((data.acme_domains ?? []).join("\n"));
    setAcmeEmail(data.acme_email ?? "");
    setAcmeDirectoryUrl(
      data.acme_directory_url || "https://acme-v02.api.letsencrypt.org/directory",
    );
    setAcmeChallengeType(data.acme_challenge_type ?? "http01");
    setAcmeHttpListen(data.acme_http_listen ?? "");
    setAcmeRenewBeforeDays(data.acme_renew_before_days ?? 30);
    setRdnsEnabled(data.rdns_enabled);
    setSafesearch(
      data.safesearch ?? {
        enabled: false,
        google: true,
        bing: true,
        youtube: true,
        youtube_strict: false,
        duckduckgo: true,
        yandex: true,
        pixabay: true,
        brave: true,
      },
    );
    setDns64Enabled(data.dns64_enabled);
    setDns64PrefixesText((data.dns64_prefixes ?? ["64:ff9b::/96"]).join("\n"));
    setSvcbStripEch(data.svcb_strip_ech);
    setSvcbStripHints(data.svcb_strip_hints);
    if (data.cf_cdn) {
      setCfCdnEnabled(data.cf_cdn.enabled);
      setCfCdnIpv6Enabled(data.cf_cdn.ipv6_enabled);
      setCfCdnIntervalSecs(data.cf_cdn.interval_secs);
      setCfCdnTtlSecs(data.cf_cdn.ttl_secs);
      setCfCdnSpeedtestUrl(data.cf_cdn.speedtest_url);
      setCfCdnExcludedDomainsText((data.cf_cdn.excluded_domains ?? []).join("\n"));
      setCfCdnConcurrency(data.cf_cdn.concurrency ?? 50);
      setCfCdnTopN(data.cf_cdn.top_n ?? 3);
      setCfCdnSamplesPerCidr(data.cf_cdn.samples_per_cidr ?? 3);
      setCfCdnCustomIpv4CidrsText((data.cf_cdn.custom_ipv4_cidrs ?? []).join("\n"));
      setCfCdnCustomIpv6CidrsText((data.cf_cdn.custom_ipv6_cidrs ?? []).join("\n"));
    }
    setStorageProfile(data.storage_profile ?? "auto");
    setDiskMinFreeMb(data.disk_min_free_mb ?? 128);
  }

  const clientNameMap = createMemo<Record<string, string>>(() => {
    const map: Record<string, string> = {};
    const ov = clientsOverview();
    if (!ov) return map;
    for (const d of ov.discovered) {
      if (d.resolved_name) {
        map[d.ip] = d.resolved_name;
      }
    }
    for (const c of ov.clients) {
      for (const ident of c.identifiers) {
        if (!ident.includes("/") && (ident.includes(".") || ident.includes(":"))) {
          map[ident] = c.name;
        }
      }
    }
    return map;
  });

  function showClientsToast(msg: string, isError = false) {
    setClientsIsError(isError);
    setClientsMessage(msg);
    setTimeout(() => setClientsMessage(""), 3000);
  }

  async function fetchClients() {
    try {
      const res = await fetch("/api/clients");
      if (res.ok) setClientsOverview(await res.json());
    } catch {
      // ignore
    }
  }

  async function mutateClientsApi(url: string, method: string, body?: unknown): Promise<boolean> {
    setClientsSaving(true);
    try {
      const res = await fetch(url, {
        method,
        headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      if (res.ok) {
        await fetchClients();
        showClientsToast(t("rulesSaved"));
        return true;
      }
      const errBody = await res.json().catch(() => null);
      showClientsToast(errBody?.error ?? t("rulesFailed"), true);
      return false;
    } catch {
      showClientsToast(t("rulesNetworkError"), true);
      return false;
    } finally {
      setClientsSaving(false);
    }
  }

  async function createClientGroup(payload: ClientGroupPayload): Promise<boolean> {
    return mutateClientsApi("/api/client-groups", "POST", payload);
  }

  async function updateClientGroup(id: string, payload: ClientGroupPayload): Promise<boolean> {
    return mutateClientsApi(`/api/client-groups/${encodeURIComponent(id)}`, "PUT", payload);
  }

  async function deleteClientGroup(id: string): Promise<void> {
    await mutateClientsApi(`/api/client-groups/${encodeURIComponent(id)}`, "DELETE");
  }

  async function createClientProfile(payload: ClientProfilePayload): Promise<boolean> {
    return mutateClientsApi("/api/clients", "POST", payload);
  }

  async function updateClientProfile(id: string, payload: ClientProfilePayload): Promise<boolean> {
    return mutateClientsApi(`/api/clients/${encodeURIComponent(id)}`, "PUT", payload);
  }

  async function deleteClientProfile(id: string): Promise<void> {
    await mutateClientsApi(`/api/clients/${encodeURIComponent(id)}`, "DELETE");
  }

  function showRewritesToast(msg: string, isError = false) {
    setRewritesIsError(isError);
    setRewritesMessage(msg);
    setTimeout(() => setRewritesMessage(""), 3000);
  }

  async function fetchRewrites() {
    try {
      const res = await fetch("/api/rewrites");
      if (res.ok) setRewrites(await res.json());
    } catch {
      // ignore
    }
  }

  async function mutateRewritesApi(
    url: string,
    method: string,
    body?: unknown,
    toastKey: "rewritesSavedToast" | "rewritesDeletedToast" = "rewritesSavedToast",
  ): Promise<boolean> {
    setRewritesSaving(true);
    try {
      const res = await fetch(url, {
        method,
        headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      if (res.ok) {
        await Promise.all([fetchRewrites(), fetchStats()]);
        showRewritesToast(t(toastKey));
        return true;
      }
      const errBody = await res.json().catch(() => null);
      showRewritesToast(errBody?.error ?? t("rulesFailed"), true);
      return false;
    } catch {
      showRewritesToast(t("rulesNetworkError"), true);
      return false;
    } finally {
      setRewritesSaving(false);
    }
  }

  async function createRewrite(payload: DnsRewritePayload): Promise<boolean> {
    return mutateRewritesApi("/api/rewrites", "POST", payload, "rewritesSavedToast");
  }

  async function updateRewrite(id: string, payload: DnsRewritePayload): Promise<boolean> {
    return mutateRewritesApi(
      `/api/rewrites/${encodeURIComponent(id)}`,
      "PUT",
      payload,
      "rewritesSavedToast",
    );
  }

  async function deleteRewrite(id: string): Promise<void> {
    await mutateRewritesApi(
      `/api/rewrites/${encodeURIComponent(id)}`,
      "DELETE",
      undefined,
      "rewritesDeletedToast",
    );
  }

  async function fetchTlsStatus() {
    try {
      const res = await fetch("/api/tls/status");
      if (res.ok) setTlsStatus(await res.json());
    } catch {
      // ignore
    }
  }

  async function fetchAcmeStatus() {
    try {
      const res = await fetch("/api/acme/status");
      if (res.ok) setAcmeStatus(await res.json());
    } catch {
      // ignore
    }
  }

  async function fetchCfCdnStatus() {
    try {
      const res = await fetch("/api/cf-cdn/status");
      if (res.ok) {
        const data: CfCdnStatus = await res.json();
        setCfCdnStatus(data);
      }
    } catch {
      // ignore
    }
  }

  async function runCfCdnSpeedtest() {
    try {
      const res = await fetch("/api/cf-cdn/test", { method: "POST" });
      if (res.ok) {
        const data: CfCdnStatus = await res.json();
        setCfCdnStatus(data);
      }
    } catch {
      // ignore
    }
  }

  createEffect(() => {
    if (!shouldConnectWs() || !cfCdnStatus()?.testing || wsConnected()) return;
    const timer = setInterval(() => {
      void fetchCfCdnStatus();
    }, 1500);
    onCleanup(() => clearInterval(timer));
  });

  async function issueAcmeCertificate() {
    setIssuingAcme(true);
    setAcmeIsError(false);
    setAcmeMessage("");
    try {
      const res = await fetch("/api/acme/issue", { method: "POST" });
      if (res.ok) {
        setAcmeStatus(await res.json());
        setAcmeMessage(t("settingsAcmeIssuedOk"));
        await Promise.all([fetchTlsStatus(), fetchConfig()]);
      } else {
        setAcmeIsError(true);
        const errBody = await res.json().catch(() => null);
        setAcmeMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setAcmeIsError(true);
      setAcmeMessage(t("rulesNetworkError"));
    } finally {
      setIssuingAcme(false);
    }
  }

  async function reloadTls() {
    setReloadingTls(true);
    setTlsIsError(false);
    setTlsMessage("");
    try {
      const res = await fetch("/api/tls/reload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cert_path: tlsCertPath().trim() || null,
          key_path: tlsKeyPath().trim() || null,
        }),
      });
      if (res.ok) {
        setTlsStatus(await res.json());
        setTlsMessage(t("settingsTlsReloaded"));
        setTimeout(() => setTlsMessage(""), 3000);
      } else {
        setTlsIsError(true);
        const errBody = await res.json().catch(() => null);
        setTlsMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setTlsIsError(true);
      setTlsMessage(t("rulesNetworkError"));
    } finally {
      setReloadingTls(false);
    }
  }

  async function fetchBlockingStatus() {
    try {
      const res = await fetch("/api/blocking/status");
      if (res.ok) setBlockingStatus(await res.json());
    } catch {
      // ignore
    }
  }

  async function pauseBlocking(durationSecs: number | null) {
    try {
      const res = await fetch("/api/blocking/pause", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ duration_secs: durationSecs }),
      });
      if (res.ok) setBlockingStatus(await res.json());
    } catch {
      // ignore
    }
  }

  async function resumeBlocking() {
    try {
      const res = await fetch("/api/blocking/resume", { method: "POST" });
      if (res.ok) setBlockingStatus(await res.json());
    } catch {
      // ignore
    }
  }

  async function flushCache() {
    try {
      const res = await fetch("/api/cache/flush", { method: "POST" });
      if (res.ok) {
        setCacheFlushedMsg(t("cacheFlushed"));
        setTimeout(() => setCacheFlushedMsg(""), 2500);
        await fetchStats();
      }
    } catch {
      // ignore
    }
  }

  async function quickRule(domain: string, action: "allow" | "block") {
    try {
      const res = await fetch("/api/rules/quick", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, action }),
      });
      if (res.ok) {
        const data: QuickRuleResponse = await res.json();
        setQuickRuleMsg(`${t("logsQuickRuleAdded")}: ${data.rule}`);
        setTimeout(() => setQuickRuleMsg(""), 3000);
        await Promise.all([fetchRules(), fetchStats()]);
      }
    } catch {
      // ignore
    }
  }

  async function testRule(
    domain: string,
    qtype?: string | null,
    clientIp?: string | null,
    clientId?: string | null,
  ): Promise<TestRuleResponse | null> {
    try {
      const res = await fetch("/api/rules/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain,
          qtype: qtype ?? null,
          client_ip: clientIp ?? null,
          client_id: clientId ?? null,
        }),
      });
      if (res.ok) return await res.json();
    } catch {
      // ignore
    }
    return null;
  }

  async function fetchUpstreamHealth() {
    try {
      const res = await fetch("/api/upstreams/health");
      if (res.ok) setUpstreamHealth(await res.json());
    } catch {
      // ignore
    }
  }

  async function probeUpstreams() {
    setProbingUpstreams(true);
    try {
      const res = await fetch("/api/upstreams/health", { method: "POST" });
      if (res.ok) setUpstreamHealth(await res.json());
    } catch {
      // ignore
    } finally {
      setProbingUpstreams(false);
    }
  }

  async function probeUpstreamCapabilities() {
    const upstreams = upstreamsText()
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (upstreams.length === 0) {
      setUpstreamCapabilities([]);
      return;
    }
    const bootstrap_dns = bootstrapDnsText()
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    setProbingCapabilities(true);
    setProbeCapabilitiesError("");
    try {
      const res = await fetch("/api/upstreams/probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upstreams,
          bootstrap_dns,
          timeout_ms: upstreamTimeoutMs(),
        }),
      });
      if (res.ok) {
        setUpstreamCapabilities(await res.json());
      } else {
        const errBody = await res.json().catch(() => null);
        setProbeCapabilitiesError(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setProbeCapabilitiesError(t("rulesNetworkError"));
    } finally {
      setProbingCapabilities(false);
    }
  }

  function replaceUpstreamLine(fromInput: string, toUrl: string) {
    const lines = upstreamsText().split("\n");
    const next = lines.map((line) => (line.trim() === fromInput ? toUrl : line)).join("\n");
    setUpstreamsText(next);
  }

  async function fetchAuthStatus(): Promise<boolean> {
    try {
      const res = await fetch("/api/auth/status");
      if (res.ok) {
        const data: AuthStatusResponse = await res.json();
        setAuthEnabled(data.auth_enabled);
        setAuthenticated(data.authenticated);
        if (data.username) setAuthUsername(data.username);
        setAuthChecked(true);
        return data.authenticated || !data.auth_enabled;
      }
    } catch {
      // ignore
    }
    setAuthChecked(true);
    return true;
  }

  async function handleLogin(username: string, password: string): Promise<string | null> {
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (res.ok) {
        setAuthenticated(true);
        await Promise.all([
          fetchStats(),
          fetchLogs(),
          fetchRules(),
          fetchSubscriptions(),
          fetchRewrites(),
          fetchConfig(),
          fetchUpstreamHealth(),
          fetchClients(),
          fetchTlsStatus(),
          fetchAcmeStatus(),
          fetchCfCdnStatus(),
        ]);
        return null;
      }
      const errBody = await res.json().catch(() => null);
      return errBody?.error ?? "Login failed";
    } catch {
      return t("rulesNetworkError");
    }
  }

  async function handleLogout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      // ignore
    }
    setAuthenticated(false);
  }

  async function saveAuth() {
    setAuthIsError(false);
    setAuthMessage("");
    try {
      const res = await fetch("/api/auth/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: authEnabled(),
          username: authUsername(),
          password: authPassword() || null,
        }),
      });
      if (res.ok) {
        setAuthPassword("");
        setAuthMessage(t("settingsAuthSaved"));
        setTimeout(() => setAuthMessage(""), 3000);
      } else {
        setAuthIsError(true);
        const errBody = await res.json().catch(() => null);
        setAuthMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setAuthIsError(true);
      setAuthMessage(t("rulesNetworkError"));
    }
  }

  async function fetchConfig() {
    try {
      const res = await fetch("/api/config");
      if (res.ok) {
        const data: ConfigResponse = await res.json();
        applyConfigToForm(data);
        void fetchConfigHistory();
        void fetchSplitDnsStatus();
      }
    } catch {
      // ignore
    }
  }

  async function saveRules() {
    setSaveMessage(t("rulesSaving"));
    try {
      const res = await fetch("/api/rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules_text: rulesText(), enabled: rulesEnabled() }),
      });
      if (res.ok) {
        setSaveMessage(t("rulesSaved"));
        await fetchStats();
      } else {
        setSaveMessage(t("rulesFailed"));
      }
    } catch {
      setSaveMessage(t("rulesNetworkError"));
    }
    setTimeout(() => setSaveMessage(""), 2500);
  }

  async function saveConfig() {
    setConfigIsError(false);
    setConfigMessage(t("settingsSaving"));
    const parseLines = (text: string) =>
      text
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
    const payload: ConfigUpdatePayload = {
      upstreams: parseLines(upstreamsText()),
      bootstrap_dns: parseLines(bootstrapDnsText()),
      upstream_strategy: upstreamStrategy(),
      cache_size: Number(cacheSize()),
      optimistic_cache: optimisticCache(),
      cache_min_ttl_secs: Number(cacheMinTtlSecs()),
      cache_max_ttl_secs: Number(cacheMaxTtlSecs()),
      cache_prefetch_enabled: cachePrefetchEnabled(),
      cache_persist_enabled: cachePersistEnabled(),
      serve_stale_enabled: serveStaleEnabled(),
      upstream_timeout_ms: Number(upstreamTimeoutMs()),
      log_retention_hours: Number(logRetentionHours()),
      log_max_disk_mb: Number(logMaxDiskMb()) || 256,
      block_mode: blockMode(),
      allow_cidrs: parseLines(allowCidrsText()),
      deny_cidrs: parseLines(denyCidrsText()),
      rate_limit_qps: Number(rateLimitQps()),
      split_dns: splitDnsRules(),
      upstream_groups: upstreamGroups(),
      split_dns_match_mode: splitDnsMatchMode(),
      split_dns_before_client_upstreams: splitDnsBeforeClientUpstreams(),
      split_dns_refresh_interval_secs: Number(splitDnsRefreshIntervalSecs()),
      cname_cloaking_blocking: cnameCloakingBlocking(),
      doh_enabled: dohEnabled(),
      allow_private_subscriptions: allowPrivateSubscriptions(),
      ecs_enabled: ecsEnabled(),
      ecs_custom_ip: ecsCustomIp().trim(),
      ecs_ipv4_prefix: Number(ecsIpv4Prefix()),
      ecs_ipv6_prefix: Number(ecsIpv6Prefix()),
      dnssec_enabled: dnssecEnabled(),
      dnssec_strict_clock: dnssecStrictClock(),
      dnssec_auto_rollover: dnssecAutoRollover(),
      dnssec_trust_anchors: parseLines(dnssecTrustAnchorsText()),
      dnssec_ntas: dnssecNtas(),
      hosts_enabled: hostsEnabled(),
      hosts_path: hostsPath().trim(),
      dhcp_leases_enabled: dhcpLeasesEnabled(),
      dhcp_leases_path: dhcpLeasesPath().trim(),
      dhcp_leases_forward_enabled: dhcpLeasesForwardEnabled(),
      dhcp_leases_domain: dhcpLeasesDomain().trim() || "lan",
      mdns_enabled: mdnsEnabled(),
      sni_client_id_hostnames: parseLines(sniClientIdHostnamesText()),
      private_ptr_enabled: privatePtrEnabled(),
      private_ptr_upstreams: parseLines(privatePtrUpstreamsText()),
      block_local_domains: blockLocalDomains(),
      suppress_local_domain_logs: suppressLocalDomainLogs(),
      ddr_enabled: ddrEnabled(),
      ddr_hostname: ddrHostname().trim(),
      dns_rebinding_protection: dnsRebindingProtection(),
      block_any_queries: blockAnyQueries(),
      trusted_proxies: parseLines(trustedProxiesText()),
      tls_cert_path: tlsCertPath().trim(),
      tls_key_path: tlsKeyPath().trim(),
      rdns_enabled: rdnsEnabled(),
      safesearch: safesearch(),
      dns64_enabled: dns64Enabled(),
      dns64_prefixes: parseLines(dns64PrefixesText()),
      svcb_strip_ech: svcbStripEch(),
      svcb_strip_hints: svcbStripHints(),
      cf_cdn: {
        enabled: cfCdnEnabled(),
        ipv6_enabled: cfCdnIpv6Enabled(),
        interval_secs: Number(cfCdnIntervalSecs()) || 1800,
        speedtest_url:
          cfCdnSpeedtestUrl().trim() || "https://speed.cloudflare.com/__down?bytes=99999999",
        concurrency: Number(cfCdnConcurrency()) || 50,
        top_n: Number(cfCdnTopN()) || 3,
        samples_per_cidr: Number(cfCdnSamplesPerCidr()) || 3,
        ttl_secs: Number(cfCdnTtlSecs()) || 60,
        excluded_domains: parseLines(cfCdnExcludedDomainsText()),
        custom_ipv4_cidrs: parseLines(cfCdnCustomIpv4CidrsText()),
        custom_ipv6_cidrs: parseLines(cfCdnCustomIpv6CidrsText()),
      },
      ede_enabled: edeEnabled(),
      dns_cookies_enabled: dnsCookiesEnabled(),
      dns_cookies_require_valid: dnsCookiesRequireValid(),
      max_udp_payload_size: Number(maxUdpPayloadSize()) || 1232,
      rrl_enabled: rrlEnabled(),
      rrl_responses_per_second: Number(rrlResponsesPerSecond()) || 10,
      rrl_slip: Number(rrlSlip()) || 0,
      rrl_window_secs: Number(rrlWindowSecs()) || 15,
      storage_profile: storageProfile(),
      disk_min_free_mb: Number(diskMinFreeMb()) || 0,
      confirm_timeout_secs: null,
      acme_enabled: acmeEnabled(),
      acme_domains: acmeDomainsText()
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
      acme_email: acmeEmail().trim(),
      acme_directory_url: acmeDirectoryUrl().trim(),
      acme_challenge_type: acmeChallengeType(),
      acme_http_listen: acmeHttpListen().trim(),
      acme_renew_before_days: acmeRenewBeforeDays(),
    };

    try {
      const res = await fetch("/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const updated: ConfigResponse = await res.json();
        applyConfigToForm(updated);
        setConfigIsError(false);
        setConfigMessage(t("settingsSaved"));
        await Promise.all([
          fetchStats(),
          fetchTlsStatus(),
          fetchAcmeStatus(),
          fetchCfCdnStatus(),
          fetchConfigHistory(),
          fetchSplitDnsStatus(),
        ]);
      } else {
        setConfigIsError(true);
        const errBody = await res.json().catch(() => null);
        setConfigMessage(errBody?.error ?? t("rulesFailed"));
      }
    } catch {
      setConfigIsError(true);
      setConfigMessage(t("rulesNetworkError"));
    }
    setTimeout(() => setConfigMessage(""), 3500);
  }

  function handleSelectTab(next: TabKey) {
    setTab(next);
    if (next === "dashboard") {
      if (!wsConnected()) fetchStats();
      fetchClients();
    } else if (next === "logs") {
      fetchLogs();
    } else if (next === "rules") {
      fetchRules();
      fetchSubscriptions();
    } else if (next === "rewrites") {
      fetchRewrites();
    } else if (next === "clients") {
      fetchClients();
    } else if (next === "settings") {
      fetchConfig();
      fetchUpstreamHealth();
      fetchTlsStatus();
      if (!wsConnected()) {
        fetchUpdateStatus();
        fetchCfCdnStatus();
      }
    }
  }

  function loadDashboardData() {
    fetchStats();
    fetchLogs();
    fetchRules();
    fetchSubscriptions();
    fetchRewrites();
    fetchConfig();
    fetchUpstreamHealth();
    fetchBlockingStatus();
    fetchClients();
    fetchTlsStatus();
    fetchUpdateStatus();
  }

  const desiredWsTopics = createMemo<WsTopic[]>(() => {
    if (!shouldConnectWs() || !pageVisible()) return [];
    const topics: WsTopic[] = ["blocking"];
    const activeTab = tab();
    if (activeTab === "dashboard") {
      topics.push("stats");
    }
    if (activeTab === "logs") {
      topics.push("logs");
    }
    if (activeTab === "settings" || updateAction() !== null || Boolean(updateStatus()?.busy)) {
      topics.push("update");
    }
    if (activeTab === "settings" || Boolean(cfCdnStatus()?.testing)) {
      topics.push("cf_cdn");
    }
    if (activeTab === "rules" || shouldPollSubscriptionProgress()) {
      topics.push("subscriptions");
    }
    return topics;
  });

  const wsClient = createWsEventClient({
    onOpen: () => setWsConnected(true),
    onClose: () => setWsConnected(false),
    onAuthExpired: () => {
      setWsConnected(false);
      void fetchAuthStatus();
    },
    onLogsBatch: (batch) => {
      setLogs((prev) => [...[...batch].reverse(), ...prev].slice(0, 200));
    },
    onStats: (next) => setStats(next),
    onBlocking: (next) => setBlockingStatus(next),
    onUpdate: (next) => setUpdateStatus(next),
    onCfCdn: (next) => setCfCdnStatus(next),
    onSubscriptionProgress: (next) => setSubProgress(next),
  });

  createEffect(() => {
    if (shouldConnectWs()) {
      wsClient.connect();
    } else {
      wsClient.disconnect();
      setWsConnected(false);
    }
  });

  createEffect(() => {
    if (!shouldConnectWs()) return;
    wsClient.setSubscription(desiredWsTopics(), appliedLogFilter());
  });

  let wasPageVisible = pageVisible();
  createEffect(() => {
    const visible = pageVisible();
    const becameVisible = !wasPageVisible && visible;
    wasPageVisible = visible;
    if (becameVisible && shouldConnectWs() && tab() === "logs") {
      void fetchLogs();
    }
  });

  createEffect(() => {
    if (!shouldConnectWs() || wsConnected() || !pageVisible()) return;
    const timer = setInterval(() => {
      void fetchBlockingStatus();
      if (tab() === "dashboard") {
        void fetchStats();
      }
    }, 5000);
    onCleanup(() => clearInterval(timer));
  });

  onMount(() => {
    void fetchSetupStatus().then((needsSetup) => {
      if (needsSetup) return;
      void fetchAuthStatus().then((ok) => {
        if (ok) {
          loadDashboardData();
        }
      });
    });

    const handleVisibilityChange = () => {
      setPageVisible(document.visibilityState !== "hidden");
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibilityChange);
    }

    onCleanup(() => {
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", handleVisibilityChange);
      }
      wsClient.disconnect();
    });
  });

  return (
    <Show
      when={!setupChecked() || !setupStatus()?.setup_required}
      fallback={<SetupWizardView status={setupStatus()!} onComplete={handleSetupComplete} />}
    >
      <Show
        when={!authChecked() || !authEnabled() || authenticated()}
        fallback={<LoginView onLogin={handleLogin} />}
      >
        <div class="min-h-screen flex flex-col bg-[#fafafa] dark:bg-[#000000] text-[#171717] dark:text-[#ededed] font-sans vercel-grid-bg">
          <Header
            tab={tab()}
            onSelectTab={handleSelectTab}
            wsConnected={wsConnected()}
            blockingStatus={blockingStatus()}
            onPauseBlocking={pauseBlocking}
            onResumeBlocking={resumeBlocking}
            authEnabled={authEnabled()}
            onLogout={handleLogout}
          />

          <main class="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 pt-5 sm:pt-7 pb-24 lg:pb-10">
            <Show when={tab() === "dashboard"}>
              <DashboardView
                stats={stats()}
                clientNameMap={clientNameMap()}
                onFlushCache={flushCache}
                cacheFlushedMsg={cacheFlushedMsg()}
                onResetStats={resetStats}
                statsResetMsg={statsResetMsg()}
              />
            </Show>

            <Show when={tab() === "diagnostics"}>
              <DiagnosticsView onNavigateTab={(next) => handleSelectTab(next as TabKey)} />
            </Show>

            <Show when={tab() === "clients"}>
              <ClientsView
                overview={clientsOverview()}
                message={clientsMessage()}
                isError={clientsIsError()}
                saving={clientsSaving()}
                onCreateGroup={createClientGroup}
                onUpdateGroup={updateClientGroup}
                onDeleteGroup={deleteClientGroup}
                onCreateClient={createClientProfile}
                onUpdateClient={updateClientProfile}
                onDeleteClient={deleteClientProfile}
                onRefresh={() => void fetchClients()}
              />
            </Show>

            <Show when={tab() === "logs"}>
              <LogsView
                logs={logs()}
                search={search()}
                onSearchChange={setSearch}
                outcomeFilter={outcomeFilter()}
                onOutcomeChange={setOutcomeFilter}
                protocolFilter={protocolFilter()}
                onProtocolChange={setProtocolFilter}
                qtypeFilter={qtypeFilter()}
                onQtypeChange={setQtypeFilter}
                clientFilter={clientFilter()}
                onClientChange={setClientFilter}
                onRefresh={fetchLogs}
                onClearLogs={clearLogs}
                onExportLogs={exportLogsJson}
                onQuickRule={quickRule}
                quickRuleMsg={quickRuleMsg()}
              />
            </Show>

            <Show when={tab() === "rules"}>
              <RulesView
                rulesText={rulesText()}
                rulesEnabled={rulesEnabled()}
                onRulesChange={setRulesText}
                onRulesEnabledChange={(next) => {
                  setRulesEnabled(next);
                  void saveRules();
                }}
                saveMessage={saveMessage()}
                onSave={saveRules}
                subscriptions={subscriptions()}
                subMessage={subMessage()}
                subIsError={subIsError()}
                refreshingIds={refreshingIds()}
                refreshingAll={refreshingAll()}
                addingSub={addingSub()}
                subProgress={subProgress()}
                onAddSubscription={addSubscription}
                onToggleSubscription={toggleSubscription}
                onRefreshSubscription={refreshSubscription}
                onRefreshAllSubscriptions={refreshAllSubscriptions}
                onDeleteSubscription={deleteSubscription}
                onTestRule={testRule}
              />
            </Show>

            <Show when={tab() === "rewrites"}>
              <RewritesView
                rewrites={rewrites()}
                message={rewritesMessage()}
                isError={rewritesIsError()}
                saving={rewritesSaving()}
                onCreate={createRewrite}
                onUpdate={updateRewrite}
                onDelete={deleteRewrite}
                onRefresh={() => void fetchRewrites()}
              />
            </Show>

            <Show when={tab() === "settings"}>
              <SettingsView
                configData={configData()}
                upstreamsText={upstreamsText()}
                onUpstreamsChange={setUpstreamsText}
                bootstrapDnsText={bootstrapDnsText()}
                onBootstrapDnsChange={setBootstrapDnsText}
                upstreamStrategy={upstreamStrategy()}
                onUpstreamStrategyChange={setUpstreamStrategy}
                upstreamHealth={upstreamHealth()}
                probingUpstreams={probingUpstreams()}
                onProbeUpstreams={probeUpstreams}
                upstreamCapabilities={upstreamCapabilities()}
                probingCapabilities={probingCapabilities()}
                probeCapabilitiesError={probeCapabilitiesError()}
                onProbeCapabilities={probeUpstreamCapabilities}
                onReplaceUpstream={replaceUpstreamLine}
                blockMode={blockMode()}
                onBlockModeChange={setBlockMode}
                allowCidrsText={allowCidrsText()}
                onAllowCidrsChange={setAllowCidrsText}
                denyCidrsText={denyCidrsText()}
                onDenyCidrsChange={setDenyCidrsText}
                rateLimitQps={rateLimitQps()}
                onRateLimitChange={setRateLimitQps}
                cacheSize={cacheSize()}
                onCacheSizeChange={setCacheSize}
                upstreamTimeoutMs={upstreamTimeoutMs()}
                onUpstreamTimeoutChange={setUpstreamTimeoutMs}
                logRetentionHours={logRetentionHours()}
                onLogRetentionChange={setLogRetentionHours}
                logMaxDiskMb={logMaxDiskMb()}
                onLogMaxDiskMbChange={setLogMaxDiskMb}
                optimisticCache={optimisticCache()}
                onOptimisticCacheChange={setOptimisticCache}
                cacheMinTtlSecs={cacheMinTtlSecs()}
                onCacheMinTtlChange={setCacheMinTtlSecs}
                cacheMaxTtlSecs={cacheMaxTtlSecs()}
                onCacheMaxTtlChange={setCacheMaxTtlSecs}
                cachePrefetchEnabled={cachePrefetchEnabled()}
                onCachePrefetchChange={setCachePrefetchEnabled}
                cachePersistEnabled={cachePersistEnabled()}
                onCachePersistChange={setCachePersistEnabled}
                serveStaleEnabled={serveStaleEnabled()}
                onServeStaleChange={setServeStaleEnabled}
                splitDnsRules={splitDnsRules()}
                onSplitDnsChange={setSplitDnsRules}
                upstreamGroups={upstreamGroups()}
                onUpstreamGroupsChange={setUpstreamGroups}
                splitDnsMatchMode={splitDnsMatchMode()}
                onSplitDnsMatchModeChange={setSplitDnsMatchMode}
                splitDnsBeforeClientUpstreams={splitDnsBeforeClientUpstreams()}
                onSplitDnsBeforeClientUpstreamsChange={setSplitDnsBeforeClientUpstreams}
                splitDnsRefreshIntervalSecs={splitDnsRefreshIntervalSecs()}
                onSplitDnsRefreshIntervalSecsChange={setSplitDnsRefreshIntervalSecs}
                splitDnsStatuses={splitDnsStatuses()}
                refreshingSplitDns={refreshingSplitDns()}
                onRefreshSplitDns={refreshSplitDnsLists}
                cnameCloakingBlocking={cnameCloakingBlocking()}
                onCnameCloakingChange={setCnameCloakingBlocking}
                dohEnabled={dohEnabled()}
                onDohEnabledChange={setDohEnabled}
                allowPrivateSubscriptions={allowPrivateSubscriptions()}
                onAllowPrivateSubscriptionsChange={setAllowPrivateSubscriptions}
                ecsEnabled={ecsEnabled()}
                onEcsEnabledChange={setEcsEnabled}
                ecsCustomIp={ecsCustomIp()}
                onEcsCustomIpChange={setEcsCustomIp}
                ecsIpv4Prefix={ecsIpv4Prefix()}
                onEcsIpv4PrefixChange={setEcsIpv4Prefix}
                ecsIpv6Prefix={ecsIpv6Prefix()}
                onEcsIpv6PrefixChange={setEcsIpv6Prefix}
                dnssecEnabled={dnssecEnabled()}
                onDnssecEnabledChange={setDnssecEnabled}
                dnssecStrictClock={dnssecStrictClock()}
                onDnssecStrictClockChange={setDnssecStrictClock}
                dnssecAutoRollover={dnssecAutoRollover()}
                onDnssecAutoRolloverChange={setDnssecAutoRollover}
                dnssecTrustAnchorsText={dnssecTrustAnchorsText()}
                onDnssecTrustAnchorsChange={setDnssecTrustAnchorsText}
                dnssecNtas={dnssecNtas()}
                onDnssecNtasChange={setDnssecNtas}
                edeEnabled={edeEnabled()}
                onEdeEnabledChange={setEdeEnabled}
                dnsCookiesEnabled={dnsCookiesEnabled()}
                onDnsCookiesEnabledChange={setDnsCookiesEnabled}
                dnsCookiesRequireValid={dnsCookiesRequireValid()}
                onDnsCookiesRequireValidChange={setDnsCookiesRequireValid}
                maxUdpPayloadSize={maxUdpPayloadSize()}
                onMaxUdpPayloadSizeChange={setMaxUdpPayloadSize}
                rrlEnabled={rrlEnabled()}
                onRrlEnabledChange={setRrlEnabled}
                rrlResponsesPerSecond={rrlResponsesPerSecond()}
                onRrlResponsesPerSecondChange={setRrlResponsesPerSecond}
                rrlSlip={rrlSlip()}
                onRrlSlipChange={setRrlSlip}
                rrlWindowSecs={rrlWindowSecs()}
                onRrlWindowSecsChange={setRrlWindowSecs}
                hostsEnabled={hostsEnabled()}
                onHostsEnabledChange={setHostsEnabled}
                hostsPath={hostsPath()}
                onHostsPathChange={setHostsPath}
                dhcpLeasesEnabled={dhcpLeasesEnabled()}
                onDhcpLeasesEnabledChange={setDhcpLeasesEnabled}
                dhcpLeasesPath={dhcpLeasesPath()}
                onDhcpLeasesPathChange={setDhcpLeasesPath}
                dhcpLeasesForwardEnabled={dhcpLeasesForwardEnabled()}
                onDhcpLeasesForwardEnabledChange={setDhcpLeasesForwardEnabled}
                dhcpLeasesDomain={dhcpLeasesDomain()}
                onDhcpLeasesDomainChange={setDhcpLeasesDomain}
                mdnsEnabled={mdnsEnabled()}
                onMdnsEnabledChange={setMdnsEnabled}
                sniClientIdHostnamesText={sniClientIdHostnamesText()}
                onSniClientIdHostnamesChange={setSniClientIdHostnamesText}
                privatePtrEnabled={privatePtrEnabled()}
                onPrivatePtrEnabledChange={setPrivatePtrEnabled}
                privatePtrUpstreamsText={privatePtrUpstreamsText()}
                onPrivatePtrUpstreamsChange={setPrivatePtrUpstreamsText}
                blockLocalDomains={blockLocalDomains()}
                onBlockLocalDomainsChange={setBlockLocalDomains}
                suppressLocalDomainLogs={suppressLocalDomainLogs()}
                onSuppressLocalDomainLogsChange={setSuppressLocalDomainLogs}
                ddrEnabled={ddrEnabled()}
                onDdrEnabledChange={setDdrEnabled}
                ddrHostname={ddrHostname()}
                onDdrHostnameChange={setDdrHostname}
                dnsRebindingProtection={dnsRebindingProtection()}
                onDnsRebindingProtectionChange={setDnsRebindingProtection}
                blockAnyQueries={blockAnyQueries()}
                onBlockAnyQueriesChange={setBlockAnyQueries}
                trustedProxiesText={trustedProxiesText()}
                onTrustedProxiesChange={setTrustedProxiesText}
                rdnsEnabled={rdnsEnabled()}
                onRdnsEnabledChange={setRdnsEnabled}
                safesearch={safesearch()}
                onSafesearchChange={setSafesearch}
                dns64Enabled={dns64Enabled()}
                onDns64EnabledChange={setDns64Enabled}
                dns64PrefixesText={dns64PrefixesText()}
                onDns64PrefixesChange={setDns64PrefixesText}
                svcbStripEch={svcbStripEch()}
                onSvcbStripEchChange={setSvcbStripEch}
                svcbStripHints={svcbStripHints()}
                onSvcbStripHintsChange={setSvcbStripHints}
                cfCdnEnabled={cfCdnEnabled()}
                onCfCdnEnabledChange={setCfCdnEnabled}
                cfCdnIpv6Enabled={cfCdnIpv6Enabled()}
                onCfCdnIpv6EnabledChange={setCfCdnIpv6Enabled}
                cfCdnIntervalSecs={cfCdnIntervalSecs()}
                onCfCdnIntervalSecsChange={setCfCdnIntervalSecs}
                cfCdnTtlSecs={cfCdnTtlSecs()}
                onCfCdnTtlSecsChange={setCfCdnTtlSecs}
                cfCdnSpeedtestUrl={cfCdnSpeedtestUrl()}
                onCfCdnSpeedtestUrlChange={setCfCdnSpeedtestUrl}
                cfCdnExcludedDomainsText={cfCdnExcludedDomainsText()}
                onCfCdnExcludedDomainsChange={setCfCdnExcludedDomainsText}
                cfCdnConcurrency={cfCdnConcurrency()}
                onCfCdnConcurrencyChange={setCfCdnConcurrency}
                cfCdnTopN={cfCdnTopN()}
                onCfCdnTopNChange={setCfCdnTopN}
                cfCdnSamplesPerCidr={cfCdnSamplesPerCidr()}
                onCfCdnSamplesPerCidrChange={setCfCdnSamplesPerCidr}
                cfCdnCustomIpv4CidrsText={cfCdnCustomIpv4CidrsText()}
                onCfCdnCustomIpv4CidrsChange={setCfCdnCustomIpv4CidrsText}
                cfCdnCustomIpv6CidrsText={cfCdnCustomIpv6CidrsText()}
                onCfCdnCustomIpv6CidrsChange={setCfCdnCustomIpv6CidrsText}
                cfCdnStatus={cfCdnStatus()}
                onRunCfCdnSpeedtest={() => void runCfCdnSpeedtest()}
                storageProfile={storageProfile()}
                onStorageProfileChange={setStorageProfile}
                diskMinFreeMb={diskMinFreeMb()}
                onDiskMinFreeMbChange={setDiskMinFreeMb}
                tlsCertPath={tlsCertPath()}
                onTlsCertPathChange={setTlsCertPath}
                tlsKeyPath={tlsKeyPath()}
                onTlsKeyPathChange={setTlsKeyPath}
                tlsStatus={tlsStatus()}
                reloadingTls={reloadingTls()}
                tlsMessage={tlsMessage()}
                tlsIsError={tlsIsError()}
                onReloadTls={() => void reloadTls()}
                acmeEnabled={acmeEnabled()}
                onAcmeEnabledChange={setAcmeEnabled}
                acmeDomainsText={acmeDomainsText()}
                onAcmeDomainsChange={setAcmeDomainsText}
                acmeEmail={acmeEmail()}
                onAcmeEmailChange={setAcmeEmail}
                acmeDirectoryUrl={acmeDirectoryUrl()}
                onAcmeDirectoryUrlChange={setAcmeDirectoryUrl}
                acmeChallengeType={acmeChallengeType()}
                onAcmeChallengeTypeChange={setAcmeChallengeType}
                acmeHttpListen={acmeHttpListen()}
                onAcmeHttpListenChange={setAcmeHttpListen}
                acmeRenewBeforeDays={acmeRenewBeforeDays()}
                onAcmeRenewBeforeDaysChange={setAcmeRenewBeforeDays}
                acmeStatus={acmeStatus()}
                issuingAcme={issuingAcme()}
                acmeMessage={acmeMessage()}
                acmeIsError={acmeIsError()}
                onIssueAcme={() => void issueAcmeCertificate()}
                configMessage={configMessage()}
                configIsError={configIsError()}
                onSave={saveConfig}
                authEnabled={authEnabled()}
                onAuthEnabledChange={setAuthEnabled}
                authUsername={authUsername()}
                onAuthUsernameChange={setAuthUsername}
                authPassword={authPassword()}
                onAuthPasswordChange={setAuthPassword}
                authMessage={authMessage()}
                authIsError={authIsError()}
                onSaveAuth={saveAuth}
                onExportBackup={exportBackup}
                onImportBackup={importBackup}
                backupMessage={backupMessage()}
                backupIsError={backupIsError()}
                backupBusy={backupBusy()}
                configHistory={configHistory()}
                rollbackBusy={rollbackBusy()}
                onRefreshHistory={fetchConfigHistory}
                onRollbackConfig={rollbackConfigSnapshot}
                updateStatus={updateStatus()}
                updateAction={updateAction()}
                updateMessage={updateMessage()}
                updateIsError={updateIsError()}
                onCheckUpdate={checkUpdate}
                onApplyUpdate={applyUpdate}
                onRestartService={restartService}
              />
            </Show>
          </main>

          <MobileNav tab={tab()} onSelectTab={handleSelectTab} />
        </div>
      </Show>
    </Show>
  );
}
