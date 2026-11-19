import { createSignal, onCleanup, onMount, Show } from "solid-js";
import { DashboardView } from "./components/DashboardView";
import { Header } from "./components/Header";
import { LoginView } from "./components/LoginView";
import { LogsView } from "./components/LogsView";
import { MobileNav } from "./components/MobileNav";
import { RulesView } from "./components/RulesView";
import { SettingsView } from "./components/SettingsView";
import type { TabKey } from "./components/types";
import { t } from "./i18n";
import type { AuthStatusResponse } from "./types/AuthStatusResponse";
import type { BlockMode } from "./types/BlockMode";
import type { BlockingStatusResponse } from "./types/BlockingStatusResponse";
import type { ConfigResponse } from "./types/ConfigResponse";
import type { ConfigUpdatePayload } from "./types/ConfigUpdatePayload";
import type { CreateSubscriptionPayload } from "./types/CreateSubscriptionPayload";
import type { FilterSubscription } from "./types/FilterSubscription";
import type { QueryEvent } from "./types/QueryEvent";
import type { QuickRuleResponse } from "./types/QuickRuleResponse";
import type { RulesPayload } from "./types/RulesPayload";
import type { SplitDnsRule } from "./types/SplitDnsRule";
import type { StatsResponse } from "./types/StatsResponse";
import type { TestRuleResponse } from "./types/TestRuleResponse";
import type { UpstreamStatus } from "./types/UpstreamStatus";
import type { UpstreamStrategy } from "./types/UpstreamStrategy";

export default function App() {
  const [tab, setTab] = createSignal<TabKey>("dashboard");
  const [wsConnected, setWsConnected] = createSignal(false);
  const [stats, setStats] = createSignal<StatsResponse | null>(null);
  const [logs, setLogs] = createSignal<QueryEvent[]>([]);
  const [search, setSearch] = createSignal("");
  const [outcomeFilter, setOutcomeFilter] = createSignal("");
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
  const [upstreamTimeoutMs, setUpstreamTimeoutMs] = createSignal(3000);
  const [logRetentionHours, setLogRetentionHours] = createSignal(24);
  const [configMessage, setConfigMessage] = createSignal("");
  const [configIsError, setConfigIsError] = createSignal(false);
  const [splitDnsText, setSplitDnsText] = createSignal("");
  const [cnameCloakingBlocking, setCnameCloakingBlocking] = createSignal(true);
  const [dohEnabled, setDohEnabled] = createSignal(true);
  const [allowPrivateSubscriptions, setAllowPrivateSubscriptions] = createSignal(false);
  const [ecsEnabled, setEcsEnabled] = createSignal(false);
  const [ecsCustomIp, setEcsCustomIp] = createSignal("");
  const [ecsIpv4Prefix, setEcsIpv4Prefix] = createSignal(24);
  const [ecsIpv6Prefix, setEcsIpv6Prefix] = createSignal(56);
  const [dnssecEnabled, setDnssecEnabled] = createSignal(false);
  const [hostsEnabled, setHostsEnabled] = createSignal(false);
  const [hostsPath, setHostsPath] = createSignal("");
  const [privatePtrEnabled, setPrivatePtrEnabled] = createSignal(false);
  const [privatePtrUpstreamsText, setPrivatePtrUpstreamsText] = createSignal("");
  const [ddrEnabled, setDdrEnabled] = createSignal(false);
  const [ddrHostname, setDdrHostname] = createSignal("");
  const [dnsRebindingProtection, setDnsRebindingProtection] = createSignal(false);
  const [blockAnyQueries, setBlockAnyQueries] = createSignal(false);
  const [trustedProxiesText, setTrustedProxiesText] = createSignal("");
  const [blockingStatus, setBlockingStatus] = createSignal<BlockingStatusResponse | null>(null);
  const [cacheFlushedMsg, setCacheFlushedMsg] = createSignal("");
  const [quickRuleMsg, setQuickRuleMsg] = createSignal("");

  const [authChecked, setAuthChecked] = createSignal(false);
  const [authEnabled, setAuthEnabled] = createSignal(false);
  const [authenticated, setAuthenticated] = createSignal(true);
  const [authUsername, setAuthUsername] = createSignal("admin");
  const [authPassword, setAuthPassword] = createSignal("");
  const [authMessage, setAuthMessage] = createSignal("");
  const [authIsError, setAuthIsError] = createSignal(false);

  async function fetchStats() {
    try {
      const res = await fetch("/api/stats");
      if (res.ok) setStats(await res.json());
    } catch {
      // ignore transient network errors
    }
  }

  async function fetchLogs() {
    const params = new URLSearchParams({ limit: "150" });
    if (search()) params.set("search", search());
    if (outcomeFilter()) params.set("outcome", outcomeFilter());
    try {
      const res = await fetch(`/api/logs?${params.toString()}`);
      if (res.ok) setLogs(await res.json());
    } catch {
      // ignore
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
    setUpstreamTimeoutMs(data.upstream_timeout_ms);
    setLogRetentionHours(data.log_retention_hours);
    setAuthEnabled(data.web_auth_enabled);
    setAuthUsername(data.web_username || "admin");
    setSplitDnsText(
      (data.split_dns ?? []).map((r) => `${r.domain}=${r.upstreams.join(",")}`).join("\n"),
    );
    setCnameCloakingBlocking(data.cname_cloaking_blocking);
    setDohEnabled(data.doh_enabled);
    setAllowPrivateSubscriptions(data.allow_private_subscriptions);
    setEcsEnabled(data.ecs_enabled);
    setEcsCustomIp(data.ecs_custom_ip ?? "");
    setEcsIpv4Prefix(data.ecs_ipv4_prefix);
    setEcsIpv6Prefix(data.ecs_ipv6_prefix);
    setDnssecEnabled(data.dnssec_enabled);
    setHostsEnabled(data.hosts_enabled);
    setHostsPath(data.hosts_path ?? "");
    setPrivatePtrEnabled(data.private_ptr_enabled);
    setPrivatePtrUpstreamsText((data.private_ptr_upstreams ?? []).join("\n"));
    setDdrEnabled(data.ddr_enabled);
    setDdrHostname(data.ddr_hostname ?? "");
    setDnsRebindingProtection(data.dns_rebinding_protection);
    setBlockAnyQueries(data.block_any_queries);
    setTrustedProxiesText((data.trusted_proxies ?? []).join("\n"));
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

  async function testRule(domain: string): Promise<TestRuleResponse | null> {
    try {
      const res = await fetch("/api/rules/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
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
          fetchConfig(),
          fetchUpstreamHealth(),
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
    const parseSplitDns = (text: string): SplitDnsRule[] =>
      parseLines(text)
        .map((line) => {
          const eq = line.indexOf("=");
          if (eq <= 0) return null;
          const domain = line.slice(0, eq).trim();
          const upstreams = line
            .slice(eq + 1)
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s.length > 0);
          return domain && upstreams.length > 0 ? { domain, upstreams } : null;
        })
        .filter((item): item is SplitDnsRule => item !== null);
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
      upstream_timeout_ms: Number(upstreamTimeoutMs()),
      log_retention_hours: Number(logRetentionHours()),
      block_mode: blockMode(),
      allow_cidrs: parseLines(allowCidrsText()),
      deny_cidrs: parseLines(denyCidrsText()),
      rate_limit_qps: Number(rateLimitQps()),
      split_dns: parseSplitDns(splitDnsText()),
      cname_cloaking_blocking: cnameCloakingBlocking(),
      doh_enabled: dohEnabled(),
      allow_private_subscriptions: allowPrivateSubscriptions(),
      ecs_enabled: ecsEnabled(),
      ecs_custom_ip: ecsCustomIp().trim(),
      ecs_ipv4_prefix: Number(ecsIpv4Prefix()),
      ecs_ipv6_prefix: Number(ecsIpv6Prefix()),
      dnssec_enabled: dnssecEnabled(),
      hosts_enabled: hostsEnabled(),
      hosts_path: hostsPath().trim(),
      private_ptr_enabled: privatePtrEnabled(),
      private_ptr_upstreams: parseLines(privatePtrUpstreamsText()),
      ddr_enabled: ddrEnabled(),
      ddr_hostname: ddrHostname().trim(),
      dns_rebinding_protection: dnsRebindingProtection(),
      block_any_queries: blockAnyQueries(),
      trusted_proxies: parseLines(trustedProxiesText()),
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
        await fetchStats();
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
    if (next === "logs") {
      fetchLogs();
    } else if (next === "rules") {
      fetchRules();
      fetchSubscriptions();
    } else if (next === "settings") {
      fetchConfig();
      fetchUpstreamHealth();
    }
  }

  onMount(() => {
    void fetchAuthStatus().then((ok) => {
      if (ok) {
        fetchStats();
        fetchLogs();
        fetchRules();
        fetchSubscriptions();
        fetchConfig();
        fetchUpstreamHealth();
        fetchBlockingStatus();
      }
    });

    const timer = setInterval(() => {
      if (authenticated() || !authEnabled()) {
        fetchStats();
        fetchBlockingStatus();
      }
    }, 3000);
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;

    function connectWs() {
      if (disposed) return;
      const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(`${wsProto}//${location.host}/api/logs/ws`);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        if (!disposed) {
          reconnectTimer = setTimeout(connectWs, 3000);
        }
      };
      ws.onerror = () => {
        setWsConnected(false);
      };
      ws.onmessage = (msg) => {
        try {
          const event: QueryEvent = JSON.parse(msg.data);
          setLogs((prev) => [event, ...prev].slice(0, 200));
        } catch {
          // ignore malformed ws message
        }
      };
    }

    connectWs();

    onCleanup(() => {
      disposed = true;
      clearInterval(timer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    });
  });

  return (
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

        <main class="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 pt-5 sm:pt-7 pb-24 md:pb-10">
          <Show when={tab() === "dashboard"}>
            <DashboardView
              stats={stats()}
              onFlushCache={flushCache}
              cacheFlushedMsg={cacheFlushedMsg()}
            />
          </Show>

          <Show when={tab() === "logs"}>
            <LogsView
              logs={logs()}
              search={search()}
              onSearchChange={setSearch}
              outcomeFilter={outcomeFilter()}
              onOutcomeChange={setOutcomeFilter}
              onRefresh={fetchLogs}
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
              onAddSubscription={addSubscription}
              onToggleSubscription={toggleSubscription}
              onRefreshSubscription={refreshSubscription}
              onRefreshAllSubscriptions={refreshAllSubscriptions}
              onDeleteSubscription={deleteSubscription}
              onTestRule={testRule}
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
              splitDnsText={splitDnsText()}
              onSplitDnsChange={setSplitDnsText}
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
              hostsEnabled={hostsEnabled()}
              onHostsEnabledChange={setHostsEnabled}
              hostsPath={hostsPath()}
              onHostsPathChange={setHostsPath}
              privatePtrEnabled={privatePtrEnabled()}
              onPrivatePtrEnabledChange={setPrivatePtrEnabled}
              privatePtrUpstreamsText={privatePtrUpstreamsText()}
              onPrivatePtrUpstreamsChange={setPrivatePtrUpstreamsText}
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
            />
          </Show>
        </main>

        <MobileNav tab={tab()} onSelectTab={handleSelectTab} />
      </div>
    </Show>
  );
}
