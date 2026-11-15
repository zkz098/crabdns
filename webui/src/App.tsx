import { createSignal, onCleanup, onMount, Show } from "solid-js";
import { DashboardView } from "./components/DashboardView";
import { Header } from "./components/Header";
import { LogsView } from "./components/LogsView";
import { MobileNav } from "./components/MobileNav";
import { RulesView } from "./components/RulesView";
import { SettingsView } from "./components/SettingsView";
import type { TabKey } from "./components/types";
import { t } from "./i18n";
import type { ConfigResponse } from "./types/ConfigResponse";
import type { ConfigUpdatePayload } from "./types/ConfigUpdatePayload";
import type { CreateSubscriptionPayload } from "./types/CreateSubscriptionPayload";
import type { FilterSubscription } from "./types/FilterSubscription";
import type { QueryEvent } from "./types/QueryEvent";
import type { RulesPayload } from "./types/RulesPayload";
import type { StatsResponse } from "./types/StatsResponse";

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
  const [cacheSize, setCacheSize] = createSignal(65536);
  const [optimisticCache, setOptimisticCache] = createSignal(true);
  const [upstreamTimeoutMs, setUpstreamTimeoutMs] = createSignal(3000);
  const [logRetentionHours, setLogRetentionHours] = createSignal(24);
  const [configMessage, setConfigMessage] = createSignal("");
  const [configIsError, setConfigIsError] = createSignal(false);

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
    setCacheSize(data.cache_size);
    setOptimisticCache(data.optimistic_cache);
    setUpstreamTimeoutMs(data.upstream_timeout_ms);
    setLogRetentionHours(data.log_retention_hours);
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
    const payload: ConfigUpdatePayload = {
      upstreams: upstreamsText()
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
      cache_size: Number(cacheSize()),
      optimistic_cache: optimisticCache(),
      upstream_timeout_ms: Number(upstreamTimeoutMs()),
      log_retention_hours: Number(logRetentionHours()),
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
    }
  }

  onMount(() => {
    fetchStats();
    fetchLogs();
    fetchRules();
    fetchSubscriptions();
    fetchConfig();

    const timer = setInterval(fetchStats, 3000);
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
    <div class="min-h-screen flex flex-col bg-[#fafafa] dark:bg-[#000000] text-[#171717] dark:text-[#ededed] font-sans vercel-grid-bg">
      <Header tab={tab()} onSelectTab={handleSelectTab} wsConnected={wsConnected()} />

      <main class="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 pt-5 sm:pt-7 pb-24 md:pb-10">
        <Show when={tab() === "dashboard"}>
          <DashboardView stats={stats()} />
        </Show>

        <Show when={tab() === "logs"}>
          <LogsView
            logs={logs()}
            search={search()}
            onSearchChange={setSearch}
            outcomeFilter={outcomeFilter()}
            onOutcomeChange={setOutcomeFilter}
            onRefresh={fetchLogs}
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
          />
        </Show>

        <Show when={tab() === "settings"}>
          <SettingsView
            configData={configData()}
            upstreamsText={upstreamsText()}
            onUpstreamsChange={setUpstreamsText}
            cacheSize={cacheSize()}
            onCacheSizeChange={setCacheSize}
            upstreamTimeoutMs={upstreamTimeoutMs()}
            onUpstreamTimeoutChange={setUpstreamTimeoutMs}
            logRetentionHours={logRetentionHours()}
            onLogRetentionChange={setLogRetentionHours}
            optimisticCache={optimisticCache()}
            onOptimisticCacheChange={setOptimisticCache}
            configMessage={configMessage()}
            configIsError={configIsError()}
            onSave={saveConfig}
          />
        </Show>
      </main>

      <MobileNav tab={tab()} onSelectTab={handleSelectTab} />
    </div>
  );
}
