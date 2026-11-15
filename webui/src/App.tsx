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
  const [saveMessage, setSaveMessage] = createSignal("");

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
      }
    } catch {
      // ignore
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
        body: JSON.stringify({ rules_text: rulesText() }),
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
    } else if (next === "settings") {
      fetchConfig();
    }
  }

  onMount(() => {
    fetchStats();
    fetchLogs();
    fetchRules();
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
            onRulesChange={setRulesText}
            saveMessage={saveMessage()}
            onSave={saveRules}
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
