import { createSignal, onCleanup, onMount, For, Show } from "solid-js";
import { t, toggleLocale } from "./i18n";
import type { ConfigResponse } from "./types/ConfigResponse";
import type { ConfigUpdatePayload } from "./types/ConfigUpdatePayload";
import type { QueryEvent } from "./types/QueryEvent";
import type { QueryOutcome } from "./types/QueryOutcome";
import type { RulesPayload } from "./types/RulesPayload";
import type { StatsResponse } from "./types/StatsResponse";
import type { TopItem } from "./types/TopItem";

type TabKey = "dashboard" | "logs" | "rules" | "settings";

export default function App() {
  const [tab, setTab] = createSignal<TabKey>("dashboard");
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

  onMount(() => {
    fetchStats();
    fetchLogs();
    fetchRules();
    fetchConfig();

    const timer = setInterval(fetchStats, 3000);
    const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${wsProto}//${location.host}/api/logs/ws`);
    ws.onmessage = (msg) => {
      try {
        const event: QueryEvent = JSON.parse(msg.data);
        setLogs((prev) => [event, ...prev].slice(0, 200));
      } catch {
        // ignore malformed ws message
      }
    };

    onCleanup(() => {
      clearInterval(timer);
      ws.close();
    });
  });

  const blockRate = () => {
    const s = stats()?.stats;
    if (!s || s.total_queries === 0) return "0.0%";
    return `${((s.blocked_queries / s.total_queries) * 100).toFixed(1)}%`;
  };

  return (
    <div class="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans">
      <header class="border-b border-slate-800 bg-slate-900/70 backdrop-blur px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <span class="i-ri-shield-check-fill text-2xl text-emerald-400" />
          <div>
            <h1 class="text-lg font-bold tracking-tight">CrabDNS</h1>
            <p class="text-xs text-slate-400">{t("appSubtitle")}</p>
          </div>
        </div>
        <nav class="flex flex-wrap items-center gap-2">
          <button
            class={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-1.5 transition cursor-pointer border-0 ${
              tab() === "dashboard"
                ? "bg-emerald-500/20 text-emerald-300"
                : "bg-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setTab("dashboard")}
          >
            <span class="i-ri-dashboard-3-line" />
            {t("navDashboard")}
          </button>
          <button
            class={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-1.5 transition cursor-pointer border-0 ${
              tab() === "logs"
                ? "bg-emerald-500/20 text-emerald-300"
                : "bg-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => {
              setTab("logs");
              fetchLogs();
            }}
          >
            <span class="i-ri-file-list-3-line" />
            {t("navLogs")}
          </button>
          <button
            class={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-1.5 transition cursor-pointer border-0 ${
              tab() === "rules"
                ? "bg-emerald-500/20 text-emerald-300"
                : "bg-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => setTab("rules")}
          >
            <span class="i-ri-filter-3-line" />
            {t("navRules")}
          </button>
          <button
            class={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-1.5 transition cursor-pointer border-0 ${
              tab() === "settings"
                ? "bg-emerald-500/20 text-emerald-300"
                : "bg-transparent text-slate-400 hover:text-slate-200"
            }`}
            onClick={() => {
              setTab("settings");
              fetchConfig();
            }}
          >
            <span class="i-ri-settings-3-line" />
            {t("navSettings")}
          </button>
          <button
            onClick={toggleLocale}
            class="ml-2 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 cursor-pointer border border-slate-700"
          >
            <span class="i-ri-translate-2" />
            {t("langToggle")}
          </button>
        </nav>
      </header>

      <main class="flex-1 max-w-6xl w-full mx-auto p-6 space-y-6">
        <Show when={tab() === "dashboard"}>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title={t("statTotalQueries")}
              value={String(stats()?.stats.total_queries ?? 0)}
              icon="i-ri-global-line text-sky-400"
            />
            <StatCard
              title={t("statBlocked")}
              value={`${stats()?.stats.blocked_queries ?? 0} (${blockRate()})`}
              icon="i-ri-forbid-2-line text-rose-400"
            />
            <StatCard
              title={t("statCacheHits")}
              value={String(stats()?.stats.cached_queries ?? 0)}
              icon="i-ri-flashlight-line text-amber-400"
            />
            <StatCard
              title={t("statActiveRules")}
              value={String(stats()?.filter.total_rules ?? 0)}
              icon="i-ri-shield-keyhole-line text-emerald-400"
            />
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <TopListCard title={t("topBlockedDomains")} items={stats()?.stats.top_blocked ?? []} />
            <TopListCard title={t("topClients")} items={stats()?.stats.top_clients ?? []} />
          </div>
        </Show>

        <Show when={tab() === "logs"}>
          <div class="flex flex-wrap items-center gap-3">
            <div class="relative flex-1 min-w-56">
              <span class="i-ri-search-line absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder={t("logsSearchPlaceholder")}
                value={search()}
                onInput={(e) => setSearch(e.currentTarget.value)}
                onKeyDown={(e) => e.key === "Enter" && fetchLogs()}
                class="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-500"
              />
            </div>
            <select
              value={outcomeFilter()}
              onChange={(e) => {
                setOutcomeFilter(e.currentTarget.value);
                fetchLogs();
              }}
              class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 outline-none"
            >
              <option value="">{t("logsAllOutcomes")}</option>
              <option value="blocked">{t("logsOutcomeBlocked")}</option>
              <option value="cached">{t("logsOutcomeCached")}</option>
              <option value="forwarded">{t("logsOutcomeForwarded")}</option>
              <option value="rewritten">{t("logsOutcomeRewritten")}</option>
              <option value="error">{t("logsOutcomeError")}</option>
            </select>
            <button
              onClick={fetchLogs}
              class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-1.5 cursor-pointer border-0"
            >
              <span class="i-ri-refresh-line" />
              {t("logsRefresh")}
            </button>
          </div>

          <div class="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/50">
            <table class="w-full text-left text-sm">
              <thead class="bg-slate-900 text-slate-400 text-xs uppercase">
                <tr>
                  <th class="px-4 py-3">{t("logsColTime")}</th>
                  <th class="px-4 py-3">{t("logsColClient")}</th>
                  <th class="px-4 py-3">{t("logsColDomain")}</th>
                  <th class="px-4 py-3">{t("logsColType")}</th>
                  <th class="px-4 py-3">{t("logsColStatus")}</th>
                  <th class="px-4 py-3 text-right">{t("logsColLatency")}</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/70">
                <For each={logs()}>
                  {(entry) => (
                    <tr class="hover:bg-slate-800/40">
                      <td class="px-4 py-2.5 text-xs text-slate-400 whitespace-nowrap">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </td>
                      <td class="px-4 py-2.5 font-mono text-xs">{entry.client_ip}</td>
                      <td class="px-4 py-2.5 font-mono text-xs text-slate-200">{entry.domain}</td>
                      <td class="px-4 py-2.5 text-xs text-slate-400">{entry.qtype}</td>
                      <td class="px-4 py-2.5">
                        <OutcomeBadge outcome={entry.outcome} />
                      </td>
                      <td class="px-4 py-2.5 text-right font-mono text-xs text-slate-400">
                        {(entry.elapsed_us / 1000).toFixed(2)} ms
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>

        <Show when={tab() === "rules"}>
          <div class="border border-slate-800 rounded-xl bg-slate-900/50 p-5 space-y-4">
            <div class="flex items-center justify-between gap-4">
              <div>
                <h2 class="text-base font-semibold">{t("rulesTitle")}</h2>
                <p class="text-xs text-slate-400">{t("rulesSubtitle")}</p>
              </div>
              <div class="flex items-center gap-3">
                <Show when={saveMessage()}>
                  <span class="text-xs text-emerald-400">{saveMessage()}</span>
                </Show>
                <button
                  onClick={saveRules}
                  class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-1.5 cursor-pointer border-0"
                >
                  <span class="i-ri-save-3-line" />
                  {t("rulesApply")}
                </button>
              </div>
            </div>
            <textarea
              value={rulesText()}
              onInput={(e) => setRulesText(e.currentTarget.value)}
              rows={16}
              placeholder="||doubleclick.net^&#10;@@||safe.doubleclick.net^&#10;||myrouter.local^$dnsrewrite=192.168.1.1"
              class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 outline-none focus:border-emerald-500"
            />
          </div>
        </Show>

        <Show when={tab() === "settings"}>
          <div class="border border-slate-800 rounded-xl bg-slate-900/50 p-5 space-y-6">
            <div class="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 class="text-base font-semibold">{t("settingsTitle")}</h2>
                <p class="text-xs text-slate-400">{t("settingsSubtitle")}</p>
              </div>
              <div class="flex items-center gap-3">
                <Show when={configMessage()}>
                  <span class={`text-xs ${configIsError() ? "text-rose-400" : "text-emerald-400"}`}>
                    {configMessage()}
                  </span>
                </Show>
                <button
                  onClick={saveConfig}
                  class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-1.5 cursor-pointer border-0"
                >
                  <span class="i-ri-save-3-line" />
                  {t("settingsSave")}
                </button>
              </div>
            </div>

            <div class="space-y-4">
              <div>
                <label class="block text-xs font-medium text-slate-300 mb-1.5">
                  {t("settingsUpstreamsLabel")}
                </label>
                <textarea
                  rows={4}
                  value={upstreamsText()}
                  onInput={(e) => setUpstreamsText(e.currentTarget.value)}
                  class="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 outline-none focus:border-emerald-500"
                />
                <p class="text-xs text-slate-500 mt-1">{t("settingsUpstreamsHint")}</p>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label class="block text-xs font-medium text-slate-300 mb-1.5">
                    {t("settingsCacheSizeLabel")}
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={cacheSize()}
                    onInput={(e) => setCacheSize(Number(e.currentTarget.value))}
                    class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-slate-300 mb-1.5">
                    {t("settingsTimeoutLabel")}
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={upstreamTimeoutMs()}
                    onInput={(e) => setUpstreamTimeoutMs(Number(e.currentTarget.value))}
                    class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-slate-300 mb-1.5">
                    {t("settingsRetentionLabel")}
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={logRetentionHours()}
                    onInput={(e) => setLogRetentionHours(Number(e.currentTarget.value))}
                    class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <label class="flex items-center gap-2.5 text-sm text-slate-200 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={optimisticCache()}
                  onChange={(e) => setOptimisticCache(e.currentTarget.checked)}
                  class="rounded border-slate-700 bg-slate-950 text-emerald-500"
                />
                {t("settingsOptimisticLabel")}
              </label>
            </div>

            <Show when={configData()}>
              {(cfg) => (
                <div class="border-t border-slate-800 pt-4 space-y-2">
                  <p class="text-xs font-medium text-slate-400">{t("settingsReadonlyTitle")}</p>
                  <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div class="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3">
                      <span class="text-slate-500 block">{t("settingsDnsListen")}</span>
                      <span class="font-mono text-slate-300">{cfg().listen_dns}</span>
                    </div>
                    <div class="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3">
                      <span class="text-slate-500 block">{t("settingsWebListen")}</span>
                      <span class="font-mono text-slate-300">{cfg().listen_web}</span>
                    </div>
                    <div class="bg-slate-950/70 border border-slate-800/80 rounded-lg p-3">
                      <span class="text-slate-500 block">{t("settingsDataDir")}</span>
                      <span class="font-mono text-slate-300">{cfg().data_dir}</span>
                    </div>
                  </div>
                </div>
              )}
            </Show>
          </div>
        </Show>
      </main>
    </div>
  );
}

function StatCard(props: { title: string; value: string; icon: string }) {
  return (
    <div class="border border-slate-800 rounded-xl bg-slate-900/50 p-4 flex items-center justify-between">
      <div>
        <p class="text-xs text-slate-400">{props.title}</p>
        <p class="text-xl font-bold mt-1">{props.value}</p>
      </div>
      <span class={`${props.icon} text-2xl`} />
    </div>
  );
}

function TopListCard(props: { title: string; items: TopItem[] }) {
  return (
    <div class="border border-slate-800 rounded-xl bg-slate-900/50 p-4 space-y-3">
      <h3 class="text-sm font-semibold text-slate-200">{props.title}</h3>
      <Show
        when={props.items.length > 0}
        fallback={<p class="text-xs text-slate-500">{t("noDataRecorded")}</p>}
      >
        <div class="space-y-2">
          <For each={props.items}>
            {(item) => (
              <div class="flex items-center justify-between text-xs">
                <span class="font-mono text-slate-300 truncate">{item.name}</span>
                <span class="text-slate-400 font-mono">{item.count}</span>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}

function OutcomeBadge(props: { outcome: QueryOutcome }) {
  const styles: Record<QueryOutcome, string> = {
    blocked: "bg-rose-500/20 text-rose-300",
    cached: "bg-amber-500/20 text-amber-300",
    forwarded: "bg-sky-500/20 text-sky-300",
    rewritten: "bg-purple-500/20 text-purple-300",
    error: "bg-red-500/20 text-red-300",
  };
  const labelMap: Record<QueryOutcome, () => string> = {
    blocked: () => t("logsOutcomeBlocked"),
    cached: () => t("logsOutcomeCached"),
    forwarded: () => t("logsOutcomeForwarded"),
    rewritten: () => t("logsOutcomeRewritten"),
    error: () => t("logsOutcomeError"),
  };
  return (
    <span class={`px-2 py-0.5 rounded text-xs font-medium ${styles[props.outcome]}`}>
      {labelMap[props.outcome]()}
    </span>
  );
}
