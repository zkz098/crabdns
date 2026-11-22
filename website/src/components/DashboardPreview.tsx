import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { translations, type Locale } from "../i18n/translations";

interface DashboardPreviewProps {
  lang: Locale;
}

type PreviewTab = "dashboard" | "logs" | "rules";
type Outcome = "Blocked" | "Cached" | "Forwarded" | "Rewritten";

interface LogRow {
  id: number;
  domain: string;
  client: string;
  proto: string;
  outcome: Outcome;
  latency: string;
}

const SAMPLE_QUERIES: Omit<LogRow, "id">[] = [
  { domain: "ads.doubleclick.net", client: "192.168.1.42", proto: "DoH3", outcome: "Blocked", latency: "0.04 ms" },
  { domain: "api.github.com", client: "192.168.1.15", proto: "DoQ", outcome: "Cached", latency: "0.09 ms" },
  { domain: "telemetry.sdk.example", client: "192.168.1.88", proto: "UDP", outcome: "Blocked", latency: "0.03 ms" },
  { domain: "crates.io", client: "192.168.1.15", proto: "DoT", outcome: "Forwarded", latency: "8.42 ms" },
  { domain: "nas.local.dev", client: "192.168.1.24", proto: "UDP", outcome: "Rewritten", latency: "0.05 ms" },
  { domain: "cloudflare-dns.com", client: "192.168.1.10", proto: "DoH", outcome: "Cached", latency: "0.07 ms" },
];

export function DashboardPreview(props: DashboardPreviewProps) {
  const [tab, setTab] = createSignal<PreviewTab>("dashboard");
  const [totalQueries, setTotalQueries] = createSignal(148_920);
  const [blockedQueries, setBlockedQueries] = createSignal(34_251);
  const [cachedQueries, setCachedQueries] = createSignal(86_373);
  const [logs, setLogs] = createSignal<LogRow[]>(
    SAMPLE_QUERIES.slice(0, 5).map((q, idx) => ({ ...q, id: idx + 1 })),
  );
  const [ruleInput, setRuleInput] = createSignal("ads.doubleclick.net");
  const [ruleResult, setRuleResult] = createSignal<"blocked" | "allowed" | "rewritten" | "clean">("blocked");

  const t = () => translations[props.lang];

  let nextId = 6;
  let sampleIdx = 5;

  onMount(() => {
    const timer = setInterval(() => {
      const next = SAMPLE_QUERIES[sampleIdx % SAMPLE_QUERIES.length];
      sampleIdx += 1;
      setTotalQueries((n) => n + 1);
      if (next.outcome === "Blocked") setBlockedQueries((n) => n + 1);
      if (next.outcome === "Cached") setCachedQueries((n) => n + 1);
      setLogs((prev) => [{ ...next, id: nextId++ }, ...prev.slice(0, 4)]);
    }, 2400);
    onCleanup(() => clearInterval(timer));
  });

  const evaluateRule = (domain: string) => {
    const d = domain.trim().toLowerCase();
    setRuleInput(domain);
    if (!d) return;
    if (d.includes("ads") || d.includes("track") || d.includes("telemetry") || d.includes("doubleclick")) {
      setRuleResult("blocked");
    } else if (d.includes("github.com")) {
      setRuleResult("allowed");
    } else if (d.endsWith(".dev") || d.endsWith(".local")) {
      setRuleResult("rewritten");
    } else {
      setRuleResult("clean");
    }
  };

  const blockRate = () => `${((blockedQueries() / totalQueries()) * 100).toFixed(1)}%`;
  const hitRate = () => `${((cachedQueries() / totalQueries()) * 100).toFixed(1)}%`;

  const outcomeStyle = (outcome: Outcome) => {
    switch (outcome) {
      case "Blocked":
        return "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20";
      case "Cached":
        return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20";
      case "Rewritten":
        return "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/20";
      default:
        return "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20";
    }
  };

  return (
    <div class="rounded-2xl border border-[#eaeaea] dark:border-[#262626] bg-white/95 dark:bg-[#0a0a0a]/95 shadow-xl shadow-black/5 dark:shadow-black/40 overflow-hidden">
      {/* Top Preview Chrome */}
      <div class="px-4 py-2.5 border-b border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-2.5">
          <div class="flex items-center gap-1.5">
            <span class="w-2.5 h-2.5 rounded-full bg-[#e4e4e7] dark:bg-[#27272a]" />
            <span class="w-2.5 h-2.5 rounded-full bg-[#e4e4e7] dark:bg-[#27272a]" />
            <span class="w-2.5 h-2.5 rounded-full bg-[#e4e4e7] dark:bg-[#27272a]" />
          </div>
          <span class="text-[11px] font-mono text-[#666666] dark:text-[#8f8f8f]">
            127.0.0.1:3000
          </span>
          <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
            <span class="relative flex h-1.5 w-1.5">
              <span class="animate-pulse-ring absolute inline-flex h-full w-full rounded-full bg-emerald-500" />
              <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
            </span>
            {t().previewLive}
          </span>
        </div>

        {/* WebUI-style Tabs */}
        <div class="flex items-center gap-1 p-0.5 rounded-lg bg-[#f4f4f5] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#222222]">
          {(
            [
              { key: "dashboard", label: t().previewTabDashboard, icon: "i-ri-dashboard-3-line" },
              { key: "logs", label: t().previewTabLogs, icon: "i-ri-terminal-box-line" },
              { key: "rules", label: t().previewTabRules, icon: "i-ri-shield-flash-line" },
            ] as const
          ).map((item) => (
            <button
              type="button"
              onClick={() => setTab(item.key)}
              class={`px-2.5 py-1 rounded-md text-[11px] font-medium flex items-center gap-1.5 cursor-pointer border-0 transition-all ${
                tab() === item.key
                  ? "bg-white dark:bg-[#1f1f1f] text-[#171717] dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10"
                  : "bg-transparent text-[#666666] dark:text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed]"
              }`}
            >
              <span class={`${item.icon} text-xs`} />
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div class="p-4 sm:p-5">
        <Show when={tab() === "dashboard"}>
          <div class="space-y-4">
            {/* KPI Cards matching DashboardView.tsx */}
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
                    {t().statTotalQueries}
                  </span>
                  <div class="w-6 h-6 rounded-md bg-sky-500/10 text-sky-600 dark:text-sky-400 flex items-center justify-center">
                    <span class="i-ri-global-line text-xs" />
                  </div>
                </div>
                <div class="mt-2 text-lg sm:text-xl font-semibold tracking-tight tabular-nums text-[#171717] dark:text-[#ededed]">
                  {totalQueries().toLocaleString()}
                </div>
                <div class="mt-0.5 text-[11px] text-[#8f8f8f] dark:text-[#71717a] tabular-nums">
                  8,412 {t().statCacheEntries}
                </div>
              </div>

              <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
                    {t().statBlocked}
                  </span>
                  <div class="w-6 h-6 rounded-md bg-rose-500/10 text-rose-600 dark:text-rose-400 flex items-center justify-center">
                    <span class="i-ri-forbid-2-line text-xs" />
                  </div>
                </div>
                <div class="mt-2 text-lg sm:text-xl font-semibold tracking-tight tabular-nums text-[#171717] dark:text-[#ededed]">
                  {blockedQueries().toLocaleString()}
                </div>
                <div class="mt-0.5 text-[11px] text-[#8f8f8f] dark:text-[#71717a] tabular-nums">
                  {t().statBlockRate} {blockRate()}
                </div>
              </div>

              <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
                    {t().statCacheHits}
                  </span>
                  <div class="w-6 h-6 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                    <span class="i-ri-flashlight-line text-xs" />
                  </div>
                </div>
                <div class="mt-2 text-lg sm:text-xl font-semibold tracking-tight tabular-nums text-[#171717] dark:text-[#ededed]">
                  {cachedQueries().toLocaleString()}
                </div>
                <div class="mt-0.5 text-[11px] text-[#8f8f8f] dark:text-[#71717a] tabular-nums">
                  {t().statHitRate} {hitRate()}
                </div>
              </div>

              <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5">
                <div class="flex items-center justify-between gap-2">
                  <span class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
                    {t().statActiveRules}
                  </span>
                  <div class="w-6 h-6 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
                    <span class="i-ri-shield-keyhole-line text-xs" />
                  </div>
                </div>
                <div class="mt-2 text-lg sm:text-xl font-semibold tracking-tight tabular-nums text-[#171717] dark:text-[#ededed]">
                  124,850
                </div>
                <div class="mt-0.5 text-[11px] text-[#8f8f8f] dark:text-[#71717a] tabular-nums">
                  123,400 {t().filterBlockRules} · 1,450 {t().filterAllowRules}
                </div>
              </div>
            </div>

            {/* Query Distribution Bar */}
            <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5 space-y-2.5">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <span class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                  {t().queryDistribution}
                </span>
                <div class="flex flex-wrap items-center gap-3 text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                  <span class="inline-flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-rose-500" />
                    {t().distBlocked} 23%
                  </span>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-amber-500" />
                    {t().distCached} 58%
                  </span>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-sky-500" />
                    {t().distForwarded} 16%
                  </span>
                  <span class="inline-flex items-center gap-1.5">
                    <span class="w-2 h-2 rounded-full bg-violet-500" />
                    {t().distRewritten} 3%
                  </span>
                </div>
              </div>
              <div class="h-2 w-full rounded-full overflow-hidden bg-[#f4f4f5] dark:bg-[#161616] flex">
                <div class="bg-rose-500 h-full" style={{ width: "23%" }} />
                <div class="bg-amber-500 h-full" style={{ width: "58%" }} />
                <div class="bg-sky-500 h-full" style={{ width: "16%" }} />
                <div class="bg-violet-500 h-full" style={{ width: "3%" }} />
              </div>
            </div>
          </div>
        </Show>

        <Show when={tab() === "logs"}>
          <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse text-xs">
                <thead>
                  <tr class="border-b border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-[#666666] dark:text-[#8f8f8f] text-[11px]">
                    <th class="py-2 px-3 font-medium">{t().logsDomain}</th>
                    <th class="py-2 px-3 font-medium">{t().logsClient}</th>
                    <th class="py-2 px-3 font-medium">{t().logsProtocol}</th>
                    <th class="py-2 px-3 font-medium">{t().logsOutcome}</th>
                    <th class="py-2 px-3 font-medium text-right">{t().logsLatency}</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-[#eaeaea] dark:divide-[#1f1f1f]">
                  <For each={logs()}>
                    {(row) => (
                      <tr class="animate-row-enter hover:bg-[#fafafa] dark:hover:bg-[#111111]">
                        <td class="py-2 px-3 font-mono text-[#171717] dark:text-[#ededed]">
                          {row.domain}
                        </td>
                        <td class="py-2 px-3 font-mono text-[#666666] dark:text-[#a1a1aa]">
                          {row.client}
                        </td>
                        <td class="py-2 px-3 font-mono text-[#666666] dark:text-[#a1a1aa]">
                          {row.proto}
                        </td>
                        <td class="py-2 px-3">
                          <span
                            class={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${outcomeStyle(row.outcome)}`}
                          >
                            {row.outcome}
                          </span>
                        </td>
                        <td class="py-2 px-3 text-right font-mono tabular-nums text-[#666666] dark:text-[#a1a1aa]">
                          {row.latency}
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </div>
        </Show>

        <Show when={tab() === "rules"}>
          <div class="space-y-3">
            <label class="block text-xs font-medium text-[#666666] dark:text-[#a1a1aa]">
              {t().ruleTestLabel}
            </label>
            <div class="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={ruleInput()}
                onInput={(e) => evaluateRule(e.currentTarget.value)}
                placeholder={t().ruleTestPlaceholder}
                class="flex-1 h-9 px-3 rounded-lg text-xs font-mono bg-[#fafafa] dark:bg-[#111111] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] focus:outline-none focus:border-[#0070f3]"
              />
              <div class="flex flex-wrap gap-1.5">
                {["ads.doubleclick.net", "github.com", "nas.local.dev", "rust-lang.org"].map(
                  (preset) => (
                    <button
                      type="button"
                      onClick={() => evaluateRule(preset)}
                      class="h-9 px-2.5 rounded-lg text-[11px] font-mono bg-[#f4f4f5] dark:bg-[#161616] hover:bg-[#eaeaea] dark:hover:bg-[#222222] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer"
                    >
                      {preset}
                    </button>
                  ),
                )}
              </div>
            </div>

            <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#111111] p-3 flex items-center gap-2.5 text-xs font-mono">
              <Show when={ruleResult() === "blocked"}>
                <span class="i-ri-forbid-2-line text-rose-500 text-base shrink-0" />
                <span class="text-rose-600 dark:text-rose-400">{t().ruleMatchBlocked}</span>
              </Show>
              <Show when={ruleResult() === "allowed"}>
                <span class="i-ri-checkbox-circle-line text-emerald-500 text-base shrink-0" />
                <span class="text-emerald-600 dark:text-emerald-400">{t().ruleMatchAllowed}</span>
              </Show>
              <Show when={ruleResult() === "rewritten"}>
                <span class="i-ri-arrow-left-right-line text-violet-500 text-base shrink-0" />
                <span class="text-violet-600 dark:text-violet-400">{t().ruleMatchRewritten}</span>
              </Show>
              <Show when={ruleResult() === "clean"}>
                <span class="i-ri-global-line text-sky-500 text-base shrink-0" />
                <span class="text-sky-600 dark:text-sky-400">{t().ruleMatchClean}</span>
              </Show>
            </div>
          </div>
        </Show>
      </div>
    </div>
  );
}
