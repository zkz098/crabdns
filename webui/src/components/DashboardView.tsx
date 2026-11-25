import { createMemo, createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import { SystemDiagnosticsCard } from "./SystemDiagnosticsCard";
import type { StatsResponse } from "../types/StatsResponse";
import type { TimeSeriesPoint } from "../types/TimeSeriesPoint";
import type { TopItem } from "../types/TopItem";

interface DashboardViewProps {
  stats: StatsResponse | null;
  clientNameMap?: Record<string, string>;
  onFlushCache?: () => Promise<void> | void;
  cacheFlushedMsg?: string;
  onResetStats?: () => Promise<void> | void;
  statsResetMsg?: string;
}

export function DashboardView(props: DashboardViewProps) {
  const s = () => props.stats?.stats;
  const filter = () => props.stats?.filter;
  const cacheEntries = () => props.stats?.cache_entries ?? 0;
  const cacheStats = () => props.stats?.cache_stats;

  const total = () => s()?.total_queries ?? 0;
  const blocked = () => s()?.blocked_queries ?? 0;
  const cached = () => s()?.cached_queries ?? 0;
  const rewritten = () => s()?.rewritten_queries ?? 0;
  const errors = () => s()?.error_queries ?? 0;
  const forwarded = () => Math.max(0, total() - blocked() - cached() - rewritten() - errors());

  const pct = (part: number) => {
    const tVal = total();
    if (tVal === 0) return 0;
    return Math.min(100, Math.max(0, (part / tVal) * 100));
  };

  const blockRate = () => `${pct(blocked()).toFixed(1)}%`;
  const hitRate = () => {
    const cs = cacheStats();
    if (cs && cs.hits + cs.misses > 0) {
      return `${(cs.hit_rate * 100).toFixed(1)}%`;
    }
    return `${pct(cached()).toFixed(1)}%`;
  };

  const series = () => s()?.timeseries_24h ?? [];

  return (
    <div class="space-y-5 sm:space-y-6 animate-view-enter">
      {/* KPI Cards */}
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <StatCard
          delay={0}
          title={t("statTotalQueries")}
          value={total().toLocaleString()}
          sub={`${cacheEntries().toLocaleString()} ${t("statCacheEntries").toLowerCase()}`}
          icon="i-ri-global-line"
          accent="text-sky-600 dark:text-sky-400 bg-sky-500/10"
        />
        <StatCard
          delay={60}
          title={t("statBlocked")}
          value={blocked().toLocaleString()}
          sub={`${t("statBlockRate")} ${blockRate()}`}
          icon="i-ri-forbid-2-line"
          accent="text-rose-600 dark:text-rose-400 bg-rose-500/10"
        />
        <StatCard
          delay={120}
          title={t("statCacheHits")}
          value={cached().toLocaleString()}
          sub={`${t("statHitRate")} ${hitRate()}`}
          icon="i-ri-flashlight-line"
          accent="text-amber-600 dark:text-amber-400 bg-amber-500/10"
        />
        <StatCard
          delay={180}
          title={t("statActiveRules")}
          value={(filter()?.total_rules ?? 0).toLocaleString()}
          sub={`${filter()?.block_rules ?? 0} ${t("filterBlockRules")} · ${filter()?.allow_rules ?? 0} ${t("filterAllowRules")}`}
          icon="i-ri-shield-keyhole-line"
          accent="text-emerald-600 dark:text-emerald-400 bg-emerald-500/10"
        />
      </div>

      {/* 24-Hour Time-Series Chart */}
      <TimeSeriesChart points={series()} />

      {/* System Health Check */}
      <SystemDiagnosticsCard />

      {/* Query Distribution Bar */}
      <div
        class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3.5 transition-colors hover:border-[#d4d4d8] dark:hover:border-[#3a3a3a]"
        style={{ "animation-delay": "140ms" }}
      >
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h2 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
            {t("queryDistribution")}
          </h2>
          <div class="flex flex-wrap items-center gap-2">
            <Show when={props.cacheFlushedMsg || props.statsResetMsg}>
              <span class="text-xs text-emerald-600 dark:text-emerald-400">
                {props.cacheFlushedMsg || props.statsResetMsg}
              </span>
            </Show>
            <Show when={props.onFlushCache}>
              <button
                type="button"
                onClick={() => props.onFlushCache?.()}
                class="h-7 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-150"
              >
                <span class="i-ri-delete-bin-6-line text-xs" />
                <span>{t("cacheFlushBtn")}</span>
              </button>
            </Show>
            <Show when={props.onResetStats}>
              <button
                type="button"
                onClick={() => props.onResetStats?.()}
                class="h-7 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-rose-50 dark:hover:bg-rose-950/30 text-[#666666] hover:text-rose-600 dark:text-[#a1a1aa] dark:hover:text-rose-400 border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-150"
              >
                <span class="i-ri-restart-line text-xs" />
                <span>{t("statsResetBtn")}</span>
              </button>
            </Show>
            <span class="text-xs text-[#666666] dark:text-[#a1a1aa] tabular-nums">
              {total().toLocaleString()} {t("logsCountSuffix")}
            </span>
          </div>
        </div>

        <div class="h-2.5 w-full rounded-full overflow-hidden bg-[#f4f4f5] dark:bg-[#171717] flex">
          <Show when={total() > 0}>
            <div
              class="h-full bg-sky-500 transition-[width] duration-500 ease-out"
              style={{ width: `${pct(forwarded())}%` }}
            />
            <div
              class="h-full bg-amber-500 transition-[width] duration-500 ease-out"
              style={{ width: `${pct(cached())}%` }}
            />
            <div
              class="h-full bg-rose-500 transition-[width] duration-500 ease-out"
              style={{ width: `${pct(blocked())}%` }}
            />
            <div
              class="h-full bg-violet-500 transition-[width] duration-500 ease-out"
              style={{ width: `${pct(rewritten())}%` }}
            />
            <div
              class="h-full bg-red-600 transition-[width] duration-500 ease-out"
              style={{ width: `${pct(errors())}%` }}
            />
          </Show>
        </div>

        <div class="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-[#666666] dark:text-[#a1a1aa]">
          <LegendItem color="bg-sky-500" label={t("distForwarded")} count={forwarded()} />
          <LegendItem color="bg-amber-500" label={t("distCached")} count={cached()} />
          <LegendItem color="bg-rose-500" label={t("distBlocked")} count={blocked()} />
          <LegendItem color="bg-violet-500" label={t("distRewritten")} count={rewritten()} />
          <LegendItem color="bg-red-600" label={t("distError")} count={errors()} />
        </div>
      </div>

      {/* Top Lists */}
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <TopListCard
          delay={180}
          title={t("topBlockedDomains")}
          items={s()?.top_blocked ?? []}
          barColor="bg-rose-500/12 dark:bg-rose-500/15"
        />
        <TopListCard
          delay={230}
          title={t("topQueriedDomains")}
          items={s()?.top_domains ?? []}
          barColor="bg-sky-500/12 dark:bg-sky-500/15"
        />
        <TopListCard
          delay={280}
          title={t("topClients")}
          items={s()?.top_clients ?? []}
          nameMap={props.clientNameMap}
          barColor="bg-emerald-500/12 dark:bg-emerald-500/15"
        />
      </div>
    </div>
  );
}

function TimeSeriesChart(props: { points: TimeSeriesPoint[] }) {
  const [hoverIdx, setHoverIdx] = createSignal<number | null>(null);

  const normalized = createMemo<TimeSeriesPoint[]>(() => {
    if (props.points.length > 0) return props.points;
    const nowHour = Math.floor(Date.now() / 3_600_000) * 3_600_000;
    return Array.from({ length: 24 }, (_, idx) => ({
      timestamp_ms: nowHour - (23 - idx) * 3_600_000,
      total: 0,
      blocked: 0,
      cached: 0,
      rewritten: 0,
      error: 0,
    }));
  });

  const maxBucket = createMemo(() => Math.max(1, ...normalized().map((p) => p.total)));

  const hoveredPoint = createMemo(() => {
    const idx = hoverIdx();
    if (idx === null) return null;
    return normalized()[idx] ?? null;
  });

  const formatHour = (ms: number) => {
    const d = new Date(ms);
    return `${String(d.getHours()).padStart(2, "0")}:00`;
  };

  return (
    <div
      class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3.5 transition-colors hover:border-[#d4d4d8] dark:hover:border-[#3a3a3a]"
      style={{ "animation-delay": "100ms" }}
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
            {t("chart24hTitle")}
          </h2>
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-0.5">
            {t("chart24hSubtitle")}
          </p>
        </div>

        <Show
          when={hoveredPoint()}
          fallback={
            <div class="flex items-center gap-3 text-xs text-[#666666] dark:text-[#a1a1aa]">
              <span class="inline-flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-sky-500/80" />
                {t("chartTotalLabel")}
              </span>
              <span class="inline-flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-amber-500/85" />
                {t("chartCachedLabel")}
              </span>
              <span class="inline-flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full bg-rose-500" />
                {t("chartBlockedLabel")}
              </span>
            </div>
          }
        >
          {(pt) => (
            <div class="flex flex-wrap items-center gap-3 text-xs font-mono tabular-nums bg-[#fafafa] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 py-1">
              <span class="text-[#171717] dark:text-[#ededed] font-semibold">
                {formatHour(pt().timestamp_ms)}
              </span>
              <span class="text-sky-600 dark:text-sky-400">
                {t("chartTotalLabel")}: {pt().total.toLocaleString()}
              </span>
              <span class="text-amber-600 dark:text-amber-400">
                {t("chartCachedLabel")}: {pt().cached.toLocaleString()}
              </span>
              <span class="text-rose-600 dark:text-rose-400">
                {t("chartBlockedLabel")}: {pt().blocked.toLocaleString()}
              </span>
            </div>
          )}
        </Show>
      </div>

      {/* 24 Hourly Columns */}
      <div class="pt-2">
        <div
          class="h-32 sm:h-36 flex items-end gap-1 sm:gap-1.5 border-b border-[#eaeaea] dark:border-[#262626] pb-1.5"
          onMouseLeave={() => setHoverIdx(null)}
        >
          <For each={normalized()}>
            {(pt, idx) => {
              const totalPct = () =>
                pt.total === 0 ? 0 : Math.max(6, Math.round((pt.total / maxBucket()) * 100));
              const blockedPctOfBar = () =>
                pt.total === 0 ? 0 : Math.min(100, Math.round((pt.blocked / pt.total) * 100));
              const cachedPctOfBar = () =>
                pt.total === 0
                  ? 0
                  : Math.min(100 - blockedPctOfBar(), Math.round((pt.cached / pt.total) * 100));

              return (
                <div
                  class="flex-1 h-full flex flex-col justify-end items-center group cursor-pointer"
                  onMouseEnter={() => setHoverIdx(idx())}
                >
                  <div class="w-full h-full flex items-end justify-center">
                    <Show
                      when={pt.total > 0}
                      fallback={
                        <div class="w-full max-w-[18px] h-1 rounded-t bg-[#f4f4f5] dark:bg-[#1a1a1a] group-hover:bg-[#d4d4d8] dark:group-hover:bg-[#333333] transition-colors" />
                      }
                    >
                      <div
                        class="w-full max-w-[18px] rounded-t-md overflow-hidden flex flex-col justify-end bg-sky-500/75 dark:bg-sky-500/70 group-hover:brightness-110 transition-all duration-300"
                        style={{ height: `${totalPct()}%` }}
                      >
                        <div
                          class="w-full bg-amber-500/85 transition-all duration-300"
                          style={{ height: `${cachedPctOfBar()}%` }}
                        />
                        <div
                          class="w-full bg-rose-500 transition-all duration-300"
                          style={{ height: `${blockedPctOfBar()}%` }}
                        />
                      </div>
                    </Show>
                  </div>
                </div>
              );
            }}
          </For>
        </div>

        {/* X-Axis Hour Labels */}
        <div class="flex items-center justify-between text-[10px] font-mono text-[#8f8f8f] dark:text-[#71717a] pt-1.5 tabular-nums">
          <For each={normalized()}>
            {(pt, idx) => (
              <div class="flex-1 text-center">
                <Show when={idx() % 4 === 0 || idx() === 23}>
                  <span>{formatHour(pt.timestamp_ms)}</span>
                </Show>
              </div>
            )}
          </For>
        </div>
      </div>
    </div>
  );
}

function StatCard(props: {
  title: string;
  value: string;
  sub: string;
  icon: string;
  accent: string;
  delay: number;
}) {
  return (
    <div
      class="animate-card-enter group rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 transition-all duration-200 hover:border-[#d4d4d8] dark:hover:border-[#404040] hover:-translate-y-0.5 hover:shadow-sm"
      style={{ "animation-delay": `${props.delay}ms` }}
    >
      <div class="flex items-center justify-between gap-2">
        <p class="text-xs font-medium text-[#666666] dark:text-[#a1a1aa] truncate">{props.title}</p>
        <span
          class={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 transition-transform duration-200 group-hover:scale-110 ${props.accent}`}
        >
          <span class={`${props.icon} text-sm`} />
        </span>
      </div>
      <p class="text-xl sm:text-2xl font-semibold tracking-tight text-[#171717] dark:text-[#ededed] mt-2 tabular-nums">
        {props.value}
      </p>
      <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-1 truncate tabular-nums">
        {props.sub}
      </p>
    </div>
  );
}

function LegendItem(props: { color: string; label: string; count: number }) {
  return (
    <div class="flex items-center gap-1.5 tabular-nums">
      <span class={`w-2 h-2 rounded-full ${props.color}`} />
      <span>{props.label}</span>
      <span class="font-medium text-[#171717] dark:text-[#ededed]">
        {props.count.toLocaleString()}
      </span>
    </div>
  );
}

function TopListCard(props: {
  title: string;
  items: TopItem[];
  barColor: string;
  delay: number;
  nameMap?: Record<string, string>;
}) {
  const maxCount = () => Math.max(1, ...props.items.map((item) => item.count));

  return (
    <div
      class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3.5 transition-colors hover:border-[#d4d4d8] dark:hover:border-[#3a3a3a]"
      style={{ "animation-delay": `${props.delay}ms` }}
    >
      <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">{props.title}</h3>
      <Show
        when={props.items.length > 0}
        fallback={
          <p class="text-xs text-[#8f8f8f] dark:text-[#71717a] py-2">{t("noDataRecorded")}</p>
        }
      >
        <div class="space-y-1.5">
          <For each={props.items}>
            {(item) => {
              const widthPct = () => `${Math.max(4, (item.count / maxCount()) * 100)}%`;
              const mappedName = () => props.nameMap?.[item.name];
              return (
                <div class="relative overflow-hidden rounded-lg px-2.5 py-1.5 flex items-center justify-between gap-3 text-xs group">
                  <div
                    class={`absolute inset-y-0 left-0 rounded-lg transition-[width] duration-500 ease-out ${props.barColor}`}
                    style={{ width: widthPct() }}
                  />
                  <span
                    class="relative font-mono text-[#171717] dark:text-[#ededed] truncate"
                    title={item.name}
                  >
                    <Show when={mappedName()} fallback={item.name}>
                      {(name) => (
                        <>
                          <span class="font-sans font-medium">{name()}</span>{" "}
                          <span class="text-[#8f8f8f] dark:text-[#71717a]">({item.name})</span>
                        </>
                      )}
                    </Show>
                  </span>
                  <span class="relative font-mono text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {item.count.toLocaleString()}
                  </span>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
