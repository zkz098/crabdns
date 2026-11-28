import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import { t, type TranslationKey } from "../i18n";
import type { DiagnosticCategory } from "../types/DiagnosticCategory";
import type { DiagnosticItem } from "../types/DiagnosticItem";
import type { DiagnosticStatus } from "../types/DiagnosticStatus";
import type { DomainTraceResponse } from "../types/DomainTraceResponse";
import type { SystemDiagnosticsResponse } from "../types/SystemDiagnosticsResponse";

const ITEM_TITLE_KEYS: Record<string, TranslationKey> = {
  mdns_port_conflict: "diagItemMdnsConflict",
  loopback_probe: "diagItemLoopbackProbe",
  system_dns_takeover: "diagItemSystemDns",
  udp_inflight_drops: "diagItemUdpDrops",
  upstream_health: "diagItemUpstreamHealth",
  bootstrap_dns: "diagItemBootstrapDns",
  forwarding_loop: "diagItemForwardingLoop",
  webui_auth: "diagItemWebuiAuth",
  tls_cert_health: "diagItemTlsCert",
  open_resolver_risk: "diagItemOpenResolver",
  dnssec_clock: "diagItemDnssecClock",
  local_data_sources: "diagItemLocalSources",
  data_dir_storage: "diagItemDataStorage",
  cache_config: "diagItemCacheConfig",
};

const TRACE_QTYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "HTTPS", "PTR"] as const;

function categoryLabel(category: DiagnosticCategory): string {
  switch (category) {
    case "listener":
      return t("diagCatListener");
    case "upstream":
      return t("diagCatUpstream");
    case "security":
      return t("diagCatSecurity");
    case "storage":
      return t("diagCatStorage");
  }
}

function traceStageLabel(stage: string): string {
  switch (stage) {
    case "filter":
      return t("diagTraceStageFilter");
    case "routing":
      return t("diagTraceStageRouting");
    case "result":
      return t("diagTraceStageResult");
    default:
      return stage;
  }
}

function statusBadgeClass(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20";
    case "warn":
      return "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20";
    case "error":
      return "bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20";
  }
}

function statusDotClass(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return "bg-emerald-500";
    case "warn":
      return "bg-amber-500";
    case "error":
      return "bg-rose-500";
  }
}

function statusLabel(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return t("diagStatusOk");
    case "warn":
      return t("diagStatusWarn");
    case "error":
      return t("diagStatusError");
  }
}

function itemTitle(id: string): string {
  const key = ITEM_TITLE_KEYS[id];
  return key ? t(key) : id;
}

function formatCheckedTime(ms: number): string {
  if (!ms) return "-";
  return new Date(ms).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function DiagnosticsView(props: { onNavigateTab?: (tab: string) => void } = {}) {
  const [report, setReport] = createSignal<SystemDiagnosticsResponse | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal("");

  const [traceDomain, setTraceDomain] = createSignal("");
  const [traceQtype, setTraceQtype] = createSignal<string>("A");
  const [traceLoading, setTraceLoading] = createSignal(false);
  const [traceError, setTraceError] = createSignal("");
  const [traceResult, setTraceResult] = createSignal<DomainTraceResponse | null>(null);

  async function runDiagnostics() {
    setLoading(true);
    setErrorMsg("");
    try {
      const res = await fetch("/api/system/diagnostics", { method: "POST" });
      if (!res.ok) {
        setErrorMsg(t("diagFailed"));
        return;
      }
      const data: SystemDiagnosticsResponse = await res.json();
      setReport(data);
    } catch {
      setErrorMsg(t("diagFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function runDomainTrace(e: Event) {
    e.preventDefault();
    const domain = traceDomain().trim();
    if (!domain) return;
    setTraceLoading(true);
    setTraceError("");
    try {
      const res = await fetch("/api/system/diagnostics/trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, qtype: traceQtype() }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setTraceError(body?.error || t("diagTraceFailed"));
        return;
      }
      const data: DomainTraceResponse = await res.json();
      setTraceResult(data);
    } catch {
      setTraceError(t("diagTraceFailed"));
    } finally {
      setTraceLoading(false);
    }
  }

  onMount(() => {
    void runDiagnostics();
  });

  const errorItems = createMemo(() =>
    (report()?.items ?? []).filter((item) => item.status === "error"),
  );
  const warnItems = createMemo(() =>
    (report()?.items ?? []).filter((item) => item.status === "warn"),
  );
  const infoItems = createMemo(() =>
    (report()?.items ?? []).filter((item) => item.status === "ok"),
  );

  return (
    <div class="space-y-5 sm:space-y-6 animate-view-enter">
      {/* System Status Overview Header */}
      <div class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="space-y-1">
            <div class="flex flex-wrap items-center gap-2.5">
              <h2 class="text-base sm:text-lg font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
                {t("diagTitle")}
              </h2>
              <Show when={report()}>
                {(r) => (
                  <span
                    class={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${statusBadgeClass(r().overall)}`}
                  >
                    <span class={`w-1.5 h-1.5 rounded-full ${statusDotClass(r().overall)}`} />
                    {statusLabel(r().overall)}
                  </span>
                )}
              </Show>
            </div>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("diagOverviewSubtitle")}</p>
          </div>

          <button
            type="button"
            disabled={loading()}
            onClick={() => void runDiagnostics()}
            class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] dark:bg-white hover:bg-[#333333] dark:hover:bg-[#e5e5e5] disabled:opacity-50 text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer transition-all duration-150 shrink-0"
          >
            <span class={`i-ri-heart-pulse-line text-sm ${loading() ? "animate-pulse" : ""}`} />
            <span>{loading() ? t("diagRunning") : t("diagRunBtn")}</span>
          </button>
        </div>

        <Show when={errorMsg()}>
          <div class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-400">
            {errorMsg()}
          </div>
        </Show>

        <Show when={report()}>
          {(r) => (
            <>
              {/* Summary KPI Bar */}
              <div class="grid grid-cols-3 gap-3">
                <SummaryCounter
                  label={t("diagCountErrors")}
                  count={errorItems().length}
                  icon="i-ri-close-circle-line"
                  tone="error"
                />
                <SummaryCounter
                  label={t("diagCountWarnings")}
                  count={warnItems().length}
                  icon="i-ri-alert-line"
                  tone="warn"
                />
                <SummaryCounter
                  label={t("diagCountInfo")}
                  count={infoItems().length}
                  icon="i-ri-checkbox-circle-line"
                  tone="ok"
                />
              </div>

              {/* Health Metrics Cards */}
              <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <HealthMetricCard
                  label={t("diagMetricAvgResponse")}
                  value={
                    r().metrics.avg_response_ms !== null
                      ? `${r().metrics.avg_response_ms!.toFixed(1)} ms`
                      : "-"
                  }
                  subLabel={`${r().metrics.total_queries.toLocaleString()} ${t("diagMetricQueriesUnit")}`}
                  icon="i-ri-speed-up-line"
                  tone={
                    r().metrics.avg_response_ms === null
                      ? "neutral"
                      : r().metrics.avg_response_ms! >= 200
                        ? "error"
                        : r().metrics.avg_response_ms! >= 50
                          ? "warn"
                          : "ok"
                  }
                />
                <HealthMetricCard
                  label={t("diagMetricUpstreamLatency")}
                  value={
                    r().metrics.upstream_avg_latency_ms !== null
                      ? `${r().metrics.upstream_avg_latency_ms} ms`
                      : "-"
                  }
                  subLabel={
                    r().metrics.upstream_avg_latency_ms === null ? t("diagMetricNoData") : "EWMA"
                  }
                  icon="i-ri-pulse-line"
                  tone={
                    r().metrics.upstream_avg_latency_ms === null
                      ? "neutral"
                      : r().metrics.upstream_avg_latency_ms! >= 400
                        ? "error"
                        : r().metrics.upstream_avg_latency_ms! >= 150
                          ? "warn"
                          : "ok"
                  }
                />
                <HealthMetricCard
                  label={t("diagMetricCacheHitRate")}
                  value={
                    r().metrics.cache_hit_rate_pct !== null
                      ? `${r().metrics.cache_hit_rate_pct!.toFixed(1)}%`
                      : "-"
                  }
                  subLabel={`${r().metrics.cache_entries.toLocaleString()} ${t("diagMetricCachedEntries")}`}
                  icon="i-ri-database-2-line"
                  tone={
                    r().metrics.cache_hit_rate_pct === null
                      ? "neutral"
                      : r().metrics.cache_hit_rate_pct! < 20
                        ? "warn"
                        : "ok"
                  }
                />
                <HealthMetricCard
                  label={t("diagMetricErrorRate")}
                  value={
                    r().metrics.error_rate_pct !== null
                      ? `${r().metrics.error_rate_pct!.toFixed(2)}%`
                      : "-"
                  }
                  subLabel={
                    r().metrics.error_rate_pct === null ? t("diagMetricNoData") : "SERVFAIL / Error"
                  }
                  icon="i-ri-shield-check-line"
                  tone={
                    r().metrics.error_rate_pct === null
                      ? "neutral"
                      : r().metrics.error_rate_pct! >= 5
                        ? "error"
                        : r().metrics.error_rate_pct! >= 1
                          ? "warn"
                          : "ok"
                  }
                />
              </div>

              {/* Metadata Row */}
              <div class="flex flex-wrap items-center gap-x-5 gap-y-1.5 pt-1 border-t border-[#eaeaea] dark:border-[#262626] text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                <span class="inline-flex items-center gap-1.5">
                  <span class="i-ri-server-line text-xs" />
                  <span>{t("diagListenAddr")}:</span>
                  <span class="font-mono text-[#171717] dark:text-[#ededed]">{r().listen_dns}</span>
                </span>
                <span class="inline-flex items-center gap-1.5">
                  <span class="i-ri-time-line text-xs" />
                  <span>{t("diagLastChecked")}:</span>
                  <span class="font-mono text-[#171717] dark:text-[#ededed]">
                    {formatCheckedTime(r().checked_at_ms)}
                  </span>
                </span>
              </div>
            </>
          )}
        </Show>
      </div>

      {/* All-clear notice when no errors or warnings */}
      <Show when={report() && errorItems().length === 0 && warnItems().length === 0}>
        <div class="animate-card-enter rounded-xl border border-emerald-500/25 bg-emerald-500/5 px-4 py-3.5 flex items-start gap-3">
          <span class="i-ri-shield-check-fill text-lg text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
          <div class="space-y-0.5">
            <p class="text-sm font-medium text-emerald-800 dark:text-emerald-300">
              {t("diagAllClearTitle")}
            </p>
            <p class="text-xs text-emerald-700/80 dark:text-emerald-400/80">
              {t("diagAllClearDesc")}
            </p>
          </div>
        </div>
      </Show>

      {/* 1. Errors Section (Top) */}
      <Show when={errorItems().length > 0}>
        <SeveritySection
          title={t("diagSectionErrors")}
          severity="error"
          items={errorItems()}
          delay={60}
          onNavigateTab={props.onNavigateTab}
        />
      </Show>

      {/* 2. Warnings Section (Middle) */}
      <Show when={warnItems().length > 0}>
        <SeveritySection
          title={t("diagSectionWarnings")}
          severity="warn"
          items={warnItems()}
          delay={120}
          onNavigateTab={props.onNavigateTab}
        />
      </Show>

      {/* 3. Information / Healthy Section (Bottom) */}
      <Show when={infoItems().length > 0}>
        <SeveritySection
          title={t("diagSectionInfo")}
          severity="ok"
          items={infoItems()}
          delay={180}
          onNavigateTab={props.onNavigateTab}
        />
      </Show>

      {/* 4. Single-Domain Resolution Trace */}
      <section
        class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3.5"
        style={{ "animation-delay": "220ms" }}
      >
        <div class="space-y-0.5">
          <div class="flex items-center gap-2">
            <span class="i-ri-route-line text-base text-[#171717] dark:text-[#ededed]" />
            <h3 class="text-sm font-semibold text-[#171717] dark:text-[#ededed]">
              {t("diagTraceTitle")}
            </h3>
          </div>
          <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("diagTraceSubtitle")}</p>
        </div>

        <form onSubmit={(e) => void runDomainTrace(e)} class="flex flex-wrap sm:flex-nowrap gap-2">
          <input
            type="text"
            value={traceDomain()}
            onInput={(e) => setTraceDomain(e.currentTarget.value)}
            placeholder={t("diagTracePlaceholder")}
            class="flex-1 min-w-[180px] h-8.5 px-3 rounded-lg border border-[#e5e5e5] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-xs font-mono text-[#171717] dark:text-[#ededed] placeholder:text-[#999999] focus:outline-none focus:ring-1 focus:ring-[#171717] dark:focus:ring-white"
          />
          <select
            value={traceQtype()}
            onChange={(e) => setTraceQtype(e.currentTarget.value)}
            class="h-8.5 px-2.5 rounded-lg border border-[#e5e5e5] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-xs font-mono text-[#171717] dark:text-[#ededed] focus:outline-none"
          >
            <For each={TRACE_QTYPES}>{(qt) => <option value={qt}>{qt}</option>}</For>
          </select>
          <button
            type="submit"
            disabled={traceLoading() || !traceDomain().trim()}
            class="h-8.5 px-3.5 rounded-lg text-xs font-medium bg-[#171717] dark:bg-white hover:bg-[#333333] dark:hover:bg-[#e5e5e5] disabled:opacity-50 text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer transition-all duration-150 shrink-0"
          >
            <span class={`i-ri-play-line text-sm ${traceLoading() ? "animate-spin" : ""}`} />
            <span>{traceLoading() ? t("diagTraceRunning") : t("diagTraceBtn")}</span>
          </button>
        </form>

        <Show when={traceError()}>
          <div class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-400">
            {traceError()}
          </div>
        </Show>

        <Show when={traceResult()}>
          {(tr) => (
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="font-mono text-xs font-semibold text-[#171717] dark:text-[#ededed]">
                    {tr().domain}
                  </span>
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#eaeaea]/80 dark:bg-[#1f1f1f] text-[#52525b] dark:text-[#a1a1aa]">
                    {tr().qtype}
                  </span>
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                    {tr().outcome} · {tr().rcode}
                  </span>
                </div>
                <span class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums">
                  {tr().elapsed_ms.toFixed(1)} ms
                </span>
              </div>

              <div class="space-y-1.5">
                <For each={tr().steps}>
                  {(step, idx) => (
                    <div class="flex items-start gap-2 text-xs">
                      <span
                        class={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${statusDotClass(step.status)}`}
                      />
                      <span class="font-medium text-[#52525b] dark:text-[#a1a1aa] shrink-0">
                        {idx() + 1}. {traceStageLabel(step.stage)}:
                      </span>
                      <span class="text-[#171717] dark:text-[#ededed] break-all">
                        {step.detail}
                      </span>
                    </div>
                  )}
                </For>
              </div>

              <div class="pt-2 border-t border-[#eaeaea] dark:border-[#262626] space-y-1">
                <div class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
                  {t("diagTraceAnswers")}
                </div>
                <Show
                  when={tr().answers.length > 0}
                  fallback={
                    <p class="text-xs text-[#888888] dark:text-[#71717a]">
                      {t("diagTraceNoAnswers")}
                    </p>
                  }
                >
                  <div class="flex flex-wrap gap-1.5">
                    <For each={tr().answers}>
                      {(ans) => (
                        <span class="font-mono text-[11px] px-2 py-0.5 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed]">
                          {ans}
                        </span>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
            </div>
          )}
        </Show>
      </section>
    </div>
  );
}

function HealthMetricCard(props: {
  label: string;
  value: string;
  subLabel: string;
  icon: string;
  tone: DiagnosticStatus | "neutral";
}) {
  const valueClass = () => {
    switch (props.tone) {
      case "ok":
        return "text-emerald-700 dark:text-emerald-400";
      case "warn":
        return "text-amber-700 dark:text-amber-400";
      case "error":
        return "text-rose-700 dark:text-rose-400";
      case "neutral":
        return "text-[#171717] dark:text-[#ededed]";
    }
  };

  return (
    <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2.5 space-y-1">
      <div class="flex items-center justify-between gap-1.5 text-[#666666] dark:text-[#a1a1aa]">
        <span class="text-[11px] font-medium truncate">{props.label}</span>
        <span class={`${props.icon} text-sm shrink-0`} />
      </div>
      <div class={`text-base sm:text-lg font-semibold font-mono tabular-nums ${valueClass()}`}>
        {props.value}
      </div>
      <div class="text-[11px] text-[#888888] dark:text-[#71717a] truncate">{props.subLabel}</div>
    </div>
  );
}

function SummaryCounter(props: {
  label: string;
  count: number;
  icon: string;
  tone: DiagnosticStatus;
}) {
  const toneClass = () => {
    switch (props.tone) {
      case "error":
        return props.count > 0
          ? "border-rose-500/30 bg-rose-500/8 text-rose-700 dark:text-rose-400"
          : "border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-[#666666] dark:text-[#a1a1aa]";
      case "warn":
        return props.count > 0
          ? "border-amber-500/30 bg-amber-500/8 text-amber-700 dark:text-amber-400"
          : "border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-[#666666] dark:text-[#a1a1aa]";
      case "ok":
        return "border-emerald-500/25 bg-emerald-500/8 text-emerald-700 dark:text-emerald-400";
    }
  };

  return (
    <div
      class={`rounded-lg border px-3 py-2.5 flex items-center justify-between gap-2 ${toneClass()}`}
    >
      <div class="flex items-center gap-2 min-w-0">
        <span class={`${props.icon} text-base shrink-0`} />
        <span class="text-xs font-medium truncate">{props.label}</span>
      </div>
      <span class="text-base sm:text-lg font-semibold tabular-nums">{props.count}</span>
    </div>
  );
}

function SeveritySection(props: {
  title: string;
  severity: DiagnosticStatus;
  items: DiagnosticItem[];
  delay: number;
  onNavigateTab?: (tab: string) => void;
}) {
  const headerAccent = () => {
    switch (props.severity) {
      case "error":
        return {
          icon: "i-ri-error-warning-fill text-rose-500",
          border: "border-rose-500/30 dark:border-rose-500/25",
          badge: "bg-rose-500/10 text-rose-700 dark:text-rose-400",
        };
      case "warn":
        return {
          icon: "i-ri-alert-fill text-amber-500",
          border: "border-amber-500/30 dark:border-amber-500/25",
          badge: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
        };
      case "ok":
        return {
          icon: "i-ri-information-line text-emerald-500",
          border: "border-[#eaeaea] dark:border-[#262626]",
          badge: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
        };
    }
  };

  const hintClass = () => {
    switch (props.severity) {
      case "error":
        return "text-rose-700 dark:text-rose-300 bg-rose-500/8 border-rose-500/20";
      case "warn":
        return "text-amber-700 dark:text-amber-300 bg-amber-500/8 border-amber-500/20";
      case "ok":
        return "text-[#666666] dark:text-[#a1a1aa] bg-[#f4f4f5] dark:bg-[#141414] border-[#eaeaea] dark:border-[#262626]";
    }
  };

  return (
    <section
      class={`animate-card-enter rounded-xl border ${headerAccent().border} bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3`}
      style={{ "animation-delay": `${props.delay}ms` }}
    >
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <span class={`${headerAccent().icon} text-base`} />
          <h3 class="text-sm font-semibold text-[#171717] dark:text-[#ededed]">{props.title}</h3>
        </div>
        <span
          class={`px-2 py-0.5 rounded-full text-[11px] font-medium tabular-nums ${headerAccent().badge}`}
        >
          {props.items.length}
        </span>
      </div>

      <div class="space-y-2.5">
        <For each={props.items}>
          {(item) => (
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                  <span class={`w-2 h-2 rounded-full shrink-0 ${statusDotClass(item.status)}`} />
                  <span class="text-xs sm:text-sm font-medium text-[#171717] dark:text-[#ededed]">
                    {itemTitle(item.id)}
                  </span>
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#eaeaea]/70 dark:bg-[#1f1f1f] text-[#666666] dark:text-[#a1a1aa]">
                    {categoryLabel(item.category)}
                  </span>
                </div>
                <span class="font-mono text-[11px] text-[#52525b] dark:text-[#a1a1aa] bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] px-2 py-0.5 rounded">
                  {item.summary}
                </span>
              </div>

              <Show when={item.detail}>
                {(detail) => (
                  <p class="text-xs text-[#666666] dark:text-[#a1a1aa] pl-4">{detail()}</p>
                )}
              </Show>

              <Show when={item.hint}>
                {(hint) => (
                  <div
                    class={`ml-4 rounded-md border px-2.5 py-1.5 text-[11px] flex flex-wrap items-center justify-between gap-2 ${hintClass()}`}
                  >
                    <div class="flex items-start gap-1.5 min-w-0">
                      <span class="i-ri-lightbulb-line text-xs shrink-0 mt-0.5" />
                      <span>{hint()}</span>
                    </div>
                    <Show when={item.action_tab && props.onNavigateTab}>
                      <button
                        type="button"
                        onClick={() => props.onNavigateTab?.(item.action_tab!)}
                        class="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/80 dark:bg-[#0a0a0a]/80 border border-current/20 font-medium hover:opacity-80 cursor-pointer shrink-0 transition-opacity"
                      >
                        <span>{t("diagActionFix")}</span>
                        <span class="i-ri-arrow-right-line text-xs" />
                      </button>
                    </Show>
                  </div>
                )}
              </Show>
            </div>
          )}
        </For>
      </div>
    </section>
  );
}
