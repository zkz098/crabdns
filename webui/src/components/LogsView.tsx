import { createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { QueryEvent } from "../types/QueryEvent";
import { OutcomeBadge } from "./OutcomeBadge";
import { SelectMenu, type SelectOption } from "./SelectMenu";

interface LogsViewProps {
  logs: QueryEvent[];
  search: string;
  onSearchChange: (val: string) => void;
  outcomeFilter: string;
  onOutcomeChange: (val: string) => void;
  protocolFilter: string;
  onProtocolChange: (val: string) => void;
  qtypeFilter: string;
  onQtypeChange: (val: string) => void;
  clientFilter: string;
  onClientChange: (val: string) => void;
  onRefresh: () => Promise<void> | void;
  onClearLogs?: () => Promise<void> | void;
  onExportLogs?: () => void;
  onQuickRule?: (domain: string, action: "allow" | "block") => Promise<void> | void;
  quickRuleMsg?: string;
}

const OUTCOME_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("logsAllOutcomes") },
  { value: "blocked", label: () => t("logsOutcomeBlocked"), dotClass: "bg-rose-500" },
  { value: "cached", label: () => t("logsOutcomeCached"), dotClass: "bg-amber-500" },
  { value: "forwarded", label: () => t("logsOutcomeForwarded"), dotClass: "bg-sky-500" },
  { value: "rewritten", label: () => t("logsOutcomeRewritten"), dotClass: "bg-violet-500" },
  { value: "error", label: () => t("logsOutcomeError"), dotClass: "bg-red-500" },
];

const PROTOCOL_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("logsAllProtocols") },
  { value: "udp", label: () => "UDP" },
  { value: "tcp", label: () => "TCP" },
  { value: "dot", label: () => "DoT" },
  { value: "doq", label: () => "DoQ" },
  { value: "doh3", label: () => "DoH3" },
  { value: "doh", label: () => "DoH" },
];

const QTYPE_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("logsAllTypes") },
  { value: "A", label: () => "A" },
  { value: "AAAA", label: () => "AAAA" },
  { value: "HTTPS", label: () => "HTTPS" },
  { value: "SVCB", label: () => "SVCB" },
  { value: "CNAME", label: () => "CNAME" },
  { value: "TXT", label: () => "TXT" },
  { value: "PTR", label: () => "PTR" },
  { value: "MX", label: () => "MX" },
];

export function LogsView(props: LogsViewProps) {
  const [refreshing, setRefreshing] = createSignal(false);
  const [clearing, setClearing] = createSignal(false);

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await props.onRefresh();
    } finally {
      setTimeout(() => setRefreshing(false), 450);
    }
  }

  async function handleClear() {
    if (!props.onClearLogs) return;
    setClearing(true);
    try {
      await props.onClearLogs();
    } finally {
      setClearing(false);
    }
  }

  return (
    <div class="space-y-4 animate-view-enter">
      {/* Filter Toolbar */}
      <div class="flex flex-col gap-2.5">
        <div class="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          {/* Domain / General Search */}
          <div class="relative flex-1 min-w-0">
            <span class="i-ri-search-line absolute left-3 top-1/2 -translate-y-1/2 text-[#8f8f8f] dark:text-[#71717a] text-sm pointer-events-none" />
            <input
              type="text"
              placeholder={t("logsSearchPlaceholder")}
              value={props.search}
              onInput={(e) => props.onSearchChange(e.currentTarget.value)}
              onKeyDown={(e) => e.key === "Enter" && handleRefresh()}
              class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg pl-9 pr-8 text-sm text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#71717a] outline-none shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
            <Show when={props.search.length > 0}>
              <button
                type="button"
                onClick={() => {
                  props.onSearchChange("");
                  handleRefresh();
                }}
                aria-label="Clear search"
                class="absolute right-2 top-1/2 -translate-y-1/2 w-5 h-5 rounded-md flex items-center justify-center bg-transparent hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed] border-0 cursor-pointer transition-colors"
              >
                <span class="i-ri-close-line text-sm" />
              </button>
            </Show>
          </div>

          {/* Client IP / Name Filter */}
          <div class="relative sm:w-48 shrink-0">
            <span class="i-ri-computer-line absolute left-3 top-1/2 -translate-y-1/2 text-[#8f8f8f] dark:text-[#71717a] text-sm pointer-events-none" />
            <input
              type="text"
              placeholder={t("logsClientFilterPlaceholder")}
              value={props.clientFilter}
              onInput={(e) => props.onClientChange(e.currentTarget.value)}
              onKeyDown={(e) => e.key === "Enter" && handleRefresh()}
              class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg pl-9 pr-7 text-xs font-mono text-[#171717] dark:text-[#ededed] placeholder:font-sans placeholder:text-[#8f8f8f] dark:placeholder:text-[#71717a] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed]"
            />
            <Show when={props.clientFilter.length > 0}>
              <button
                type="button"
                onClick={() => {
                  props.onClientChange("");
                  handleRefresh();
                }}
                aria-label="Clear client filter"
                class="absolute right-1.5 top-1/2 -translate-y-1/2 w-5 h-5 rounded-md flex items-center justify-center bg-transparent hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed] border-0 cursor-pointer transition-colors"
              >
                <span class="i-ri-close-line text-xs" />
              </button>
            </Show>
          </div>
        </div>

        {/* Select Filters & Action Buttons */}
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex flex-wrap items-center gap-2 flex-1 sm:flex-none">
            <SelectMenu
              value={props.outcomeFilter}
              options={OUTCOME_OPTIONS}
              onChange={(val) => {
                props.onOutcomeChange(val);
                handleRefresh();
              }}
              class="w-32 sm:w-36"
            />
            <SelectMenu
              value={props.protocolFilter}
              options={PROTOCOL_OPTIONS}
              onChange={(val) => {
                props.onProtocolChange(val);
                handleRefresh();
              }}
              class="w-28 sm:w-32"
            />
            <SelectMenu
              value={props.qtypeFilter}
              options={QTYPE_OPTIONS}
              onChange={(val) => {
                props.onQtypeChange(val);
                handleRefresh();
              }}
              class="w-28 sm:w-32"
            />
          </div>

          <div class="flex items-center gap-2 shrink-0">
            <Show when={props.onExportLogs && props.logs.length > 0}>
              <button
                type="button"
                onClick={() => props.onExportLogs?.()}
                class="h-9 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors"
              >
                <span class="i-ri-download-2-line text-sm" />
                <span class="hidden sm:inline">{t("logsExportBtn")}</span>
              </button>
            </Show>

            <Show when={props.onClearLogs}>
              <button
                type="button"
                disabled={clearing()}
                onClick={handleClear}
                class="h-9 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#0a0a0a] hover:bg-rose-50 dark:hover:bg-rose-950/30 text-[#666666] hover:text-rose-600 dark:text-[#a1a1aa] dark:hover:text-rose-400 border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
              >
                <span class="i-ri-delete-bin-line text-sm" />
                <span class="hidden sm:inline">{t("logsClearBtn")}</span>
              </button>
            </Show>

            <button
              type="button"
              onClick={handleRefresh}
              class="h-9 px-3.5 rounded-lg text-xs sm:text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center justify-center gap-1.5 cursor-pointer border-0 shadow-sm transition-all duration-200 active:scale-[0.97] shrink-0"
            >
              <span
                class={`i-ri-refresh-line text-sm ${refreshing() ? "animate-spin-once" : ""}`}
              />
              <span>{t("logsRefresh")}</span>
            </button>
          </div>
        </div>
      </div>

      <Show when={props.quickRuleMsg}>
        <div class="text-xs text-emerald-600 dark:text-emerald-400 font-medium">
          {props.quickRuleMsg}
        </div>
      </Show>

      {/* Empty State */}
      <Show
        when={props.logs.length > 0}
        fallback={
          <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-10 text-center shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none">
            <span class="i-ri-terminal-box-line text-2xl text-[#8f8f8f] dark:text-[#71717a] mb-2" />
            <p class="text-sm text-[#666666] dark:text-[#a1a1aa]">{t("logsEmpty")}</p>
          </div>
        }
      >
        {/* Desktop Table */}
        <div class="hidden md:block rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] overflow-hidden shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm border-collapse">
              <thead class="bg-[#fafafa] dark:bg-[#111111] border-b border-[#eaeaea] dark:border-[#262626] text-[#666666] dark:text-[#a1a1aa] text-[11px] font-medium uppercase tracking-wider">
                <tr>
                  <th class="px-4 py-2.5">{t("logsColTime")}</th>
                  <th class="px-4 py-2.5">{t("logsColProtocol")}</th>
                  <th class="px-4 py-2.5">{t("logsColClient")}</th>
                  <th class="px-4 py-2.5">{t("logsColDomain")}</th>
                  <th class="px-4 py-2.5">{t("logsColType")}</th>
                  <th class="px-4 py-2.5">{t("logsColStatus")}</th>
                  <th class="px-4 py-2.5">{t("logsColAnswers")}</th>
                  <th class="px-4 py-2.5 text-right">{t("logsColLatency")}</th>
                  <Show when={props.onQuickRule}>
                    <th class="px-4 py-2.5 text-right" />
                  </Show>
                </tr>
              </thead>
              <tbody class="divide-y divide-[#f0f0f0] dark:divide-[#1a1a1a]">
                <For each={props.logs}>
                  {(entry) => (
                    <tr class="animate-row-enter hover:bg-[#fafafa] dark:hover:bg-[#111111] transition-colors">
                      <td class="px-4 py-2.5 text-xs text-[#666666] dark:text-[#8f8f8f] whitespace-nowrap tabular-nums">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </td>
                      <td class="px-4 py-2.5 whitespace-nowrap">
                        <span class="px-1.5 py-0.5 rounded font-mono text-[10px] font-medium uppercase bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa]">
                          {entry.protocol}
                        </span>
                      </td>
                      <td class="px-4 py-2.5 text-xs whitespace-nowrap">
                        <Show when={entry.client_name}>
                          {(name) => (
                            <div class="font-medium text-[#171717] dark:text-[#ededed] leading-tight">
                              {name()}
                            </div>
                          )}
                        </Show>
                        <div class="font-mono text-[#666666] dark:text-[#a1a1aa] tabular-nums">
                          {entry.client_ip}
                        </div>
                      </td>
                      <td
                        class="px-4 py-2.5 text-xs text-[#171717] dark:text-[#ededed] max-w-xs lg:max-w-md"
                        title={entry.matched_rule ?? entry.upstream ?? entry.domain}
                      >
                        <div class="font-mono truncate">{entry.domain}</div>
                        <Show when={entry.matched_list || entry.matched_rule}>
                          <div class="flex items-center gap-1.5 mt-0.5 text-[10px] text-[#8f8f8f] dark:text-[#71717a] truncate">
                            <Show when={entry.matched_list}>
                              {(listName) => (
                                <span class="px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-700 dark:text-rose-400 border border-rose-500/20 shrink-0">
                                  {t("logsMatchedList")}: {listName()}
                                </span>
                              )}
                            </Show>
                            <Show when={entry.matched_rule}>
                              {(rule) => <span class="font-mono truncate">{rule()}</span>}
                            </Show>
                          </div>
                        </Show>
                      </td>
                      <td class="px-4 py-2.5 font-mono text-xs text-[#666666] dark:text-[#8f8f8f]">
                        {entry.qtype}
                      </td>
                      <td class="px-4 py-2.5 whitespace-nowrap">
                        <OutcomeBadge outcome={entry.outcome} />
                      </td>
                      <td
                        class="px-4 py-2.5 font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] max-w-[12rem] truncate"
                        title={entry.answers.join(", ")}
                      >
                        <Show when={entry.answers.length > 0} fallback="-">
                          {entry.answers.join(", ")}
                        </Show>
                      </td>
                      <td class="px-4 py-2.5 text-right font-mono text-xs text-[#666666] dark:text-[#a1a1aa] whitespace-nowrap tabular-nums">
                        {(entry.elapsed_us / 1000).toFixed(2)} ms
                      </td>
                      <Show when={props.onQuickRule}>
                        <td class="px-4 py-2.5 text-right whitespace-nowrap">
                          <div class="inline-flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => props.onQuickRule?.(entry.domain, "allow")}
                              class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 cursor-pointer"
                            >
                              {t("logsQuickAllow")}
                            </button>
                            <button
                              type="button"
                              onClick={() => props.onQuickRule?.(entry.domain, "block")}
                              class="px-2 py-0.5 rounded text-[11px] font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 dark:text-rose-400 border border-rose-500/20 cursor-pointer"
                            >
                              {t("logsQuickBlock")}
                            </button>
                          </div>
                        </td>
                      </Show>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </div>

        {/* Mobile Card List */}
        <div class="md:hidden space-y-2.5">
          <For each={props.logs}>
            {(entry) => (
              <div class="animate-row-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-3.5 space-y-2 shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none">
                <div class="flex items-start justify-between gap-2">
                  <div class="min-w-0">
                    <span class="font-mono text-xs font-medium text-[#171717] dark:text-[#ededed] break-all leading-relaxed">
                      {entry.domain}
                    </span>
                    <Show when={entry.matched_list}>
                      {(listName) => (
                        <div class="mt-0.5">
                          <span class="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-700 dark:text-rose-400 border border-rose-500/20">
                            {t("logsMatchedList")}: {listName()}
                          </span>
                        </div>
                      )}
                    </Show>
                  </div>
                  <div class="shrink-0 flex items-center gap-1.5">
                    <span class="px-1.5 py-0.5 rounded font-mono text-[10px] uppercase bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa]">
                      {entry.protocol}
                    </span>
                    <OutcomeBadge outcome={entry.outcome} />
                  </div>
                </div>
                <Show when={entry.answers.length > 0}>
                  <div class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] break-all">
                    {entry.answers.join(", ")}
                  </div>
                </Show>
                <div class="flex items-center justify-between text-[11px] text-[#666666] dark:text-[#8f8f8f] tabular-nums">
                  <div class="flex items-center gap-2 font-mono truncate">
                    <span>
                      {entry.client_name
                        ? `${entry.client_name} (${entry.client_ip})`
                        : entry.client_ip}
                    </span>
                    <span class="text-[#d4d4d8] dark:text-[#333333]">·</span>
                    <span>{entry.qtype}</span>
                  </div>
                  <div class="flex items-center gap-2 shrink-0 font-mono">
                    <span>{(entry.elapsed_us / 1000).toFixed(2)} ms</span>
                    <span class="text-[#d4d4d8] dark:text-[#333333]">·</span>
                    <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
