import { For, Show, createMemo, createSignal } from "solid-js";
import { t } from "../../i18n";
import type { BlockMode } from "../../types/BlockMode";
import type { RecursiveQnameMinimization } from "../../types/RecursiveQnameMinimization";
import type { RootProbeReport } from "../../types/RootProbeReport";
import type { RootServerProbeResult } from "../../types/RootServerProbeResult";
import type { UpstreamStrategy } from "../../types/UpstreamStrategy";
import { InfoTooltip } from "../InfoTooltip";
import { SelectMenu, type SelectOption } from "../SelectMenu";
import { UpstreamList } from "../UpstreamList";
import {
  NUMBER_INPUT_CLASS,
  SettingsCard,
  SettingsSectionHeader,
  TEXTAREA_MONO_CLASS,
  ToggleRow,
} from "./SettingsControls";
import type { SettingsViewProps } from "./types";

const STRATEGY_OPTIONS: SelectOption<UpstreamStrategy>[] = [
  { value: "failover", label: () => t("settingsStrategyFailover") },
  { value: "parallel", label: () => t("settingsStrategyParallel") },
  { value: "least_latency", label: () => t("settingsStrategyLeastLatency") },
];

const BLOCK_MODE_OPTIONS: SelectOption<BlockMode>[] = [
  { value: "zero_ip", label: () => t("settingsBlockZeroIp") },
  { value: "nx_domain", label: () => t("settingsBlockNxDomain") },
  { value: "no_data", label: () => t("settingsBlockNoData") },
];

const QNAME_MIN_OPTIONS: SelectOption<RecursiveQnameMinimization>[] = [
  { value: "relaxed", label: () => t("settingsRecursiveQnameRelaxed") },
  { value: "strict", label: () => t("settingsRecursiveQnameStrict") },
];

export function BasicSettingsSection(props: SettingsViewProps) {
  const [probingRoots, setProbingRoots] = createSignal(false);
  const [rootProbeReport, setRootProbeReport] = createSignal<RootProbeReport | null>(null);
  const [rootProbeError, setRootProbeError] = createSignal("");

  const groupedRootResults = createMemo(() => {
    const report = rootProbeReport();
    if (!report) return [];
    const byName = new Map<
      string,
      { name: string; v4?: RootServerProbeResult; v6?: RootServerProbeResult }
    >();
    for (const item of report.results) {
      const entry = byName.get(item.name) ?? { name: item.name };
      if (item.family === "ipv4") {
        entry.v4 = item;
      } else {
        entry.v6 = item;
      }
      byName.set(item.name, entry);
    }
    return Array.from(byName.values());
  });

  async function handleProbeRoots() {
    setProbingRoots(true);
    setRootProbeError("");
    try {
      const res = await fetch("/api/recursive/probe", { method: "POST" });
      if (!res.ok) {
        setRootProbeError(`HTTP ${res.status}`);
        return;
      }
      const data: RootProbeReport = await res.json();
      setRootProbeReport(data);
    } catch (err) {
      setRootProbeError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbingRoots(false);
    }
  }

  return (
    <div class="space-y-4">
      <SettingsSectionHeader
        icon="i-ri-settings-4-line"
        title={t("settingsSecBasicTitle")}
        description={t("settingsSecBasicDesc")}
      />

      {/* Upstream DNS Servers (UpstreamList provides its own header) */}
      <section class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5">
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
      </section>

      {/* Resolution & Behavior */}
      <SettingsCard
        icon="i-ri-equalizer-line"
        title={t("settingsCardBasicBehaviorTitle")}
        description={t("settingsCardBasicBehaviorDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsStrategyLabel")}</span>
              <InfoTooltip text={t("tooltipStrategy")} align="left" />
            </label>
            <SelectMenu
              variant="subtle"
              size="md"
              value={props.upstreamStrategy}
              options={STRATEGY_OPTIONS}
              onChange={props.onUpstreamStrategyChange}
              class="w-full"
            />
          </div>

          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsBlockModeLabel")}</span>
              <InfoTooltip text={t("tooltipBlockMode")} align="right" />
            </label>
            <SelectMenu
              variant="subtle"
              size="md"
              value={props.blockMode}
              options={BLOCK_MODE_OPTIONS}
              onChange={props.onBlockModeChange}
              class="w-full"
            />
          </div>

          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsTimeoutLabel")}</span>
              <InfoTooltip text={t("tooltipTimeout")} align="left" />
            </label>
            <input
              type="number"
              min={1}
              value={props.upstreamTimeoutMs}
              onInput={(e) => props.onUpstreamTimeoutChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
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
              class={NUMBER_INPUT_CLASS}
            />
          </div>

          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsLogMaxDiskLabel")}</span>
            </label>
            <input
              type="number"
              min={1}
              value={props.logMaxDiskMb}
              onInput={(e) => props.onLogMaxDiskMbChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
        </div>
      </SettingsCard>

      {/* Built-in Recursive Resolver */}
      <SettingsCard
        icon="i-ri-git-branch-line"
        title={t("settingsRecursiveTitle")}
        description={t("settingsRecursiveDesc")}
      >
        <ToggleRow
          label={t("settingsRecursiveEnabled")}
          checked={props.recursive.enabled}
          onChange={(checked) =>
            props.onRecursiveChange({
              ...props.recursive,
              enabled: checked,
            })
          }
        />

        <div
          class={`grid grid-cols-1 sm:grid-cols-3 gap-3 transition-opacity duration-150 ${
            props.recursive.enabled ? "opacity-100" : "opacity-60"
          }`}
        >
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsRecursiveQnameLabel")}
            </label>
            <SelectMenu
              value={props.recursive.qname_minimization}
              options={QNAME_MIN_OPTIONS}
              onChange={(val) =>
                props.onRecursiveChange({
                  ...props.recursive,
                  qname_minimization: val as RecursiveQnameMinimization,
                })
              }
              class="w-full"
            />
          </div>
          <div class="flex items-end">
            <ToggleRow
              label={t("settingsRecursiveDnssecLabel")}
              checked={props.recursive.dnssec_validate}
              onChange={(checked) =>
                props.onRecursiveChange({
                  ...props.recursive,
                  dnssec_validate: checked,
                })
              }
            />
          </div>
          <div class="flex items-end">
            <ToggleRow
              label={t("settingsRecursiveCaseRandLabel")}
              checked={props.recursive.case_randomization}
              onChange={(checked) =>
                props.onRecursiveChange({
                  ...props.recursive,
                  case_randomization: checked,
                })
              }
            />
          </div>
        </div>

        {/* Root Server Reachability & Latency Test */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-3 space-y-2.5">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              disabled={probingRoots()}
              onClick={() => void handleProbeRoots()}
              class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#141414] text-xs font-medium text-[#171717] dark:text-[#ededed] hover:border-[#d4d4d8] dark:hover:border-[#404040] disabled:opacity-50 cursor-pointer"
            >
              <span
                class={
                  probingRoots()
                    ? "i-ri-loader-4-line animate-spin text-sm"
                    : "i-ri-pulse-line text-sm"
                }
              />
              <span>
                {probingRoots() ? t("settingsRecursiveProbing") : t("settingsRecursiveProbeBtn")}
              </span>
            </button>
            <Show when={rootProbeReport()}>
              {(report) => (
                <span class="text-xs font-mono tabular-nums text-[#666666] dark:text-[#a1a1aa]">
                  {t("settingsRecursiveProbeSummary")} {report().reachable_count}/{report().total} ·
                  IPv4 {report().ipv4_reachable}/13 · IPv6 {report().ipv6_reachable}/13
                </span>
              )}
            </Show>
          </div>

          <Show when={rootProbeError()}>
            <p class="text-xs text-rose-600 dark:text-rose-400">{rootProbeError()}</p>
          </Show>

          <Show when={groupedRootResults().length > 0}>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-1.5 max-h-64 overflow-y-auto pr-1">
              <For each={groupedRootResults()}>
                {(row) => (
                  <div class="flex items-center justify-between gap-2 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-2.5 py-1.5 text-[11px]">
                    <span class="font-mono font-medium text-[#171717] dark:text-[#ededed] truncate">
                      {row.name}
                    </span>
                    <div class="flex items-center gap-1.5 shrink-0 font-mono tabular-nums">
                      <Show when={row.v4}>
                        {(v4) => (
                          <span
                            title={`${v4().ip}${v4().error ? ` (${v4().error})` : ""}`}
                            class={`px-1.5 py-0.5 rounded ${
                              v4().reachable
                                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                                : "bg-rose-500/10 text-rose-600 dark:text-rose-400"
                            }`}
                          >
                            v4 {v4().reachable ? `${v4().latency_ms ?? 0}ms` : "×"}
                          </span>
                        )}
                      </Show>
                      <Show when={row.v6}>
                        {(v6) => (
                          <span
                            title={`${v6().ip}${v6().error ? ` (${v6().error})` : ""}`}
                            class={`px-1.5 py-0.5 rounded ${
                              v6().reachable
                                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                                : "bg-zinc-500/10 text-[#8f8f8f] dark:text-[#71717a]"
                            }`}
                          >
                            v6 {v6().reachable ? `${v6().latency_ms ?? 0}ms` : "×"}
                          </span>
                        )}
                      </Show>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </SettingsCard>

      {/* Bootstrap DNS */}
      <SettingsCard
        icon="i-ri-radar-line"
        title={t("settingsCardBootstrapTitle")}
        tooltip={t("tooltipBootstrapDns")}
        tooltipAlign="left"
      >
        <div>
          <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
            {t("settingsBootstrapDnsLabel")}
          </label>
          <textarea
            rows={2}
            spellcheck={false}
            placeholder={"1.1.1.1\n8.8.8.8"}
            value={props.bootstrapDnsText}
            onInput={(e) => props.onBootstrapDnsChange(e.currentTarget.value)}
            class={TEXTAREA_MONO_CLASS}
          />
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-1.5 leading-relaxed">
            {t("settingsBootstrapDnsHint")}
          </p>
        </div>
      </SettingsCard>
    </div>
  );
}
