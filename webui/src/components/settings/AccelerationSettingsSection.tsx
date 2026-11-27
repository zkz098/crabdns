import { For, Show } from "solid-js";
import { t } from "../../i18n";
import { InfoTooltip } from "../InfoTooltip";
import { SplitDnsList } from "../SplitDnsList";
import { UpstreamGroupsCard } from "../UpstreamGroupsCard";
import {
  MONO_INPUT_CLASS,
  NUMBER_INPUT_CLASS,
  SettingsCard,
  SettingsSectionHeader,
  TEXTAREA_MONO_CLASS,
  ToggleRow,
} from "./SettingsControls";
import type { SettingsViewProps } from "./types";

export function AccelerationSettingsSection(props: SettingsViewProps) {
  return (
    <div class="space-y-4">
      <SettingsSectionHeader
        icon="i-ri-speed-up-line"
        title={t("settingsSecAccelTitle")}
        description={t("settingsSecAccelDesc")}
      />

      {/* DNS Cache Acceleration */}
      <SettingsCard
        icon="i-ri-database-2-line"
        title={t("settingsCardCacheTitle")}
        description={t("settingsCardCacheDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsCacheSizeLabel")}</span>
              <InfoTooltip text={t("tooltipCacheSize")} align="left" />
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheSize}
              onInput={(e) => props.onCacheSizeChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsCacheMinTtlLabel")}</span>
              <InfoTooltip text={t("tooltipCacheMinTtl")} />
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheMinTtlSecs}
              onInput={(e) => props.onCacheMinTtlChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              <span>{t("settingsCacheMaxTtlLabel")}</span>
              <InfoTooltip text={t("tooltipCacheMaxTtl")} align="right" />
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheMaxTtlSecs}
              onInput={(e) => props.onCacheMaxTtlChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
        </div>

        <div class="space-y-2.5 pt-1">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <ToggleRow
              label={t("settingsOptimisticLabel")}
              tooltip={t("tooltipOptimisticCache")}
              checked={props.optimisticCache}
              onChange={props.onOptimisticCacheChange}
            />
            <ToggleRow
              label={t("settingsServeStaleLabel")}
              tooltipAlign="right"
              checked={props.serveStaleEnabled}
              onChange={props.onServeStaleChange}
            />
            <ToggleRow
              label={t("settingsCachePrefetchLabel")}
              tooltip={t("tooltipCachePrefetch")}
              checked={props.cachePrefetchEnabled}
              onChange={props.onCachePrefetchChange}
            />
            <ToggleRow
              label={t("settingsCachePersistLabel")}
              tooltip={t("tooltipCachePersist")}
              tooltipAlign="right"
              checked={props.cachePersistEnabled}
              onChange={props.onCachePersistChange}
            />
          </div>
        </div>
      </SettingsCard>

      {/* Cloudflare CDN Active Acceleration */}
      <SettingsCard
        icon="i-ri-cloud-line"
        title={t("settingsCfCdnTitle")}
        description={t("settingsCfCdnDesc")}
        tooltip={t("tooltipCfCdn")}
        tooltipAlign="left"
        action={
          <button
            type="button"
            disabled={props.cfCdnStatus?.testing}
            onClick={() => props.onRunCfCdnSpeedtest()}
            class="h-8 px-3 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#000000] hover:bg-[#f0f0f0] dark:hover:bg-[#111111] text-xs font-medium text-[#171717] dark:text-[#ededed] disabled:opacity-50 shrink-0 cursor-pointer transition-colors"
          >
            {props.cfCdnStatus?.testing ? t("settingsCfCdnTesting") : t("settingsCfCdnRunTest")}
          </button>
        }
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <ToggleRow
            label={t("settingsCfCdnEnabled")}
            checked={props.cfCdnEnabled}
            onChange={props.onCfCdnEnabledChange}
          />
          <ToggleRow
            label={t("settingsCfCdnIpv6Enabled")}
            checked={props.cfCdnIpv6Enabled}
            onChange={props.onCfCdnIpv6EnabledChange}
          />
        </div>

        {/* Live status summary */}
        <Show when={props.cfCdnStatus}>
          {(st) => {
            const progressPercent = (): number | null => {
              const s = st();
              if (!s.testing || s.progress_total <= 0) return null;
              return Math.min(100, Math.round((s.progress_current / s.progress_total) * 100));
            };
            const phaseLabel = (): string => {
              switch (st().phase) {
                case "resolving_cidrs":
                  return t("settingsCfCdnPhaseResolving");
                case "latency_v4":
                  return t("settingsCfCdnPhaseLatencyV4");
                case "throughput_v4":
                  return t("settingsCfCdnPhaseThroughputV4");
                case "latency_v6":
                  return t("settingsCfCdnPhaseLatencyV6");
                case "throughput_v6":
                  return t("settingsCfCdnPhaseThroughputV6");
                default:
                  return t("settingsCfCdnTesting");
              }
            };
            return (
              <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#000000] p-3 space-y-2 text-xs">
                <Show when={st().testing}>
                  <div class="rounded-md border border-[#eaeaea] dark:border-[#222222] bg-white dark:bg-[#0a0a0a] p-2.5 space-y-2">
                    <div class="flex items-center justify-between gap-2">
                      <div class="flex items-center gap-1.5 min-w-0 font-medium text-[#171717] dark:text-[#ededed]">
                        <span class="i-ri-loader-4-line animate-spin text-sm shrink-0" />
                        <span class="truncate">{phaseLabel()}</span>
                        <Show when={st().current_ip}>
                          {(ip) => (
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#52525b] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] shrink-0">
                              {ip()}
                            </span>
                          )}
                        </Show>
                      </div>
                      <Show when={st().progress_total > 0}>
                        <span class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                          {st().progress_current} / {st().progress_total} ({progressPercent() ?? 0}
                          %)
                        </span>
                      </Show>
                    </div>
                    <div
                      role="progressbar"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={progressPercent() ?? undefined}
                      class="h-2 w-full rounded-full overflow-hidden bg-[#eaeaea] dark:bg-[#262626]"
                    >
                      <Show
                        when={progressPercent() !== null}
                        fallback={
                          <div class="h-full w-1/3 rounded-full bg-emerald-500 animate-pulse" />
                        }
                      >
                        <div
                          class="h-full rounded-full transition-all duration-200 ease-out bg-[#171717] dark:bg-[#ededed]"
                          style={{ width: `${progressPercent()}%` }}
                        />
                      </Show>
                    </div>
                  </div>
                </Show>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                      {t("settingsCfCdnBestIpv4")}
                    </div>
                    <div class="font-mono font-medium text-[#171717] dark:text-[#ededed] mt-0.5">
                      {st().best_ipv4 ?? "—"}
                      <Show when={st().best_ipv4_latency_ms !== null}>
                        <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] ml-1.5">
                          ({st().best_ipv4_latency_ms?.toFixed(1)} ms
                          <Show when={st().best_ipv4_throughput_mbps !== null}>
                            {` · ${st().best_ipv4_throughput_mbps?.toFixed(2)} MB/s`}
                          </Show>
                          )
                        </span>
                      </Show>
                    </div>
                  </div>
                  <div>
                    <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                      {t("settingsCfCdnBestIpv6")}
                    </div>
                    <div class="font-mono font-medium text-[#171717] dark:text-[#ededed] mt-0.5 break-all">
                      {st().best_ipv6 ?? "—"}
                      <Show when={st().best_ipv6_latency_ms !== null}>
                        <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] ml-1.5">
                          ({st().best_ipv6_latency_ms?.toFixed(1)} ms
                          <Show when={st().best_ipv6_throughput_mbps !== null}>
                            {` · ${st().best_ipv6_throughput_mbps?.toFixed(2)} MB/s`}
                          </Show>
                          )
                        </span>
                      </Show>
                    </div>
                  </div>
                  <div>
                    <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                      {t("settingsCfCdnLastRun")}
                    </div>
                    <div class="text-[#171717] dark:text-[#ededed] mt-0.5">
                      {st().last_run_unix_ms
                        ? new Date(st().last_run_unix_ms!).toLocaleString()
                        : t("settingsCfCdnNotTested")}
                    </div>
                  </div>
                </div>
                <Show when={st().last_error}>
                  <div class="text-[11px] text-amber-600 dark:text-amber-400">
                    {st().last_error}
                  </div>
                </Show>
                <Show when={st().candidates_v4.length > 0 || st().candidates_v6.length > 0}>
                  <details class="pt-1">
                    <summary class="cursor-pointer text-[11px] text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed]">
                      {t("settingsCfCdnCandidatesTitle")} (IPv4: {st().candidates_v4.length}, IPv6:{" "}
                      {st().candidates_v6.length})
                    </summary>
                    <div class="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
                      <For each={[...st().candidates_v4, ...st().candidates_v6]}>
                        {(node) => (
                          <div class="flex items-center justify-between gap-2 px-2 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a]">
                            <span class="truncate">{node.ip}</span>
                            <span class="text-[#666666] dark:text-[#a1a1aa] shrink-0">
                              {node.latency_ms.toFixed(1)} ms
                              {node.throughput_mbps !== null
                                ? ` · ${node.throughput_mbps.toFixed(2)} MB/s`
                                : ""}
                            </span>
                          </div>
                        )}
                      </For>
                    </div>
                  </details>
                </Show>
              </div>
            );
          }}
        </Show>

        <Show when={props.cfCdnEnabled}>
          <div class="space-y-3 pt-1">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                  {t("settingsCfCdnIntervalLabel")}
                </label>
                <input
                  type="number"
                  min={60}
                  value={props.cfCdnIntervalSecs}
                  onInput={(e) =>
                    props.onCfCdnIntervalSecsChange(Number(e.currentTarget.value) || 1800)
                  }
                  class={MONO_INPUT_CLASS}
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                  {t("settingsCfCdnTtlLabel")}
                </label>
                <input
                  type="number"
                  min={1}
                  value={props.cfCdnTtlSecs}
                  onInput={(e) => props.onCfCdnTtlSecsChange(Number(e.currentTarget.value) || 60)}
                  class={MONO_INPUT_CLASS}
                />
              </div>
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsCfCdnSpeedtestUrlLabel")}
              </label>
              <input
                type="text"
                spellcheck={false}
                value={props.cfCdnSpeedtestUrl}
                onInput={(e) => props.onCfCdnSpeedtestUrlChange(e.currentTarget.value)}
                class={MONO_INPUT_CLASS}
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsCfCdnExcludedLabel")}
              </label>
              <textarea
                rows={2}
                spellcheck={false}
                placeholder="workers.dev"
                value={props.cfCdnExcludedDomainsText}
                onInput={(e) => props.onCfCdnExcludedDomainsChange(e.currentTarget.value)}
                class={TEXTAREA_MONO_CLASS}
              />
            </div>

            <details class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3">
              <summary class="cursor-pointer text-xs font-medium text-[#171717] dark:text-[#ededed]">
                {t("settingsCfCdnAdvancedLabel")}
              </summary>
              <div class="mt-3 space-y-3">
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      {t("settingsCfCdnConcurrencyLabel")}
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={props.cfCdnConcurrency}
                      onInput={(e) =>
                        props.onCfCdnConcurrencyChange(Number(e.currentTarget.value) || 50)
                      }
                      class={MONO_INPUT_CLASS}
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      {t("settingsCfCdnTopNLabel")}
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={props.cfCdnTopN}
                      onInput={(e) => props.onCfCdnTopNChange(Number(e.currentTarget.value) || 3)}
                      class={MONO_INPUT_CLASS}
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      {t("settingsCfCdnSamplesPerCidrLabel")}
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={props.cfCdnSamplesPerCidr}
                      onInput={(e) =>
                        props.onCfCdnSamplesPerCidrChange(Number(e.currentTarget.value) || 3)
                      }
                      class={MONO_INPUT_CLASS}
                    />
                  </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      {t("settingsCfCdnCustomIpv4Label")}
                    </label>
                    <textarea
                      rows={2}
                      spellcheck={false}
                      placeholder="104.16.0.0/13"
                      value={props.cfCdnCustomIpv4CidrsText}
                      onInput={(e) => props.onCfCdnCustomIpv4CidrsChange(e.currentTarget.value)}
                      class={TEXTAREA_MONO_CLASS}
                    />
                  </div>
                  <div>
                    <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                      {t("settingsCfCdnCustomIpv6Label")}
                    </label>
                    <textarea
                      rows={2}
                      spellcheck={false}
                      placeholder="2606:4700::/32"
                      value={props.cfCdnCustomIpv6CidrsText}
                      onInput={(e) => props.onCfCdnCustomIpv6CidrsChange(e.currentTarget.value)}
                      class={TEXTAREA_MONO_CLASS}
                    />
                  </div>
                </div>
              </div>
            </details>
          </div>
        </Show>
      </SettingsCard>

      {/* EDNS0 Client Subnet (ECS) */}
      <SettingsCard
        icon="i-ri-rocket-2-line"
        title={t("settingsCardEcsTitle")}
        description={t("settingsCardEcsDesc")}
        tooltip={t("tooltipEcs")}
        tooltipAlign="left"
      >
        <ToggleRow
          label={t("settingsEcsLabel")}
          tooltip={t("tooltipEcs")}
          checked={props.ecsEnabled}
          onChange={props.onEcsEnabledChange}
        />

        <div
          class={`grid grid-cols-1 sm:grid-cols-3 gap-4 transition-opacity duration-150 ${
            props.ecsEnabled ? "opacity-100" : "opacity-60"
          }`}
        >
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsEcsCustomIpLabel")}</span>
              <InfoTooltip text={t("tooltipEcsCustomIp")} align="left" />
            </label>
            <input
              type="text"
              placeholder="203.0.113.0/24"
              value={props.ecsCustomIp}
              onInput={(e) => props.onEcsCustomIpChange(e.currentTarget.value)}
              class={MONO_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsEcsV4PrefixLabel")}</span>
              <InfoTooltip text={t("tooltipEcsV4Prefix")} />
            </label>
            <input
              type="number"
              min={0}
              max={32}
              value={props.ecsIpv4Prefix}
              onInput={(e) => props.onEcsIpv4PrefixChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsEcsV6PrefixLabel")}</span>
              <InfoTooltip text={t("tooltipEcsV6Prefix")} align="right" />
            </label>
            <input
              type="number"
              min={0}
              max={128}
              value={props.ecsIpv6Prefix}
              onInput={(e) => props.onEcsIpv6PrefixChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
        </div>
      </SettingsCard>

      {/* Named Upstream Groups */}
      <section class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5">
        <UpstreamGroupsCard groups={props.upstreamGroups} onChange={props.onUpstreamGroupsChange} />
      </section>

      {/* Split DNS Rules (SplitDnsList provides its own header) */}
      <section class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5">
        <SplitDnsList
          rules={props.splitDnsRules}
          onChange={props.onSplitDnsChange}
          upstreamGroups={props.upstreamGroups}
          matchMode={props.splitDnsMatchMode}
          onMatchModeChange={props.onSplitDnsMatchModeChange}
          splitBeforeClientUpstreams={props.splitDnsBeforeClientUpstreams}
          onSplitBeforeClientUpstreamsChange={props.onSplitDnsBeforeClientUpstreamsChange}
          refreshIntervalSecs={props.splitDnsRefreshIntervalSecs}
          onRefreshIntervalSecsChange={props.onSplitDnsRefreshIntervalSecsChange}
          sourceStatuses={props.splitDnsStatuses}
          refreshing={props.refreshingSplitDns}
          onRefresh={props.onRefreshSplitDns}
        />
      </section>
    </div>
  );
}
