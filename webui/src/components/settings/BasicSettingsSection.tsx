import { t } from "../../i18n";
import type { BlockMode } from "../../types/BlockMode";
import type { UpstreamStrategy } from "../../types/UpstreamStrategy";
import { InfoTooltip } from "../InfoTooltip";
import { SelectMenu, type SelectOption } from "../SelectMenu";
import { UpstreamList } from "../UpstreamList";
import {
  NUMBER_INPUT_CLASS,
  SettingsCard,
  SettingsSectionHeader,
  TEXTAREA_MONO_CLASS,
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

export function BasicSettingsSection(props: SettingsViewProps) {
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
