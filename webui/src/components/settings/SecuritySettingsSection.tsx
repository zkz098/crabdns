import { For, Show } from "solid-js";
import { t } from "../../i18n";
import type { SafeSearchConfig } from "../../types/SafeSearchConfig";
import { InfoTooltip } from "../InfoTooltip";
import {
  INPUT_CLASS,
  NUMBER_INPUT_CLASS,
  SettingsCard,
  SettingsSectionHeader,
  TEXTAREA_MONO_CLASS,
  ToggleRow,
  ToggleSwitch,
} from "./SettingsControls";
import type { SettingsViewProps } from "./types";

type SafeSearchEngineKey = Exclude<keyof SafeSearchConfig, "enabled">;

const SAFESEARCH_ENGINES: Array<{
  key: SafeSearchEngineKey;
  label: () => string;
}> = [
  { key: "google", label: () => "Google" },
  { key: "bing", label: () => "Bing" },
  { key: "youtube", label: () => "YouTube" },
  { key: "youtube_strict", label: () => t("settingsSafeSearchYoutubeStrict") },
  { key: "duckduckgo", label: () => "DuckDuckGo" },
  { key: "yandex", label: () => "Yandex" },
  { key: "pixabay", label: () => "Pixabay" },
  { key: "brave", label: () => "Brave" },
];

export function SecuritySettingsSection(props: SettingsViewProps) {
  return (
    <div class="space-y-4">
      <SettingsSectionHeader
        icon="i-ri-shield-keyhole-line"
        title={t("settingsSecSecurityTitle")}
        description={t("settingsSecSecurityDesc")}
      />

      {/* Protocol, DNSSEC & Security */}
      <SettingsCard
        icon="i-ri-shield-check-line"
        title={t("settingsProtocolSecurityTitle")}
        description={t("settingsCardProtocolSecDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <ToggleRow
            label={t("settingsDnssecLabel")}
            tooltip={t("tooltipDnssec")}
            checked={props.dnssecEnabled}
            onChange={props.onDnssecEnabledChange}
          />
          <ToggleRow
            label={t("settingsDnsRebindingLabel")}
            tooltip={t("tooltipDnsRebinding")}
            tooltipAlign="right"
            checked={props.dnsRebindingProtection}
            onChange={props.onDnsRebindingProtectionChange}
          />
          <ToggleRow
            label={t("settingsCnameCloakingLabel")}
            tooltip={t("tooltipCnameCloaking")}
            checked={props.cnameCloakingBlocking}
            onChange={props.onCnameCloakingChange}
          />
          <ToggleRow
            label={t("settingsBlockAnyLabel")}
            tooltip={t("tooltipBlockAny")}
            tooltipAlign="right"
            checked={props.blockAnyQueries}
            onChange={props.onBlockAnyQueriesChange}
          />
          <ToggleRow
            label={t("settingsSvcbStripEchLabel")}
            tooltip={t("tooltipSvcbStripEch")}
            checked={props.svcbStripEch}
            onChange={props.onSvcbStripEchChange}
          />
          <ToggleRow
            label={t("settingsSvcbStripHintsLabel")}
            tooltip={t("tooltipSvcbStripHints")}
            tooltipAlign="right"
            checked={props.svcbStripHints}
            onChange={props.onSvcbStripHintsChange}
          />
          <div class="sm:col-span-2">
            <ToggleRow
              label={t("settingsAllowPrivateSubsLabel")}
              tooltip={t("tooltipAllowPrivateSubs")}
              checked={props.allowPrivateSubscriptions}
              onChange={props.onAllowPrivateSubscriptionsChange}
            />
          </div>
        </div>

        <div>
          <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
            <span>{t("settingsTrustedProxiesLabel")}</span>
            <InfoTooltip text={t("tooltipTrustedProxies")} align="left" />
          </label>
          <textarea
            rows={2}
            spellcheck={false}
            placeholder="127.0.0.1/32"
            value={props.trustedProxiesText}
            onInput={(e) => props.onTrustedProxiesChange(e.currentTarget.value)}
            class={TEXTAREA_MONO_CLASS}
          />
        </div>
      </SettingsCard>

      {/* SafeSearch */}
      <SettingsCard
        icon="i-ri-search-eye-line"
        title={t("settingsSafeSearchTitle")}
        description={t("settingsSafeSearchDesc")}
        tooltip={t("tooltipSafeSearch")}
        tooltipAlign="left"
      >
        <ToggleRow
          label={t("settingsSafeSearchEnabled")}
          checked={props.safesearch.enabled}
          onChange={(checked) =>
            props.onSafesearchChange({
              ...props.safesearch,
              enabled: checked,
            })
          }
        />

        <div
          class={`grid grid-cols-2 sm:grid-cols-4 gap-2.5 transition-opacity duration-150 ${
            props.safesearch.enabled ? "opacity-100" : "opacity-60"
          }`}
        >
          <For each={SAFESEARCH_ENGINES}>
            {(engine) => {
              const checked = () => props.safesearch[engine.key];
              return (
                <div
                  class={`flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs transition-colors ${
                    checked()
                      ? "border-[#171717]/40 dark:border-[#ededed]/40 bg-[#f4f4f5] dark:bg-[#141414] text-[#171717] dark:text-[#ededed] font-medium"
                      : "border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] text-[#666666] dark:text-[#a1a1aa] hover:border-[#d4d4d8] dark:hover:border-[#404040]"
                  }`}
                >
                  <span class="truncate">{engine.label()}</span>
                  <ToggleSwitch
                    compact
                    checked={checked()}
                    ariaLabel={engine.label()}
                    onChange={(next) =>
                      props.onSafesearchChange({
                        ...props.safesearch,
                        [engine.key]: next,
                      })
                    }
                  />
                </div>
              );
            }}
          </For>
        </div>
      </SettingsCard>

      {/* DNS Client ACL & Rate Limiting */}
      <SettingsCard
        icon="i-ri-shield-user-line"
        title={t("settingsAclTitle")}
        description={t("settingsCardAclDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsAllowCidrsLabel")}</span>
              <InfoTooltip text={t("tooltipAllowCidrs")} align="left" />
            </label>
            <textarea
              rows={3}
              spellcheck={false}
              placeholder="192.168.0.0/16"
              value={props.allowCidrsText}
              onInput={(e) => props.onAllowCidrsChange(e.currentTarget.value)}
              class={TEXTAREA_MONO_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsDenyCidrsLabel")}</span>
              <InfoTooltip text={t("tooltipDenyCidrs")} align="right" />
            </label>
            <textarea
              rows={3}
              spellcheck={false}
              placeholder="203.0.113.0/24"
              value={props.denyCidrsText}
              onInput={(e) => props.onDenyCidrsChange(e.currentTarget.value)}
              class={TEXTAREA_MONO_CLASS}
            />
          </div>
        </div>
        <div class="max-w-xs">
          <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
            <span>{t("settingsRateLimitLabel")}</span>
            <InfoTooltip text={t("tooltipRateLimit")} align="left" />
          </label>
          <input
            type="number"
            min={0}
            value={props.rateLimitQps}
            onInput={(e) => props.onRateLimitChange(Number(e.currentTarget.value))}
            class={NUMBER_INPUT_CLASS}
          />
        </div>
      </SettingsCard>

      {/* Web UI Authentication */}
      <SettingsCard
        icon="i-ri-key-2-line"
        title={t("settingsAuthTitle")}
        description={t("settingsCardAuthDesc")}
        action={
          <>
            <Show when={props.authMessage}>
              <span
                class={`text-xs font-medium ${
                  props.authIsError
                    ? "text-rose-600 dark:text-rose-400"
                    : "text-emerald-600 dark:text-emerald-400"
                }`}
              >
                {props.authMessage}
              </span>
            </Show>
            <button
              type="button"
              onClick={props.onSaveAuth}
              class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0 transition-colors"
            >
              {t("settingsAuthSave")}
            </button>
          </>
        }
      >
        <ToggleRow
          label={t("settingsAuthEnableLabel")}
          checked={props.authEnabled}
          onChange={props.onAuthEnabledChange}
        />

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("authUsernameLabel")}
            </label>
            <input
              type="text"
              value={props.authUsername}
              onInput={(e) => props.onAuthUsernameChange(e.currentTarget.value)}
              class={INPUT_CLASS}
            />
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("authNewPasswordLabel")}
            </label>
            <input
              type="password"
              value={props.authPassword}
              onInput={(e) => props.onAuthPasswordChange(e.currentTarget.value)}
              class={INPUT_CLASS}
            />
          </div>
        </div>
      </SettingsCard>
    </div>
  );
}
