import { For, Show, createSignal } from "solid-js";
import { t } from "../../i18n";
import type { SafeSearchConfig } from "../../types/SafeSearchConfig";
import { InfoTooltip } from "../InfoTooltip";
import {
  INPUT_CLASS,
  MONO_INPUT_CLASS,
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
  const [ntaDomain, setNtaDomain] = createSignal("");
  const [ntaExpiry, setNtaExpiry] = createSignal("");
  const [ntaReason, setNtaReason] = createSignal("");

  function addNta() {
    const domain = ntaDomain().trim();
    if (!domain) return;
    const rawExp = ntaExpiry().trim();
    const parsedExp = rawExp ? Number(rawExp) : null;
    const expires_at_unix_secs =
      parsedExp !== null && Number.isFinite(parsedExp) ? Math.trunc(parsedExp) : null;
    props.onDnssecNtasChange([
      ...props.dnssecNtas,
      {
        domain,
        expires_at_unix_secs,
        reason: ntaReason().trim() || undefined,
      },
    ]);
    setNtaDomain("");
    setNtaExpiry("");
    setNtaReason("");
  }

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
          <ToggleRow
            label={t("settingsAllowPrivateSubsLabel")}
            tooltip={t("tooltipAllowPrivateSubs")}
            checked={props.allowPrivateSubscriptions}
            onChange={props.onAllowPrivateSubscriptionsChange}
          />
          <ToggleRow
            label={t("settingsEdeLabel")}
            tooltipAlign="right"
            checked={props.edeEnabled}
            onChange={props.onEdeEnabledChange}
          />
          <ToggleRow
            label={t("settingsDnsCookiesLabel")}
            checked={props.dnsCookiesEnabled}
            onChange={props.onDnsCookiesEnabledChange}
          />
          <ToggleRow
            label={t("settingsDnsCookiesRequireValidLabel")}
            tooltipAlign="right"
            checked={props.dnsCookiesRequireValid}
            onChange={props.onDnsCookiesRequireValidChange}
          />
        </div>

        <div class="max-w-xs">
          <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
            {t("settingsMaxUdpPayloadLabel")}
          </label>
          <input
            type="number"
            min={512}
            max={4096}
            value={props.maxUdpPayloadSize}
            onInput={(e) => props.onMaxUdpPayloadSizeChange(Number(e.currentTarget.value))}
            class={NUMBER_INPUT_CLASS}
          />
        </div>

        <Show when={props.dnssecEnabled}>
          <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <ToggleRow
                label={t("settingsDnssecStrictClockLabel")}
                checked={props.dnssecStrictClock}
                onChange={props.onDnssecStrictClockChange}
                compact
              />
              <ToggleRow
                label={t("settingsDnssecAutoRolloverLabel")}
                checked={props.dnssecAutoRollover}
                onChange={props.onDnssecAutoRolloverChange}
                compact
              />
            </div>

            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDnssecTrustAnchorsLabel")}
              </label>
              <textarea
                rows={2}
                spellcheck={false}
                placeholder=". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
                value={props.dnssecTrustAnchorsText}
                onInput={(e) => props.onDnssecTrustAnchorsChange(e.currentTarget.value)}
                class={TEXTAREA_MONO_CLASS}
              />
            </div>

            <div class="space-y-2">
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa]">
                {t("settingsDnssecNtasLabel")}
              </label>
              <Show when={props.dnssecNtas.length > 0}>
                <div class="space-y-1.5">
                  <For each={props.dnssecNtas}>
                    {(nta, idx) => (
                      <div class="flex items-center justify-between gap-2 rounded-md border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] px-2.5 py-1.5 text-xs">
                        <div class="min-w-0 flex-1 flex flex-wrap items-center gap-2 font-mono">
                          <span class="font-medium text-[#171717] dark:text-[#ededed]">
                            {nta.domain}
                          </span>
                          <Show when={nta.expires_at_unix_secs}>
                            {(exp) => (
                              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                                exp:{exp()}
                              </span>
                            )}
                          </Show>
                          <Show when={nta.reason}>
                            {(reason) => (
                              <span class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] font-sans">
                                ({reason()})
                              </span>
                            )}
                          </Show>
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            props.onDnssecNtasChange(props.dnssecNtas.filter((_, i) => i !== idx()))
                          }
                          class="text-[#8f8f8f] hover:text-rose-600 dark:hover:text-rose-400 cursor-pointer bg-transparent border-0 p-1"
                        >
                          <span class="i-ri-delete-bin-line text-sm" />
                        </button>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
              <div class="grid grid-cols-1 sm:grid-cols-4 gap-2">
                <input
                  type="text"
                  placeholder="broken.example.com"
                  value={ntaDomain()}
                  onInput={(e) => setNtaDomain(e.currentTarget.value)}
                  class={MONO_INPUT_CLASS}
                />
                <input
                  type="number"
                  placeholder={t("settingsDnssecNtaExpiryPlaceholder")}
                  value={ntaExpiry()}
                  onInput={(e) => setNtaExpiry(e.currentTarget.value)}
                  class={MONO_INPUT_CLASS}
                />
                <input
                  type="text"
                  placeholder={t("settingsDnssecNtaReasonPlaceholder")}
                  value={ntaReason()}
                  onInput={(e) => setNtaReason(e.currentTarget.value)}
                  class={INPUT_CLASS}
                />
                <button
                  type="button"
                  disabled={!ntaDomain().trim()}
                  onClick={addNta}
                  class="h-9 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] cursor-pointer disabled:opacity-50 transition-colors"
                >
                  {t("settingsDnssecNtaAddBtn")}
                </button>
              </div>
            </div>
          </div>
        </Show>

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

        <div>
          <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
            <span>{t("settingsTrustedForwardersLabel")}</span>
            <InfoTooltip text={t("tooltipTrustedForwarders")} align="left" />
          </label>
          <textarea
            rows={2}
            spellcheck={false}
            placeholder={"127.0.0.1/32\n192.168.1.1/32"}
            value={props.trustedForwardersText}
            onInput={(e) => props.onTrustedForwardersChange(e.currentTarget.value)}
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

        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-4 space-y-3">
          <p class="text-[11px] font-medium uppercase tracking-wider text-[#8f8f8f] dark:text-[#71717a]">
            {t("settingsRrlTitle")}
          </p>
          <ToggleRow
            label={t("settingsRrlEnabledLabel")}
            checked={props.rrlEnabled}
            onChange={props.onRrlEnabledChange}
          />
          <Show when={props.rrlEnabled}>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                  {t("settingsRrlRpsLabel")}
                </label>
                <input
                  type="number"
                  min={1}
                  value={props.rrlResponsesPerSecond}
                  onInput={(e) =>
                    props.onRrlResponsesPerSecondChange(Number(e.currentTarget.value))
                  }
                  class={NUMBER_INPUT_CLASS}
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                  {t("settingsRrlSlipLabel")}
                </label>
                <input
                  type="number"
                  min={0}
                  value={props.rrlSlip}
                  onInput={(e) => props.onRrlSlipChange(Number(e.currentTarget.value))}
                  class={NUMBER_INPUT_CLASS}
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                  {t("settingsRrlWindowLabel")}
                </label>
                <input
                  type="number"
                  min={1}
                  value={props.rrlWindowSecs}
                  onInput={(e) => props.onRrlWindowSecsChange(Number(e.currentTarget.value))}
                  class={NUMBER_INPUT_CLASS}
                />
              </div>
            </div>
          </Show>
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
