import { Show } from "solid-js";
import { t } from "../../i18n";
import type { AcmeChallengeType } from "../../types/AcmeChallengeType";
import { InfoTooltip } from "../InfoTooltip";
import { SelectMenu, type SelectOption } from "../SelectMenu";
import {
  MONO_INPUT_CLASS,
  SettingsCard,
  SettingsSectionHeader,
  TEXTAREA_MONO_CLASS,
  ToggleRow,
} from "./SettingsControls";
import type { SettingsViewProps } from "./types";

const ACME_CHALLENGE_OPTIONS: SelectOption<AcmeChallengeType>[] = [
  { value: "http01", label: () => t("settingsAcmeChallengeHttp01") },
  { value: "dns01_local", label: () => t("settingsAcmeChallengeDns01") },
];

export function NetworkTlsSettingsSection(props: SettingsViewProps) {
  const hasTlsListener = () =>
    Boolean(
      props.tlsStatus?.https_enabled ||
      props.tlsStatus?.dot_enabled ||
      props.tlsStatus?.doq_enabled ||
      props.tlsStatus?.doh3_enabled,
    );

  return (
    <div class="space-y-4">
      <SettingsSectionHeader
        icon="i-ri-global-line"
        title={t("settingsSecNetworkTitle")}
        description={t("settingsSecNetworkDesc")}
      />

      {/* Encrypted DNS & Discovery */}
      <SettingsCard
        icon="i-ri-lock-2-line"
        title={t("settingsCardEncryptedDnsTitle")}
        description={t("settingsCardEncryptedDnsDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <ToggleRow
            label={t("settingsDohEnabledLabel")}
            tooltip={t("tooltipDohEnabled")}
            checked={props.dohEnabled}
            onChange={props.onDohEnabledChange}
          />
          <ToggleRow
            label={t("settingsDdrLabel")}
            tooltip={t("tooltipDdr")}
            tooltipAlign="right"
            checked={props.ddrEnabled}
            onChange={props.onDdrEnabledChange}
          />
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsDdrHostnameLabel")}</span>
              <InfoTooltip text={t("tooltipDdrHostname")} align="left" />
            </label>
            <input
              type="text"
              placeholder="dns.example.com"
              value={props.ddrHostname}
              onInput={(e) => props.onDdrHostnameChange(e.currentTarget.value)}
              class={MONO_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsSniHostnamesLabel")}</span>
              <InfoTooltip text={t("tooltipSniHostnames")} align="right" />
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="dot.example.com"
              value={props.sniClientIdHostnamesText}
              onInput={(e) => props.onSniClientIdHostnamesChange(e.currentTarget.value)}
              class={TEXTAREA_MONO_CLASS}
            />
          </div>
        </div>
      </SettingsCard>

      {/* Native TLS & ACME */}
      <SettingsCard
        icon="i-ri-shield-check-line"
        title={t("settingsTlsTitle")}
        tooltip={t("tooltipTls")}
        tooltipAlign="left"
        action={
          <>
            <Show when={props.tlsMessage}>
              <span
                class={`text-xs font-medium ${
                  props.tlsIsError
                    ? "text-rose-600 dark:text-rose-400"
                    : "text-emerald-600 dark:text-emerald-400"
                }`}
              >
                {props.tlsMessage}
              </span>
            </Show>
            <button
              type="button"
              disabled={props.reloadingTls || !hasTlsListener()}
              onClick={props.onReloadTls}
              class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] cursor-pointer disabled:opacity-50 transition-colors"
            >
              {props.reloadingTls ? t("settingsTlsReloading") : t("settingsTlsReloadBtn")}
            </button>
          </>
        }
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsTlsCertPathLabel")}
            </label>
            <input
              type="text"
              placeholder="/etc/crabdns/cert.pem"
              value={props.tlsCertPath}
              onInput={(e) => props.onTlsCertPathChange(e.currentTarget.value)}
              class={MONO_INPUT_CLASS}
            />
          </div>
          <div>
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsTlsKeyPathLabel")}
            </label>
            <input
              type="text"
              placeholder="/etc/crabdns/key.pem"
              value={props.tlsKeyPath}
              onInput={(e) => props.onTlsKeyPathChange(e.currentTarget.value)}
              class={MONO_INPUT_CLASS}
            />
          </div>
        </div>

        <Show
          when={props.tlsStatus && hasTlsListener()}
          fallback={
            <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">{t("settingsTlsInactive")}</p>
          }
        >
          <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
            <div>
              <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                {t("settingsTlsFingerprint")}
              </span>
              <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed] break-all">
                {props.tlsStatus?.cert_fingerprint_sha256 ?? "-"}
              </span>
            </div>
            <div>
              <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                {t("settingsTlsLastLoaded")}
              </span>
              <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed] break-all">
                {props.tlsStatus?.last_loaded_at ?? "-"}
              </span>
            </div>
            <Show when={props.tlsStatus?.last_error}>
              {(err) => (
                <div class="sm:col-span-2 text-rose-600 dark:text-rose-400 font-mono text-[11px] break-all">
                  {err()}
                </div>
              )}
            </Show>
          </div>
        </Show>

        {/* ACME / Let's Encrypt Sub-Panel */}
        <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
                {t("settingsAcmeTitle")}
              </div>
              <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">{t("settingsAcmeDesc")}</p>
            </div>
            <div class="flex items-center gap-2">
              <Show when={props.acmeMessage}>
                <span
                  class={`text-[11px] font-medium ${
                    props.acmeIsError
                      ? "text-rose-600 dark:text-rose-400"
                      : "text-emerald-600 dark:text-emerald-400"
                  }`}
                >
                  {props.acmeMessage}
                </span>
              </Show>
              <button
                type="button"
                disabled={props.issuingAcme || !props.acmeDomainsText.trim()}
                onClick={props.onIssueAcme}
                class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] cursor-pointer disabled:opacity-50 transition-colors"
              >
                {props.issuingAcme ? t("settingsAcmeIssuing") : t("settingsAcmeIssueBtn")}
              </button>
            </div>
          </div>

          <ToggleRow
            label={t("settingsAcmeEnabled")}
            checked={props.acmeEnabled}
            onChange={props.onAcmeEnabledChange}
            compact
          />

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="sm:col-span-2">
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("settingsAcmeDomainsLabel")}
              </label>
              <input
                type="text"
                placeholder="dns.example.com"
                value={props.acmeDomainsText}
                onInput={(e) => props.onAcmeDomainsChange(e.currentTarget.value)}
                class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("settingsAcmeEmailLabel")}
              </label>
              <input
                type="email"
                placeholder="admin@example.com"
                value={props.acmeEmail}
                onInput={(e) => props.onAcmeEmailChange(e.currentTarget.value)}
                class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("settingsAcmeChallengeLabel")}
              </label>
              <SelectMenu
                size="md"
                value={props.acmeChallengeType}
                options={ACME_CHALLENGE_OPTIONS}
                onChange={props.onAcmeChallengeTypeChange}
                class="w-full"
                triggerClass="text-xs font-normal"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("settingsAcmeDirectoryLabel")}
              </label>
              <input
                type="text"
                value={props.acmeDirectoryUrl}
                onInput={(e) => props.onAcmeDirectoryUrlChange(e.currentTarget.value)}
                class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("settingsAcmeHttpListenLabel")}
                </label>
                <input
                  type="text"
                  placeholder="0.0.0.0:80"
                  value={props.acmeHttpListen}
                  onInput={(e) => props.onAcmeHttpListenChange(e.currentTarget.value)}
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("settingsAcmeRenewDaysLabel")}
                </label>
                <input
                  type="number"
                  min={1}
                  max={89}
                  value={props.acmeRenewBeforeDays}
                  onInput={(e) =>
                    props.onAcmeRenewBeforeDaysChange(Number(e.currentTarget.value) || 30)
                  }
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
            </div>
          </div>

          <Show when={props.acmeStatus?.cert_exists || props.acmeStatus?.last_error}>
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-2.5 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div>
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsAcmeExpires")}
                </span>
                <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                  {props.acmeStatus?.cert_expires_at ?? "-"}
                </span>
              </div>
              <div>
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsAcmeDaysRemaining")}
                </span>
                <span class="font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                  {props.acmeStatus?.days_remaining !== null &&
                  props.acmeStatus?.days_remaining !== undefined
                    ? String(props.acmeStatus.days_remaining)
                    : "-"}
                </span>
              </div>
              <Show when={props.acmeStatus?.last_error}>
                {(err) => (
                  <div class="sm:col-span-2 text-rose-600 dark:text-rose-400 font-mono text-[11px] break-all">
                    {err()}
                  </div>
                )}
              </Show>
            </div>
          </Show>
        </div>
      </SettingsCard>

      {/* LAN & System Integration */}
      <SettingsCard
        icon="i-ri-router-line"
        title={t("settingsLanTitle")}
        description={t("settingsCardLanDesc")}
      >
        {/* Group 1: Hosts & DHCP */}
        <div class="space-y-3">
          <p class="text-[11px] font-medium uppercase tracking-wider text-[#8f8f8f] dark:text-[#71717a]">
            {t("settingsLanHostsDhcpTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <ToggleRow
              label={t("settingsHostsLabel")}
              tooltip={t("tooltipHosts")}
              checked={props.hostsEnabled}
              onChange={props.onHostsEnabledChange}
            />
            <ToggleRow
              label={t("settingsDhcpLeasesLabel")}
              tooltip={t("tooltipDhcpLeases")}
              tooltipAlign="right"
              checked={props.dhcpLeasesEnabled}
              onChange={props.onDhcpLeasesEnabledChange}
            />
            <div class="sm:col-span-2">
              <ToggleRow
                label={t("settingsDhcpLeasesForwardLabel")}
                tooltip={t("tooltipDhcpLeasesForward")}
                checked={props.dhcpLeasesForwardEnabled}
                onChange={props.onDhcpLeasesForwardEnabledChange}
              />
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsHostsPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/etc/hosts"
                value={props.hostsPath}
                onInput={(e) => props.onHostsPathChange(e.currentTarget.value)}
                class={MONO_INPUT_CLASS}
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDhcpLeasesPathLabel")}
              </label>
              <input
                type="text"
                placeholder="/var/lib/misc/dnsmasq.leases"
                value={props.dhcpLeasesPath}
                onInput={(e) => props.onDhcpLeasesPathChange(e.currentTarget.value)}
                class={MONO_INPUT_CLASS}
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDhcpLeasesDomainLabel")}
              </label>
              <input
                type="text"
                placeholder="lan"
                value={props.dhcpLeasesDomain}
                onInput={(e) => props.onDhcpLeasesDomainChange(e.currentTarget.value)}
                class={MONO_INPUT_CLASS}
              />
            </div>
          </div>
        </div>

        {/* Group 2: LAN Discovery & .local */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-4 space-y-3">
          <p class="text-[11px] font-medium uppercase tracking-wider text-[#8f8f8f] dark:text-[#71717a]">
            {t("settingsLanDiscoveryTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <ToggleRow
              label={t("settingsMdnsLabel")}
              tooltip={t("tooltipMdns")}
              checked={props.mdnsEnabled}
              onChange={props.onMdnsEnabledChange}
            />
            <ToggleRow
              label={t("settingsRdnsLabel")}
              tooltip={t("tooltipRdns")}
              tooltipAlign="right"
              checked={props.rdnsEnabled}
              onChange={props.onRdnsEnabledChange}
            />
            <ToggleRow
              label={t("settingsBlockLocalDomainsLabel")}
              tooltip={t("tooltipBlockLocalDomains")}
              checked={props.blockLocalDomains}
              onChange={props.onBlockLocalDomainsChange}
            />
            <ToggleRow
              label={t("settingsSuppressLocalDomainLogsLabel")}
              tooltip={t("tooltipSuppressLocalDomainLogs")}
              tooltipAlign="right"
              checked={props.suppressLocalDomainLogs}
              onChange={props.onSuppressLocalDomainLogsChange}
            />
          </div>
        </div>

        {/* Group 3: Private Reverse PTR */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-4 space-y-3">
          <p class="text-[11px] font-medium uppercase tracking-wider text-[#8f8f8f] dark:text-[#71717a]">
            {t("settingsLanPtrTitle")}
          </p>
          <ToggleRow
            label={t("settingsPrivatePtrLabel")}
            tooltip={t("tooltipPrivatePtr")}
            checked={props.privatePtrEnabled}
            onChange={props.onPrivatePtrEnabledChange}
          />
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsPrivatePtrUpstreamsLabel")}</span>
              <InfoTooltip text={t("tooltipPrivatePtrUpstreams")} align="left" />
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="udp://192.168.1.1:53"
              value={props.privatePtrUpstreamsText}
              onInput={(e) => props.onPrivatePtrUpstreamsChange(e.currentTarget.value)}
              class={TEXTAREA_MONO_CLASS}
            />
          </div>
        </div>
      </SettingsCard>

      {/* DNS64 / NAT64 Synthesis */}
      <SettingsCard
        icon="i-ri-arrow-left-right-line"
        title={t("settingsCardDns64Title")}
        description={t("settingsCardDns64Desc")}
        tooltip={t("tooltipDns64")}
        tooltipAlign="left"
      >
        <ToggleRow
          label={t("settingsDns64Label")}
          tooltip={t("tooltipDns64")}
          checked={props.dns64Enabled}
          onChange={props.onDns64EnabledChange}
        />

        <Show when={props.dns64Enabled}>
          <div>
            <label class="inline-flex items-center gap-1.5 text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              <span>{t("settingsDns64PrefixesLabel")}</span>
              <InfoTooltip text={t("tooltipDns64Prefixes")} align="left" />
            </label>
            <textarea
              rows={2}
              spellcheck={false}
              placeholder="64:ff9b::/96"
              value={props.dns64PrefixesText}
              onInput={(e) => props.onDns64PrefixesChange(e.currentTarget.value)}
              class={TEXTAREA_MONO_CLASS}
            />
          </div>
        </Show>
      </SettingsCard>
    </div>
  );
}
