import { For, Show } from "solid-js";
import { t } from "../i18n";
import type { BlockMode } from "../types/BlockMode";
import type { ConfigResponse } from "../types/ConfigResponse";
import type { UpstreamStatus } from "../types/UpstreamStatus";
import type { UpstreamStrategy } from "../types/UpstreamStrategy";

interface SettingsViewProps {
  configData: ConfigResponse | null;
  upstreamsText: string;
  onUpstreamsChange: (val: string) => void;
  upstreamStrategy: UpstreamStrategy;
  onUpstreamStrategyChange: (val: UpstreamStrategy) => void;
  upstreamHealth: UpstreamStatus[];
  probingUpstreams: boolean;
  onProbeUpstreams: () => void;
  blockMode: BlockMode;
  onBlockModeChange: (val: BlockMode) => void;
  allowCidrsText: string;
  onAllowCidrsChange: (val: string) => void;
  denyCidrsText: string;
  onDenyCidrsChange: (val: string) => void;
  rateLimitQps: number;
  onRateLimitChange: (val: number) => void;
  cacheSize: number;
  onCacheSizeChange: (val: number) => void;
  upstreamTimeoutMs: number;
  onUpstreamTimeoutChange: (val: number) => void;
  logRetentionHours: number;
  onLogRetentionChange: (val: number) => void;
  optimisticCache: boolean;
  onOptimisticCacheChange: (val: boolean) => void;
  configMessage: string;
  configIsError: boolean;
  onSave: () => void;
  authEnabled: boolean;
  onAuthEnabledChange: (val: boolean) => void;
  authUsername: string;
  onAuthUsernameChange: (val: string) => void;
  authPassword: string;
  onAuthPasswordChange: (val: string) => void;
  authMessage: string;
  authIsError: boolean;
  onSaveAuth: () => void;
}

export function SettingsView(props: SettingsViewProps) {
  return (
    <div class="animate-view-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-6">
      {/* Header */}
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="space-y-1">
          <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
            {t("settingsTitle")}
          </h2>
          <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
            {t("settingsSubtitle")}
          </p>
        </div>

        <div class="flex items-center justify-end gap-3 shrink-0">
          <Show when={props.configMessage}>
            <span
              class={`animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                props.configIsError
                  ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                  : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
              }`}
            >
              <span class={props.configIsError ? "i-ri-error-warning-line" : "i-ri-check-line"} />
              {props.configMessage}
            </span>
          </Show>
          <button
            type="button"
            onClick={props.onSave}
            class="w-full sm:w-auto h-9 px-4 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center justify-center gap-1.5 cursor-pointer border-0 transition-all duration-200 active:scale-[0.97]"
          >
            <span class="i-ri-save-3-line text-sm" />
            <span>{t("settingsSave")}</span>
          </button>
        </div>
      </div>

      {/* Form Fields */}
      <div class="space-y-5">
        <div>
          <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
            {t("settingsUpstreamsLabel")}
          </label>
          <textarea
            rows={4}
            spellcheck={false}
            value={props.upstreamsText}
            onInput={(e) => props.onUpstreamsChange(e.currentTarget.value)}
            class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
          />
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-1.5">
            {t("settingsUpstreamsHint")}
          </p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsCacheSizeLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.cacheSize}
              onInput={(e) => props.onCacheSizeChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsTimeoutLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.upstreamTimeoutMs}
              onInput={(e) => props.onUpstreamTimeoutChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsRetentionLabel")}
            </label>
            <input
              type="number"
              min={1}
              value={props.logRetentionHours}
              onInput={(e) => props.onLogRetentionChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10"
            />
          </div>
        </div>

        {/* Custom Vercel-style Toggle Switch */}
        <div class="flex items-center justify-between gap-4 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5">
          <span class="text-sm text-[#171717] dark:text-[#ededed] leading-snug">
            {t("settingsOptimisticLabel")}
          </span>
          <button
            type="button"
            role="switch"
            aria-checked={props.optimisticCache}
            onClick={() => props.onOptimisticCacheChange(!props.optimisticCache)}
            class={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-0 p-0.5 transition-colors duration-200 ease-in-out ${
              props.optimisticCache
                ? "bg-[#171717] dark:bg-[#ededed]"
                : "bg-[#d4d4d8] dark:bg-[#3f3f46]"
            }`}
          >
            <span
              class={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white dark:bg-[#0a0a0a] shadow-sm transition-transform duration-200 ease-in-out ${
                props.optimisticCache ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>

        {/* Upstream Strategy & Block Response Mode */}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsStrategyLabel")}
            </label>
            <select
              value={props.upstreamStrategy}
              onChange={(e) =>
                props.onUpstreamStrategyChange(e.currentTarget.value as UpstreamStrategy)
              }
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
            >
              <option value="failover">{t("settingsStrategyFailover")}</option>
              <option value="parallel">{t("settingsStrategyParallel")}</option>
              <option value="least_latency">{t("settingsStrategyLeastLatency")}</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsBlockModeLabel")}
            </label>
            <select
              value={props.blockMode}
              onChange={(e) => props.onBlockModeChange(e.currentTarget.value as BlockMode)}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
            >
              <option value="zero_ip">{t("settingsBlockZeroIp")}</option>
              <option value="nx_domain">{t("settingsBlockNxDomain")}</option>
              <option value="no_data">{t("settingsBlockNoData")}</option>
            </select>
          </div>
        </div>

        {/* Upstream Health */}
        <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsUpstreamHealthTitle")}
            </span>
            <button
              type="button"
              disabled={props.probingUpstreams}
              onClick={props.onProbeUpstreams}
              class="h-7 px-2.5 rounded-md text-xs font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] cursor-pointer hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50"
            >
              {t("settingsProbeNow")}
            </button>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <For each={props.upstreamHealth}>
              {(item) => (
                <div class="flex items-center justify-between gap-2 rounded-md border border-[#eaeaea] dark:border-[#222222] bg-white dark:bg-[#0a0a0a] px-2.5 py-2 text-xs">
                  <div class="flex items-center gap-2 min-w-0">
                    <span
                      class={`h-2 w-2 rounded-full shrink-0 ${
                        item.healthy ? "bg-emerald-500" : "bg-rose-500"
                      }`}
                    />
                    <span class="font-mono truncate text-[#171717] dark:text-[#ededed]">
                      {item.endpoint}
                    </span>
                  </div>
                  <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {item.healthy ? t("settingsUpstreamHealthy") : t("settingsUpstreamUnhealthy")} ·{" "}
                    {item.ewma_latency_ms}ms
                  </span>
                </div>
              )}
            </For>
          </div>
        </div>

        {/* DNS Client ACL & Rate Limiting */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
            {t("settingsAclTitle")}
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsAllowCidrsLabel")}
              </label>
              <textarea
                rows={3}
                spellcheck={false}
                placeholder="192.168.0.0/16"
                value={props.allowCidrsText}
                onInput={(e) => props.onAllowCidrsChange(e.currentTarget.value)}
                class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("settingsDenyCidrsLabel")}
              </label>
              <textarea
                rows={3}
                spellcheck={false}
                placeholder="203.0.113.0/24"
                value={props.denyCidrsText}
                onInput={(e) => props.onDenyCidrsChange(e.currentTarget.value)}
                class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
          <div class="max-w-xs">
            <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
              {t("settingsRateLimitLabel")}
            </label>
            <input
              type="number"
              min={0}
              value={props.rateLimitQps}
              onInput={(e) => props.onRateLimitChange(Number(e.currentTarget.value))}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] tabular-nums outline-none"
            />
          </div>
        </div>

        {/* Web UI Authentication */}
        <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-3">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <p class="text-xs font-medium text-[#171717] dark:text-[#ededed]">
              {t("settingsAuthTitle")}
            </p>
            <div class="flex items-center gap-2">
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
                class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0"
              >
                {t("settingsAuthSave")}
              </button>
            </div>
          </div>

          <div class="flex items-center justify-between gap-4 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3">
            <span class="text-xs text-[#171717] dark:text-[#ededed]">
              {t("settingsAuthEnableLabel")}
            </span>
            <button
              type="button"
              role="switch"
              aria-checked={props.authEnabled}
              onClick={() => props.onAuthEnabledChange(!props.authEnabled)}
              class={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-0 p-0.5 transition-colors duration-200 ease-in-out ${
                props.authEnabled
                  ? "bg-[#171717] dark:bg-[#ededed]"
                  : "bg-[#d4d4d8] dark:bg-[#3f3f46]"
              }`}
            >
              <span
                class={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white dark:bg-[#0a0a0a] shadow-sm transition-transform duration-200 ease-in-out ${
                  props.authEnabled ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1.5">
                {t("authUsernameLabel")}
              </label>
              <input
                type="text"
                value={props.authUsername}
                onInput={(e) => props.onAuthUsernameChange(e.currentTarget.value)}
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
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
                class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Readonly Startup Bindings */}
      <Show when={props.configData}>
        {(cfg) => (
          <div class="border-t border-[#eaeaea] dark:border-[#262626] pt-5 space-y-2.5">
            <p class="text-xs font-medium text-[#666666] dark:text-[#a1a1aa]">
              {t("settingsReadonlyTitle")}
            </p>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDnsListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_dns}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsWebListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_web}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDataDir")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().data_dir}
                </span>
              </div>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
