import { Show } from "solid-js";
import { t } from "../i18n";
import type { ConfigResponse } from "../types/ConfigResponse";

interface SettingsViewProps {
  configData: ConfigResponse | null;
  upstreamsText: string;
  onUpstreamsChange: (val: string) => void;
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
