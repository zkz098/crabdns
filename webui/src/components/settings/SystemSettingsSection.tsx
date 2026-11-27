import { For, Show } from "solid-js";
import { t } from "../../i18n";
import type { StorageProfile } from "../../types/StorageProfile";
import { PortPrecheckPanel } from "../PortPrecheckPanel";
import { SelectMenu, type SelectOption } from "../SelectMenu";
import { SetupGuideCard } from "../SetupGuideCard";
import { NUMBER_INPUT_CLASS, SettingsCard, SettingsSectionHeader } from "./SettingsControls";
import type { SettingsViewProps } from "./types";

const STORAGE_PROFILE_OPTIONS: SelectOption<StorageProfile>[] = [
  { value: "auto", label: () => t("settingsStorageProfileAuto") },
  { value: "embedded", label: () => t("settingsStorageProfileEmbedded") },
  { value: "balanced", label: () => t("settingsStorageProfileBalanced") },
  { value: "performance", label: () => t("settingsStorageProfilePerformance") },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function SystemSettingsSection(props: SettingsViewProps) {
  const updatePhase = () => props.updateStatus?.phase ?? "idle";
  const isCheckingUpdate = () =>
    props.updateAction === "check" || (props.updateAction === null && updatePhase() === "checking");
  const isApplyingUpdate = () =>
    props.updateAction === "apply" ||
    updatePhase() === "downloading" ||
    updatePhase() === "installing";
  const isRestartingService = () => props.updateAction === "restart";
  const isUpdateBusy = () =>
    (props.updateAction ?? null) !== null || Boolean(props.updateStatus?.busy);

  const updateTotalBytes = () =>
    props.updateStatus?.total_bytes ?? props.updateStatus?.asset_size ?? null;
  const updateDownloadedBytes = () => props.updateStatus?.downloaded_bytes ?? 0;
  const updateProgressPercent = (): number | null => {
    if (updatePhase() === "installing") return 100;
    const total = updateTotalBytes();
    if (total !== null && total > 0) {
      return Math.min(100, Math.round((updateDownloadedBytes() / total) * 100));
    }
    return null;
  };
  const updatePhaseLabel = () => {
    const phase = updatePhase();
    if (phase === "installing") return t("updatePhaseInstalling");
    if (phase === "downloading") return t("updatePhaseDownloading");
    return t("updatePhasePreparing");
  };

  return (
    <div class="space-y-4">
      <SettingsSectionHeader
        icon="i-ri-server-line"
        title={t("settingsSecSystemTitle")}
        description={t("settingsSecSystemDesc")}
      />

      {/* Storage & Disk Protection */}
      <SettingsCard
        icon="i-ri-database-line"
        title={t("settingsStorageCardTitle")}
        description={t("settingsStorageCardDesc")}
      >
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsStorageProfileLabel")}
            </label>
            <SelectMenu
              variant="subtle"
              size="md"
              value={props.storageProfile}
              options={STORAGE_PROFILE_OPTIONS}
              onChange={props.onStorageProfileChange}
              class="w-full"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1.5">
              {t("settingsDiskMinFreeLabel")}
            </label>
            <input
              type="number"
              min={0}
              value={props.diskMinFreeMb}
              onInput={(e) => props.onDiskMinFreeMbChange(Number(e.currentTarget.value))}
              class={NUMBER_INPUT_CLASS}
            />
          </div>
        </div>
      </SettingsCard>

      {/* System Backup & Restore */}
      <Show when={props.onExportBackup || props.onImportBackup}>
        <SettingsCard
          icon="i-ri-download-cloud-2-line"
          title={t("backupTitle")}
          description={t("backupSubtitle")}
          action={
            <div class="flex flex-wrap items-center gap-2 shrink-0">
              <Show when={props.onExportBackup}>
                <button
                  type="button"
                  disabled={props.backupBusy}
                  onClick={() => props.onExportBackup?.()}
                  class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
                >
                  <span class="i-ri-download-cloud-2-line text-sm" />
                  <span>{t("backupExportBtn")}</span>
                </button>
              </Show>

              <Show when={props.onImportBackup}>
                <label
                  class={`h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 border-0 transition-colors ${
                    props.backupBusy ? "opacity-50 pointer-events-none" : "cursor-pointer"
                  }`}
                >
                  <input
                    type="file"
                    accept="application/json,.json"
                    disabled={props.backupBusy}
                    class="hidden"
                    onChange={(e) => {
                      const file = e.currentTarget.files?.[0];
                      if (file) {
                        void props.onImportBackup?.(file);
                        e.currentTarget.value = "";
                      }
                    }}
                  />
                  <span class="i-ri-upload-cloud-2-line text-sm" />
                  <span>{t("backupImportBtn")}</span>
                </label>
              </Show>
            </div>
          }
        >
          <Show when={props.backupMessage}>
            <div
              class={`rounded-lg border px-3 py-2 text-xs font-medium flex items-start gap-2 break-all ${
                props.backupIsError
                  ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                  : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
              }`}
            >
              <span
                class={`${
                  props.backupIsError ? "i-ri-error-warning-line" : "i-ri-check-line"
                } text-sm shrink-0 mt-0.5`}
              />
              <span class="min-w-0">{props.backupMessage}</span>
            </div>
          </Show>
        </SettingsCard>
      </Show>

      {/* Configuration History & Rollback */}
      <Show when={props.onRollbackConfig}>
        <SettingsCard
          icon="i-ri-history-line"
          title={t("configHistoryTitle")}
          description={t("configHistorySubtitle")}
          action={
            <Show when={props.onRefreshHistory}>
              <button
                type="button"
                disabled={props.rollbackBusy}
                onClick={() => props.onRefreshHistory?.()}
                class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50 shrink-0"
              >
                <span class="i-ri-refresh-line text-sm" />
              </button>
            </Show>
          }
        >
          <Show
            when={(props.configHistory?.length ?? 0) > 0}
            fallback={
              <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                {t("configHistoryEmpty")}
              </p>
            }
          >
            <div class="max-h-52 overflow-y-auto divide-y divide-[#eaeaea] dark:divide-[#262626] border border-[#eaeaea] dark:border-[#262626] rounded-lg bg-[#fafafa] dark:bg-[#050505]">
              <For each={props.configHistory ?? []}>
                {(snap) => (
                  <div class="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center gap-2 font-mono text-[11px] text-[#171717] dark:text-[#ededed]">
                        <span>{new Date(Number(snap.created_at) * 1000).toLocaleString()}</span>
                        <span class="px-1.5 py-0.5 rounded bg-[#eaeaea] dark:bg-[#1f1f1f] text-[10px]">
                          {snap.reason}
                        </span>
                      </div>
                      <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa] truncate">
                        {snap.listen_dns} · {snap.upstreams_count} upstreams ·{" "}
                        {snap.split_dns_count} split rules
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={props.rollbackBusy}
                      onClick={() => props.onRollbackConfig?.(snap.id)}
                      class="h-7 px-2.5 rounded-md text-[11px] font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] cursor-pointer transition-colors disabled:opacity-50 shrink-0"
                    >
                      {t("configHistoryRollbackBtn")}
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </SettingsCard>
      </Show>

      {/* System Self-Update (SigilUp) */}
      <Show when={props.onCheckUpdate || props.onApplyUpdate}>
        <SettingsCard
          icon="i-ri-refresh-line"
          title={t("updateTitle")}
          description={t("updateSubtitle")}
          action={
            <div class="flex flex-wrap items-center gap-2 shrink-0">
              <Show when={props.onCheckUpdate}>
                <button
                  type="button"
                  disabled={isUpdateBusy()}
                  onClick={() => props.onCheckUpdate?.()}
                  class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50"
                >
                  <span
                    class={
                      isCheckingUpdate()
                        ? "i-ri-loader-4-line animate-spin text-sm"
                        : "i-ri-refresh-line text-sm"
                    }
                  />
                  <span>{isCheckingUpdate() ? t("updateCheckingBtn") : t("updateCheckBtn")}</span>
                </button>
              </Show>

              <Show
                when={
                  props.onApplyUpdate &&
                  props.updateStatus?.update_available &&
                  !props.updateStatus?.restart_pending
                }
              >
                <button
                  type="button"
                  disabled={isUpdateBusy()}
                  onClick={() => props.onApplyUpdate?.()}
                  class="h-8 px-3 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer border-0 transition-colors disabled:opacity-50"
                >
                  <span
                    class={
                      isApplyingUpdate()
                        ? "i-ri-loader-4-line animate-spin text-sm"
                        : "i-ri-sparkling-2-line text-sm"
                    }
                  />
                  <span>{isApplyingUpdate() ? t("updateApplyingBtn") : t("updateApplyBtn")}</span>
                </button>
              </Show>

              <Show when={props.onRestartService}>
                <button
                  type="button"
                  disabled={isUpdateBusy()}
                  onClick={() => props.onRestartService?.()}
                  class={`h-8 px-3 rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer transition-colors disabled:opacity-50 ${
                    props.updateStatus?.restart_pending
                      ? "bg-amber-600 hover:bg-amber-700 text-white border-0"
                      : "bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626]"
                  }`}
                >
                  <span
                    class={
                      isRestartingService()
                        ? "i-ri-loader-4-line animate-spin text-sm"
                        : "i-ri-restart-line text-sm"
                    }
                  />
                  <span>
                    {isRestartingService() ? t("updateRestartingBtn") : t("updateRestartBtn")}
                  </span>
                </button>
              </Show>
            </div>
          }
        >
          <Show when={props.updateStatus}>
            {(st) => (
              <div class="flex flex-wrap items-center gap-2">
                <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border border-zinc-500/20">
                  {t("updateCurrentVersion")}: v{st().current_version}
                </span>
                <Show when={st().update_available && st().latest_version}>
                  <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                    {t("updateLatestVersion")}: v{st().latest_version}
                  </span>
                </Show>
                <Show when={st().restart_pending}>
                  <span class="px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                    {t("updateRestartPendingBadge")}
                  </span>
                </Show>
              </div>
            )}
          </Show>

          <Show when={isApplyingUpdate()}>
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 space-y-2">
              <div class="flex items-center justify-between gap-2 text-xs">
                <span class="flex items-center gap-1.5 font-medium text-[#171717] dark:text-[#ededed]">
                  <span class="i-ri-loader-4-line animate-spin text-sm shrink-0" />
                  <span>{updatePhaseLabel()}</span>
                </span>
                <span class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                  {(() => {
                    const total = updateTotalBytes();
                    const done = updateDownloadedBytes();
                    const pct = updateProgressPercent();
                    if (total !== null && total > 0 && pct !== null) {
                      return `${formatBytes(done)} / ${formatBytes(total)} (${pct}%)`;
                    }
                    if (done > 0) {
                      return formatBytes(done);
                    }
                    if (pct !== null) {
                      return `${pct}%`;
                    }
                    return "";
                  })()}
                </span>
              </div>
              <div
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={updateProgressPercent() ?? undefined}
                class="h-2 w-full rounded-full overflow-hidden bg-[#eaeaea] dark:bg-[#262626]"
              >
                <Show
                  when={updateProgressPercent() !== null}
                  fallback={<div class="h-full w-1/3 rounded-full bg-emerald-500 animate-pulse" />}
                >
                  <div
                    class={`h-full rounded-full transition-all duration-200 ease-out ${
                      updatePhase() === "installing"
                        ? "bg-emerald-500 animate-pulse"
                        : "bg-[#171717] dark:bg-[#ededed]"
                    }`}
                    style={{ width: `${updateProgressPercent()}%` }}
                  />
                </Show>
              </div>
            </div>
          </Show>

          <Show when={props.updateMessage}>
            <div
              class={`rounded-lg border px-3 py-2 text-xs font-medium flex items-start gap-2 break-all ${
                props.updateIsError
                  ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                  : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
              }`}
            >
              <span
                class={`${
                  props.updateIsError ? "i-ri-error-warning-line" : "i-ri-check-line"
                } text-sm shrink-0 mt-0.5`}
              />
              <span class="min-w-0">{props.updateMessage}</span>
            </div>
          </Show>

          <Show when={props.updateStatus?.notes}>
            {(notes) => (
              <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 font-mono text-xs text-[#171717] dark:text-[#ededed] whitespace-pre-wrap">
                {notes()}
              </div>
            )}
          </Show>
        </SettingsCard>
      </Show>

      {/* Startup Bindings & Port Pre-check */}
      <Show when={props.configData}>
        {(cfg) => (
          <SettingsCard icon="i-ri-hard-drive-2-line" title={t("settingsReadonlyTitle")}>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
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
                  {t("settingsWebTlsListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_web_tls ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDotListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_dot ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDoqListen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_doq ?? "-"}
                </span>
              </div>
              <div class="bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDoh3Listen")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().listen_doh3 ?? "-"}
                </span>
              </div>
              <div class="sm:col-span-2 bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3">
                <span class="text-[#8f8f8f] dark:text-[#71717a] block mb-0.5">
                  {t("settingsDataDir")}
                </span>
                <span class="font-mono text-[#171717] dark:text-[#ededed] break-all">
                  {cfg().data_dir}
                </span>
              </div>
            </div>
            <PortPrecheckPanel
              listenDns={cfg().listen_dns}
              listenWeb={cfg().listen_web}
              listenWebTls={cfg().listen_web_tls}
              listenDot={cfg().listen_dot}
              listenDoq={cfg().listen_doq}
            />
          </SettingsCard>
        )}
      </Show>

      {/* Client Setup Guide (renders its own outer card) */}
      <SetupGuideCard configData={props.configData} tlsStatus={props.tlsStatus} />
    </div>
  );
}
