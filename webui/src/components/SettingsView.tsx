import { For, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import { t } from "../i18n";
import { AccelerationSettingsSection } from "./settings/AccelerationSettingsSection";
import { BasicSettingsSection } from "./settings/BasicSettingsSection";
import { NetworkTlsSettingsSection } from "./settings/NetworkTlsSettingsSection";
import { SecuritySettingsSection } from "./settings/SecuritySettingsSection";
import { SystemSettingsSection } from "./settings/SystemSettingsSection";
import type { SettingsSectionId, SettingsViewProps } from "./settings/types";

const [activeSection, setActiveSection] = createSignal<SettingsSectionId>("basic");

interface SectionMeta {
  id: SettingsSectionId;
  icon: string;
  title: () => string;
  desc: () => string;
}

const SECTIONS: SectionMeta[] = [
  {
    id: "basic",
    icon: "i-ri-settings-4-line",
    title: () => t("settingsSecBasicTitle"),
    desc: () => t("settingsSecBasicDesc"),
  },
  {
    id: "acceleration",
    icon: "i-ri-speed-up-line",
    title: () => t("settingsSecAccelTitle"),
    desc: () => t("settingsSecAccelDesc"),
  },
  {
    id: "security",
    icon: "i-ri-shield-keyhole-line",
    title: () => t("settingsSecSecurityTitle"),
    desc: () => t("settingsSecSecurityDesc"),
  },
  {
    id: "network",
    icon: "i-ri-global-line",
    title: () => t("settingsSecNetworkTitle"),
    desc: () => t("settingsSecNetworkDesc"),
  },
  {
    id: "system",
    icon: "i-ri-server-line",
    title: () => t("settingsSecSystemTitle"),
    desc: () => t("settingsSecSystemDesc"),
  },
];

function countBoolFlags(flags: boolean[]): number {
  let count = 0;
  for (const flag of flags) {
    if (flag) count += 1;
  }
  return count;
}

export function SettingsView(props: SettingsViewProps) {
  const upstreamCount = createMemo(
    () =>
      props.upstreamsText
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0).length,
  );

  const accelCount = createMemo(() =>
    countBoolFlags([
      props.optimisticCache,
      props.cachePrefetchEnabled,
      props.cachePersistEnabled,
      props.cfCdnEnabled,
      props.ecsEnabled,
      props.splitDnsRules.length > 0,
    ]),
  );

  const securityCount = createMemo(() =>
    countBoolFlags([
      props.dnssecEnabled,
      props.dnsRebindingProtection,
      props.cnameCloakingBlocking,
      props.blockAnyQueries,
      props.safesearch.enabled,
      props.authEnabled,
    ]),
  );

  const networkCount = createMemo(() =>
    countBoolFlags([
      props.dohEnabled,
      props.ddrEnabled,
      props.acmeEnabled,
      props.hostsEnabled,
      props.dhcpLeasesEnabled,
      props.mdnsEnabled,
      props.rdnsEnabled,
      props.privatePtrEnabled,
      props.dns64Enabled,
    ]),
  );

  const systemAttention = createMemo(() =>
    Boolean(props.updateStatus?.update_available || props.updateStatus?.restart_pending),
  );

  const sectionBadgeCount = (id: SettingsSectionId): number => {
    switch (id) {
      case "basic":
        return upstreamCount();
      case "acceleration":
        return accelCount();
      case "security":
        return securityCount();
      case "network":
        return networkCount();
      case "system":
        return 0;
    }
  };

  return (
    <div class="animate-view-enter space-y-5">
      {/* Sticky Top Action Bar */}
      <div class="sticky top-[3.75rem] z-20 rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white/90 dark:bg-[#0a0a0a]/90 backdrop-blur-xl px-4 sm:px-5 py-3.5 shadow-sm">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-0.5 min-w-0">
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
      </div>

      {/* Mobile Horizontal Section Tabs */}
      <nav
        aria-label={t("settingsTitle")}
        class="lg:hidden flex items-center gap-1.5 overflow-x-auto pb-1 -mx-1 px-1"
      >
        <For each={SECTIONS}>
          {(sec) => {
            const active = () => activeSection() === sec.id;
            const count = () => sectionBadgeCount(sec.id);
            return (
              <button
                type="button"
                aria-current={active() ? "page" : undefined}
                onClick={() => setActiveSection(sec.id)}
                class={`shrink-0 h-9 px-3 rounded-lg text-xs font-medium flex items-center gap-1.5 border transition-all duration-150 cursor-pointer ${
                  active()
                    ? "bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] border-transparent shadow-sm"
                    : "bg-white dark:bg-[#0a0a0a] text-[#666666] dark:text-[#a1a1aa] border-[#eaeaea] dark:border-[#262626] hover:text-[#171717] dark:hover:text-[#ededed]"
                }`}
              >
                <span class={`${sec.icon} text-sm shrink-0`} />
                <span>{sec.title()}</span>
                <Show when={sec.id === "system" && systemAttention()}>
                  <span class="h-2 w-2 rounded-full bg-amber-500 shrink-0" />
                </Show>
                <Show when={sec.id !== "system" && count() > 0}>
                  <span
                    class={`px-1.5 py-0.2 rounded-full text-[10px] font-mono tabular-nums ${
                      active()
                        ? "bg-white/20 dark:bg-black/15 text-current"
                        : "bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa]"
                    }`}
                  >
                    {count()}
                  </span>
                </Show>
              </button>
            );
          }}
        </For>
      </nav>

      {/* Desktop Two-Column Layout */}
      <div class="flex flex-col lg:flex-row gap-5 items-start">
        {/* Left Sticky Sidebar */}
        <aside class="hidden lg:flex lg:flex-col w-64 shrink-0 lg:sticky lg:top-[8.75rem] self-start space-y-3">
          <nav
            aria-label={t("settingsTitle")}
            class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-1.5 space-y-1"
          >
            <For each={SECTIONS}>
              {(sec) => {
                const active = () => activeSection() === sec.id;
                const count = () => sectionBadgeCount(sec.id);
                return (
                  <button
                    type="button"
                    aria-current={active() ? "page" : undefined}
                    onClick={() => setActiveSection(sec.id)}
                    class={`w-full text-left px-3 py-2.5 rounded-lg border-0 flex items-start gap-2.5 transition-all duration-150 cursor-pointer ${
                      active()
                        ? "bg-[#f4f4f5] dark:bg-[#171717] text-[#171717] dark:text-[#ededed] ring-1 ring-black/5 dark:ring-white/10"
                        : "bg-transparent text-[#666666] dark:text-[#a1a1aa] hover:bg-[#fafafa] dark:hover:bg-[#111111] hover:text-[#171717] dark:hover:text-[#ededed]"
                    }`}
                  >
                    <span
                      class={`${sec.icon} text-base shrink-0 mt-0.5 ${
                        active()
                          ? "text-[#171717] dark:text-[#ededed]"
                          : "text-[#8f8f8f] dark:text-[#71717a]"
                      }`}
                    />
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center justify-between gap-2">
                        <span class="text-xs font-semibold truncate">{sec.title()}</span>
                        <Show when={sec.id === "system" && systemAttention()}>
                          <span class="h-2 w-2 rounded-full bg-amber-500 shrink-0" />
                        </Show>
                        <Show when={sec.id !== "system" && count() > 0}>
                          <span
                            class={`px-1.5 py-0.2 rounded-full text-[10px] font-mono tabular-nums shrink-0 ${
                              active()
                                ? "bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626]"
                                : "bg-[#f4f4f5] dark:bg-[#141414] text-[#8f8f8f] dark:text-[#71717a]"
                            }`}
                          >
                            {count()}
                          </span>
                        </Show>
                      </div>
                      <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] truncate mt-0.5">
                        {sec.desc()}
                      </p>
                    </div>
                  </button>
                );
              }}
            </For>
          </nav>

          <p class="px-2 text-[11px] text-[#8f8f8f] dark:text-[#71717a] leading-relaxed">
            {t("settingsUnsavedNote")}
          </p>
        </aside>

        {/* Right Section Content */}
        <div class="flex-1 min-w-0 w-full">
          <Switch>
            <Match when={activeSection() === "basic"}>
              <div class="animate-view-enter">
                <BasicSettingsSection {...props} />
              </div>
            </Match>
            <Match when={activeSection() === "acceleration"}>
              <div class="animate-view-enter">
                <AccelerationSettingsSection {...props} />
              </div>
            </Match>
            <Match when={activeSection() === "security"}>
              <div class="animate-view-enter">
                <SecuritySettingsSection {...props} />
              </div>
            </Match>
            <Match when={activeSection() === "network"}>
              <div class="animate-view-enter">
                <NetworkTlsSettingsSection {...props} />
              </div>
            </Match>
            <Match when={activeSection() === "system"}>
              <div class="animate-view-enter">
                <SystemSettingsSection {...props} />
              </div>
            </Match>
          </Switch>
        </div>
      </div>
    </div>
  );
}
