import { For, Show } from "solid-js";
import { t, toggleLocale } from "../i18n";
import { theme, toggleTheme } from "../theme";
import type { TabKey } from "./types";

interface HeaderProps {
  tab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  wsConnected: boolean;
  authEnabled?: boolean;
  onLogout?: () => void;
}

const NAV_ITEMS: Array<{ key: TabKey; label: () => string; icon: string }> = [
  { key: "dashboard", label: () => t("navDashboard"), icon: "i-ri-dashboard-3-line" },
  { key: "logs", label: () => t("navLogs"), icon: "i-ri-terminal-box-line" },
  { key: "rules", label: () => t("navRules"), icon: "i-ri-shield-flash-line" },
  { key: "settings", label: () => t("navSettings"), icon: "i-ri-settings-3-line" },
];

export function Header(props: HeaderProps) {
  return (
    <header class="sticky top-0 z-40 border-b border-[#eaeaea] dark:border-[#262626] bg-white/80 dark:bg-black/80 backdrop-blur-xl transition-colors">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        {/* Brand + Live Status */}
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-8 h-8 rounded-lg bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] flex items-center justify-center shrink-0 shadow-sm transition-transform duration-200 hover:scale-105">
            <span class="i-ri-shield-check-fill text-base" />
          </div>
          <div class="flex items-center gap-2.5 min-w-0">
            <h1 class="text-sm sm:text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed] truncate">
              CrabDNS
            </h1>
            <span
              class={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border transition-colors ${
                props.wsConnected
                  ? "bg-emerald-500/10 text-emerald-700 border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/25"
                  : "bg-zinc-500/10 text-zinc-600 border-zinc-500/20 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"
              }`}
            >
              <span class="relative flex h-1.5 w-1.5">
                <Show when={props.wsConnected}>
                  <span class="animate-pulse-ring absolute inline-flex h-full w-full rounded-full bg-emerald-500" />
                </Show>
                <span
                  class={`relative inline-flex rounded-full h-1.5 w-1.5 ${
                    props.wsConnected ? "bg-emerald-500" : "bg-zinc-400 dark:bg-zinc-500"
                  }`}
                />
              </span>
              <span class="hidden xs:inline">
                {props.wsConnected ? t("statusLive") : t("statusOffline")}
              </span>
            </span>
          </div>
        </div>

        {/* Desktop Navigation */}
        <nav class="hidden md:flex items-center gap-1 p-1 rounded-xl bg-[#f4f4f5] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#222222]">
          <For each={NAV_ITEMS}>
            {(item) => {
              const active = () => props.tab === item.key;
              return (
                <button
                  type="button"
                  onClick={() => props.onSelectTab(item.key)}
                  class={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all duration-200 cursor-pointer border-0 active:scale-[0.97] ${
                    active()
                      ? "bg-white dark:bg-[#1f1f1f] text-[#171717] dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10"
                      : "bg-transparent text-[#666666] dark:text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed]"
                  }`}
                >
                  <span class={`${item.icon} text-sm`} />
                  <span>{item.label()}</span>
                </button>
              );
            }}
          </For>
        </nav>

        {/* Right Controls: Theme + Language */}
        <div class="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={theme() === "dark" ? t("themeLight") : t("themeDark")}
            title={theme() === "dark" ? t("themeLight") : t("themeDark")}
            class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-200 active:scale-[0.96]"
          >
            <span
              class={`text-sm transition-transform duration-300 ${
                theme() === "dark"
                  ? "i-ri-sun-line text-amber-400 rotate-0"
                  : "i-ri-moon-line text-zinc-700 rotate-0"
              }`}
            />
            <span class="hidden sm:inline">
              {theme() === "dark" ? t("themeLight") : t("themeDark")}
            </span>
          </button>

          <button
            type="button"
            onClick={toggleLocale}
            class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-200 active:scale-[0.96]"
          >
            <span class="i-ri-translate-2 text-sm text-[#666666] dark:text-[#a1a1aa]" />
            <span>{t("langToggle")}</span>
          </button>
          <Show when={props.authEnabled && props.onLogout}>
            <button
              type="button"
              onClick={() => props.onLogout?.()}
              title={t("authLogout")}
              class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-200 active:scale-[0.96]"
            >
              <span class="i-ri-logout-box-r-line text-sm" />
              <span class="hidden sm:inline">{t("authLogout")}</span>
            </button>
          </Show>
        </div>
      </div>
    </header>
  );
}
