import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { t, toggleLocale } from "../i18n";
import { theme, toggleTheme } from "../theme";
import type { BlockingStatusResponse } from "../types/BlockingStatusResponse";
import type { TabKey } from "./types";

interface HeaderProps {
  tab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  wsConnected: boolean;
  blockingStatus?: BlockingStatusResponse | null;
  onPauseBlocking?: (durationSecs: number | null) => void;
  onResumeBlocking?: () => void;
  authEnabled?: boolean;
  onLogout?: () => void;
}

const NAV_ITEMS: Array<{ key: TabKey; label: () => string; icon: string }> = [
  { key: "dashboard", label: () => t("navDashboard"), icon: "i-ri-dashboard-3-line" },
  { key: "diagnostics", label: () => t("navDiagnostics"), icon: "i-ri-heart-pulse-line" },
  { key: "logs", label: () => t("navLogs"), icon: "i-ri-terminal-box-line" },
  { key: "rules", label: () => t("navRules"), icon: "i-ri-shield-flash-line" },
  { key: "rewrites", label: () => t("navRewrites"), icon: "i-ri-arrow-left-right-line" },
  { key: "clients", label: () => t("navClients"), icon: "i-ri-computer-line" },
  { key: "settings", label: () => t("navSettings"), icon: "i-ri-settings-3-line" },
];

export function Header(props: HeaderProps) {
  const [pauseMenuOpen, setPauseMenuOpen] = createSignal(false);
  let pauseContainerRef: HTMLDivElement | undefined;

  createEffect(() => {
    if (!pauseMenuOpen()) return;

    const handlePointerDown = (e: PointerEvent) => {
      if (pauseContainerRef && !pauseContainerRef.contains(e.target as Node)) {
        setPauseMenuOpen(false);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setPauseMenuOpen(false);
      }
    };

    document.addEventListener("pointerdown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown);
    onCleanup(() => {
      document.removeEventListener("pointerdown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown);
    });
  });

  const formatRemaining = (secs: number | null | undefined) => {
    if (secs === null || secs === undefined) return "";
    const mins = Math.floor(secs / 60);
    const rem = secs % 60;
    return mins > 0 ? `${mins}m ${rem}s` : `${rem}s`;
  };

  return (
    <header class="sticky top-0 z-40 border-b border-[#eaeaea] dark:border-[#262626] bg-white/80 dark:bg-black/80 backdrop-blur-xl transition-colors">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        {/* Brand + Live Status */}
        <div class="flex items-center gap-2.5 sm:gap-3 shrink-0">
          <div class="w-8 h-8 rounded-lg bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] flex items-center justify-center shrink-0 shadow-sm transition-transform duration-200 hover:scale-105">
            <span class="i-ri-shield-check-fill text-base" />
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <h1 class="text-sm sm:text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed] whitespace-nowrap">
              CrabDNS
            </h1>
            <span
              class={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border transition-colors whitespace-nowrap shrink-0 ${
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
              <span class="hidden sm:inline">
                {props.wsConnected ? t("statusLive") : t("statusOffline")}
              </span>
            </span>
          </div>
        </div>

        {/* Desktop Navigation */}
        <nav class="hidden lg:flex items-center gap-0.5 xl:gap-1 p-1 rounded-xl bg-[#f4f4f5] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#222222] shrink-0">
          <For each={NAV_ITEMS}>
            {(item) => {
              const active = () => props.tab === item.key;
              return (
                <button
                  type="button"
                  onClick={() => props.onSelectTab(item.key)}
                  class={`px-2.5 xl:px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 whitespace-nowrap shrink-0 transition-all duration-200 cursor-pointer border-0 active:scale-[0.97] ${
                    active()
                      ? "bg-white dark:bg-[#1f1f1f] text-[#171717] dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10"
                      : "bg-transparent text-[#666666] dark:text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed]"
                  }`}
                >
                  <span class={`${item.icon} text-sm shrink-0`} />
                  <span>{item.label()}</span>
                </button>
              );
            }}
          </For>
        </nav>

        {/* Right Controls: Pause Blocking + Theme + Language */}
        <div class="flex items-center gap-2 shrink-0">
          <Show when={props.onPauseBlocking && props.onResumeBlocking}>
            <Show
              when={props.blockingStatus?.paused}
              fallback={
                <div
                  ref={(el) => {
                    pauseContainerRef = el;
                  }}
                  class="relative"
                >
                  <button
                    type="button"
                    aria-haspopup="menu"
                    aria-expanded={pauseMenuOpen()}
                    title={t("blockingPauseBtn")}
                    onClick={() => setPauseMenuOpen((v) => !v)}
                    class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 whitespace-nowrap cursor-pointer transition-all duration-200 active:scale-[0.96]"
                  >
                    <span class="i-ri-pause-circle-line text-sm text-amber-500 shrink-0" />
                    <span class="hidden xl:inline">{t("blockingPauseBtn")}</span>
                  </button>
                  <Show when={pauseMenuOpen()}>
                    <div
                      role="menu"
                      class="animate-dropdown-in absolute right-0 mt-1.5 w-40 rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white/95 dark:bg-[#0a0a0a]/95 backdrop-blur-xl shadow-lg shadow-black/5 dark:shadow-black/40 p-1 z-50"
                    >
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          setPauseMenuOpen(false);
                          props.onPauseBlocking?.(300);
                        }}
                        class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] bg-transparent border-0 cursor-pointer transition-colors"
                      >
                        {t("blockingPause5m")}
                      </button>
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          setPauseMenuOpen(false);
                          props.onPauseBlocking?.(1800);
                        }}
                        class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] bg-transparent border-0 cursor-pointer transition-colors"
                      >
                        {t("blockingPause30m")}
                      </button>
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          setPauseMenuOpen(false);
                          props.onPauseBlocking?.(null);
                        }}
                        class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 bg-transparent border-0 cursor-pointer transition-colors"
                      >
                        {t("blockingPauseForever")}
                      </button>
                    </div>
                  </Show>
                </div>
              }
            >
              <button
                type="button"
                onClick={() => props.onResumeBlocking?.()}
                class="h-8 px-2.5 rounded-lg text-xs font-medium bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-300 border border-amber-500/30 flex items-center gap-1.5 cursor-pointer transition-all duration-200 active:scale-[0.96]"
              >
                <span class="i-ri-play-circle-line text-sm" />
                <span>
                  {t("blockingResume")}
                  {props.blockingStatus?.remaining_secs !== null &&
                  props.blockingStatus?.remaining_secs !== undefined
                    ? ` (${formatRemaining(props.blockingStatus.remaining_secs)})`
                    : ""}
                </span>
              </button>
            </Show>
          </Show>
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
            <span class="hidden xl:inline">
              {theme() === "dark" ? t("themeLight") : t("themeDark")}
            </span>
          </button>

          <button
            type="button"
            onClick={toggleLocale}
            class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 whitespace-nowrap cursor-pointer transition-all duration-200 active:scale-[0.96]"
          >
            <span class="i-ri-translate-2 text-sm text-[#666666] dark:text-[#a1a1aa] shrink-0" />
            <span>{t("langToggle")}</span>
          </button>
          <Show when={props.authEnabled && props.onLogout}>
            <button
              type="button"
              onClick={() => props.onLogout?.()}
              title={t("authLogout")}
              class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 whitespace-nowrap cursor-pointer transition-all duration-200 active:scale-[0.96]"
            >
              <span class="i-ri-logout-box-r-line text-sm shrink-0" />
              <span class="hidden xl:inline">{t("authLogout")}</span>
            </button>
          </Show>
        </div>
      </div>
    </header>
  );
}
