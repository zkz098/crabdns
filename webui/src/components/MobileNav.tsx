import { For } from "solid-js";
import { t } from "../i18n";
import type { TabKey } from "./types";

interface MobileNavProps {
  tab: TabKey;
  onSelectTab: (tab: TabKey) => void;
}

const NAV_ITEMS: Array<{ key: TabKey; label: () => string; icon: string }> = [
  { key: "dashboard", label: () => t("navDashboard"), icon: "i-ri-dashboard-3-line" },
  { key: "logs", label: () => t("navLogs"), icon: "i-ri-terminal-box-line" },
  { key: "rules", label: () => t("navRules"), icon: "i-ri-shield-flash-line" },
  { key: "rewrites", label: () => t("navRewrites"), icon: "i-ri-arrow-left-right-line" },
  { key: "clients", label: () => t("navClients"), icon: "i-ri-computer-line" },
  { key: "settings", label: () => t("navSettings"), icon: "i-ri-settings-3-line" },
];

export function MobileNav(props: MobileNavProps) {
  return (
    <nav
      aria-label="Mobile Navigation"
      class="md:hidden fixed bottom-0 inset-x-0 z-40 border-t border-[#eaeaea] dark:border-[#262626] bg-white/90 dark:bg-[#0a0a0a]/90 backdrop-blur-xl pb-[env(safe-area-inset-bottom)]"
    >
      <div class="grid grid-cols-6 h-15">
        <For each={NAV_ITEMS}>
          {(item) => {
            const active = () => props.tab === item.key;
            return (
              <button
                type="button"
                onClick={() => props.onSelectTab(item.key)}
                class={`relative flex flex-col items-center justify-center gap-1 bg-transparent border-0 cursor-pointer transition-colors duration-200 active:scale-95 ${
                  active()
                    ? "text-[#171717] dark:text-white font-medium"
                    : "text-[#8f8f8f] dark:text-[#71717a]"
                }`}
              >
                <span
                  class={`absolute top-0 left-1/2 -translate-x-1/2 h-0.5 rounded-full transition-all duration-250 ${
                    active()
                      ? "w-8 bg-[#171717] dark:bg-white opacity-100"
                      : "w-0 bg-transparent opacity-0"
                  }`}
                />
                <span class={`${item.icon} text-lg`} />
                <span class="text-[11px] leading-none truncate max-w-full px-1">
                  {item.label()}
                </span>
              </button>
            );
          }}
        </For>
      </div>
    </nav>
  );
}
