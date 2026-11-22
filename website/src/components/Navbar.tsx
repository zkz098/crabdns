import { createSignal, onMount, Show } from "solid-js";
import { translations, type Locale } from "../i18n/translations";
import { syncThemeFromDom, theme, toggleTheme } from "../stores/theme";

interface NavbarProps {
  lang: Locale;
  switchToHref?: string;
}

export function Navbar(props: NavbarProps) {
  const [mobileOpen, setMobileOpen] = createSignal(false);
  const t = () => translations[props.lang];
  const homePrefix = () => (props.lang === "zh" ? "/zh/" : "/");
  const switchHref = () => props.switchToHref ?? (props.lang === "en" ? "/zh/" : "/");
  const switchLabel = () => (props.lang === "en" ? "中文" : "EN");

  onMount(() => {
    syncThemeFromDom();
  });

  const navLinks = () => [
    { href: `${homePrefix()}#features`, label: t().navFeatures, icon: "i-ri-shield-flash-line" },
    { href: `${homePrefix()}#setup`, label: t().navSetup, icon: "i-ri-compass-3-line" },
    { href: `${homePrefix()}#quickstart`, label: t().navQuickStart, icon: "i-ri-terminal-box-line" },
    { href: props.lang === "zh" ? "/zh/docs/" : "/docs/", label: t().navDocs, icon: "i-ri-book-open-line" },
  ];

  return (
    <header class="sticky top-0 z-40 border-b border-[#eaeaea] dark:border-[#262626] bg-white/80 dark:bg-black/80 backdrop-blur-xl transition-colors">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-3">
        {/* Brand */}
        <a
          href={props.lang === "zh" ? "/zh/" : "/"}
          class="flex items-center gap-3 min-w-0 no-underline group"
        >
          <div class="w-8 h-8 rounded-lg bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] flex items-center justify-center shrink-0 shadow-sm transition-transform duration-200 group-hover:scale-105">
            <span class="i-ri-shield-check-fill text-base" />
          </div>
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-sm sm:text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed] truncate">
              CrabDNS
            </span>
            <span class="hidden xs:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium font-mono border bg-emerald-500/10 text-emerald-700 border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/25">
              <span class="relative flex h-1.5 w-1.5">
                <span class="animate-pulse-ring absolute inline-flex h-full w-full rounded-full bg-emerald-500" />
                <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
              </span>
              v0.1.6
            </span>
          </div>
        </a>

        {/* Desktop Nav */}
        <nav class="hidden md:flex items-center gap-1 p-1 rounded-xl bg-[#f4f4f5] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#222222]">
          {navLinks().map((item) => (
            <a
              href={item.href}
              class="px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 no-underline text-[#666666] dark:text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed] hover:bg-white/70 dark:hover:bg-[#1a1a1a] transition-all duration-200"
            >
              <span class={`${item.icon} text-sm`} />
              <span>{item.label}</span>
            </a>
          ))}
        </nav>

        {/* Right Controls */}
        <div class="flex items-center gap-2 shrink-0">
          <a
            href={switchHref()}
            class="h-8 px-2.5 rounded-lg text-xs font-medium no-underline bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 transition-all duration-200"
            aria-label="Switch language"
          >
            <span class="i-ri-translate-2 text-sm text-[#666666] dark:text-[#a1a1aa]" />
            <span>{switchLabel()}</span>
          </a>

          <button
            type="button"
            onClick={toggleTheme}
            class="w-8 h-8 rounded-lg bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center justify-center cursor-pointer transition-all duration-200 active:scale-[0.95]"
            aria-label="Toggle theme"
          >
            <Show
              when={theme() === "dark"}
              fallback={<span class="i-ri-moon-line text-sm" />}
            >
              <span class="i-ri-sun-line text-sm" />
            </Show>
          </button>

          <a
            href="https://github.com/zkz098/crabdns"
            target="_blank"
            rel="noopener noreferrer"
            class="hidden sm:inline-flex h-8 px-3 rounded-lg text-xs font-medium no-underline bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] hover:opacity-90 items-center gap-1.5 transition-opacity"
          >
            <span class="i-ri-github-fill text-sm" />
            <span>GitHub</span>
          </a>

          <button
            type="button"
            onClick={() => setMobileOpen((v) => !v)}
            class="md:hidden w-8 h-8 rounded-lg bg-white dark:bg-[#111111] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center justify-center cursor-pointer"
            aria-label="Toggle menu"
          >
            <span class={mobileOpen() ? "i-ri-close-line text-base" : "i-ri-menu-line text-base"} />
          </button>
        </div>
      </div>

      {/* Mobile Dropdown */}
      <Show when={mobileOpen()}>
        <div class="md:hidden border-t border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] px-4 py-3 space-y-1">
          {navLinks().map((item) => (
            <a
              href={item.href}
              onClick={() => setMobileOpen(false)}
              class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium no-underline text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#111111]"
            >
              <span class={`${item.icon} text-base text-[#666666] dark:text-[#8f8f8f]`} />
              <span>{item.label}</span>
            </a>
          ))}
          <a
            href="https://github.com/zkz098/crabdns"
            target="_blank"
            rel="noopener noreferrer"
            class="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium no-underline text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#111111]"
          >
            <span class="i-ri-github-fill text-base" />
            <span>GitHub</span>
          </a>
        </div>
      </Show>
    </header>
  );
}
