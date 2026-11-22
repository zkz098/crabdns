import { createSignal } from "solid-js";
import { translations, type Locale } from "../i18n/translations";

interface QuickStartTabsProps {
  lang: Locale;
}

type QsTab = "install" | "openwrt" | "source";

export function QuickStartTabs(props: QuickStartTabsProps) {
  const [active, setActive] = createSignal<QsTab>("install");
  const [copied, setCopied] = createSignal(false);
  const t = () => translations[props.lang];

  const snippets: Record<QsTab, string> = {
    install: `# Linux (systemd) / OpenWrt (procd) — x86_64 & aarch64
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh`,
    openwrt: `# Install on OpenWrt and take over port 53 from dnsmasq
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | \\
  sh -s -- --openwrt-dnsmasq takeover`,
    source: `# 1. Build Web UI assets
cd webui && pnpm install && pnpm build && cd ..

# 2. Run CrabDNS (DNS: 0.0.0.0:5353, Web UI: 127.0.0.1:3000)
cargo run -p crabdns-server`,
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(snippets[active()]);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore clipboard failure
    }
  };

  return (
    <div class="rounded-2xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] overflow-hidden shadow-sm">
      <div class="px-4 py-2.5 border-b border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] flex flex-wrap items-center justify-between gap-2">
        <div class="flex flex-wrap items-center gap-1 p-0.5 rounded-lg bg-[#f4f4f5] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#222222]">
          {(
            [
              { key: "install", label: t().qsTabInstall },
              { key: "openwrt", label: t().qsTabOpenwrt },
              { key: "source", label: t().qsTabSource },
            ] as const
          ).map((item) => (
            <button
              type="button"
              onClick={() => setActive(item.key)}
              class={`px-3 py-1 rounded-md text-xs font-medium cursor-pointer border-0 transition-all ${
                active() === item.key
                  ? "bg-white dark:bg-[#1f1f1f] text-[#171717] dark:text-white shadow-sm ring-1 ring-black/5 dark:ring-white/10"
                  : "bg-transparent text-[#666666] dark:text-[#8f8f8f] hover:text-[#171717] dark:hover:text-[#ededed]"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={handleCopy}
          class="h-7 px-2.5 rounded-lg text-[11px] font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors"
        >
          <span class={copied() ? "i-ri-check-line text-emerald-500" : "i-ri-file-copy-line"} />
          <span>{copied() ? t().copied : t().copy}</span>
        </button>
      </div>

      <pre class="p-4 sm:p-5 overflow-x-auto text-xs font-mono leading-relaxed text-[#171717] dark:text-[#ededed] m-0">
        <code>{snippets[active()]}</code>
      </pre>
    </div>
  );
}
