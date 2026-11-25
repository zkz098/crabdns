import { createMemo, createSignal, For, onMount, Show } from "solid-js";
import { t, type TranslationKey } from "../i18n";
import type { DiagnosticCategory } from "../types/DiagnosticCategory";
import type { DiagnosticItem } from "../types/DiagnosticItem";
import type { DiagnosticStatus } from "../types/DiagnosticStatus";
import type { SystemDiagnosticsResponse } from "../types/SystemDiagnosticsResponse";

const ITEM_TITLE_KEYS: Record<string, TranslationKey> = {
  mdns_port_conflict: "diagItemMdnsConflict",
  loopback_probe: "diagItemLoopbackProbe",
  udp_inflight_drops: "diagItemUdpDrops",
  upstream_health: "diagItemUpstreamHealth",
  bootstrap_dns: "diagItemBootstrapDns",
  forwarding_loop: "diagItemForwardingLoop",
};

function statusBadgeClass(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20";
    case "warn":
      return "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20";
    case "error":
      return "bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20";
  }
}

function statusDotClass(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return "bg-emerald-500";
    case "warn":
      return "bg-amber-500";
    case "error":
      return "bg-rose-500";
  }
}

function statusLabel(status: DiagnosticStatus): string {
  switch (status) {
    case "ok":
      return t("diagStatusOk");
    case "warn":
      return t("diagStatusWarn");
    case "error":
      return t("diagStatusError");
  }
}

function itemTitle(id: string): string {
  const key = ITEM_TITLE_KEYS[id];
  return key ? t(key) : id;
}

export function SystemDiagnosticsCard() {
  const [report, setReport] = createSignal<SystemDiagnosticsResponse | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal("");

  async function runDiagnostics() {
    setLoading(true);
    setErrorMsg("");
    try {
      const res = await fetch("/api/system/diagnostics", { method: "POST" });
      if (!res.ok) {
        setErrorMsg(t("diagFailed"));
        return;
      }
      const data: SystemDiagnosticsResponse = await res.json();
      setReport(data);
    } catch {
      setErrorMsg(t("diagFailed"));
    } finally {
      setLoading(false);
    }
  }

  onMount(() => {
    void runDiagnostics();
  });

  const listenerItems = createMemo(() =>
    (report()?.items ?? []).filter((item) => item.category === "listener"),
  );
  const upstreamItems = createMemo(() =>
    (report()?.items ?? []).filter((item) => item.category === "upstream"),
  );

  return (
    <div
      class="animate-card-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-4 transition-colors hover:border-[#d4d4d8] dark:hover:border-[#3a3a3a]"
      style={{ "animation-delay": "200ms" }}
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-2.5">
          <h2 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">{t("diagTitle")}</h2>
          <Show when={report()}>
            {(r) => (
              <span
                class={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border ${statusBadgeClass(r().overall)}`}
              >
                <span class={`w-1.5 h-1.5 rounded-full ${statusDotClass(r().overall)}`} />
                {statusLabel(r().overall)}
              </span>
            )}
          </Show>
        </div>
        <button
          type="button"
          disabled={loading()}
          onClick={() => void runDiagnostics()}
          class="h-7 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-150"
        >
          <span class={`i-ri-heart-pulse-line text-xs ${loading() ? "animate-pulse" : ""}`} />
          <span>{loading() ? t("diagRunning") : t("diagRunBtn")}</span>
        </button>
      </div>

      <Show when={errorMsg()}>
        <p class="text-xs text-rose-600 dark:text-rose-400">{errorMsg()}</p>
      </Show>

      <Show when={report()}>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <DiagnosticGroup category="listener" items={listenerItems()} />
          <DiagnosticGroup category="upstream" items={upstreamItems()} />
        </div>
      </Show>
    </div>
  );
}

function DiagnosticGroup(props: { category: DiagnosticCategory; items: DiagnosticItem[] }) {
  const title = () => (props.category === "listener" ? t("diagCatListener") : t("diagCatUpstream"));

  return (
    <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5">
      <h3 class="text-xs font-medium text-[#666666] dark:text-[#a1a1aa]">{title()}</h3>
      <div class="space-y-2">
        <For each={props.items}>
          {(item) => (
            <div class="rounded-lg border border-[#eaeaea]/80 dark:border-[#262626]/80 bg-white dark:bg-[#0a0a0a] px-3 py-2 space-y-1">
              <div class="flex items-center justify-between gap-2 text-xs">
                <div class="flex items-center gap-2 min-w-0">
                  <span class={`w-2 h-2 rounded-full shrink-0 ${statusDotClass(item.status)}`} />
                  <span class="font-medium text-[#171717] dark:text-[#ededed] truncate">
                    {itemTitle(item.id)}
                  </span>
                </div>
                <span class="font-mono text-[11px] text-[#666666] dark:text-[#a1a1aa] shrink-0">
                  {item.summary}
                </span>
              </div>
              <Show when={item.detail}>
                {(detail) => (
                  <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] pl-4">{detail()}</p>
                )}
              </Show>
              <Show when={item.hint}>
                {(hint) => (
                  <p class="text-[11px] text-amber-700 dark:text-amber-400 pl-4">{hint()}</p>
                )}
              </Show>
            </div>
          )}
        </For>
      </div>
    </div>
  );
}
