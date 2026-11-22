import { createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { PortCheckItem } from "../types/PortCheckItem";
import type { PortCheckRequest } from "../types/PortCheckRequest";
import type { PortCheckResponse } from "../types/PortCheckResponse";

interface PortPrecheckPanelProps {
  listenDns: string;
  listenWeb: string;
  listenWebTls?: string | null;
  listenDot?: string | null;
  listenDoq?: string | null;
}

type ProtoKey = "dns" | "web" | "web_tls" | "dot" | "doq";

const PROTO_PLACEHOLDERS: Record<ProtoKey, string> = {
  dns: "0.0.0.0:53",
  web: "0.0.0.0:80",
  web_tls: "0.0.0.0:443",
  dot: "0.0.0.0:853",
  doq: "0.0.0.0:853",
};

function formatCheckHint(item: PortCheckItem): string {
  if (item.in_use_by_self) return t("portCheckStatusSelf");
  if (item.available) return t("portCheckStatusAvailable");
  switch (item.reason) {
    case "in_use":
      return t("portCheckStatusInUse");
    case "permission_denied":
      return t("portCheckStatusPermission");
    case "invalid_addr":
      return t("portCheckStatusInvalid");
    default:
      return item.error ?? "Unavailable";
  }
}

export function PortPrecheckPanel(props: PortPrecheckPanelProps) {
  const [proto, setProto] = createSignal<ProtoKey>("dns");
  const [addr, setAddr] = createSignal("0.0.0.0:53");
  const [checking, setChecking] = createSignal(false);
  const [results, setResults] = createSignal<PortCheckItem[]>([]);

  async function runCheck(payload: PortCheckRequest) {
    setChecking(true);
    try {
      const res = await fetch("/api/setup/check-ports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data: PortCheckResponse = await res.json();
        setResults(data.results);
      }
    } catch {
      // Ignore transient network errors
    } finally {
      setChecking(false);
    }
  }

  function checkTarget() {
    const trimmed = addr().trim();
    if (!trimmed) return;
    const key = proto();
    const payload: PortCheckRequest = {
      dns_addr: key === "dns" ? trimmed : null,
      web_addr: key === "web" ? trimmed : null,
      web_tls_addr: key === "web_tls" ? trimmed : null,
      dot_addr: key === "dot" ? trimmed : null,
      doq_addr: key === "doq" ? trimmed : null,
    };
    void runCheck(payload);
  }

  function checkCurrent() {
    void runCheck({
      dns_addr: props.listenDns || null,
      web_addr: props.listenWeb || null,
      web_tls_addr: props.listenWebTls ?? null,
      dot_addr: props.listenDot ?? null,
      doq_addr: props.listenDoq ?? null,
    });
  }

  return (
    <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5 text-xs">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div class="font-medium text-[#171717] dark:text-[#ededed]">{t("portCheckTitle")}</div>
          <div class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">{t("portCheckDesc")}</div>
        </div>
        <button
          type="button"
          disabled={checking()}
          onClick={checkCurrent}
          class="shrink-0 px-2.5 py-1 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer disabled:opacity-50"
        >
          {checking() ? t("portCheckChecking") : t("portCheckCurrentBtn")}
        </button>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <select
          value={proto()}
          onChange={(e) => {
            const next = e.currentTarget.value as ProtoKey;
            setProto(next);
            setAddr(PROTO_PLACEHOLDERS[next]);
          }}
          class="h-8 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 text-xs outline-none"
        >
          <option value="dns">{t("portCheckProtoDns")}</option>
          <option value="web">{t("portCheckProtoWeb")}</option>
          <option value="web_tls">{t("portCheckProtoWebTls")}</option>
          <option value="dot">{t("portCheckProtoDot")}</option>
          <option value="doq">{t("portCheckProtoDoq")}</option>
        </select>
        <input
          type="text"
          value={addr()}
          onInput={(e) => setAddr(e.currentTarget.value)}
          placeholder={PROTO_PLACEHOLDERS[proto()]}
          class="flex-1 min-w-[140px] h-8 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-2.5 font-mono text-xs outline-none"
        />
        <button
          type="button"
          disabled={checking()}
          onClick={checkTarget}
          class="h-8 px-3 rounded-lg font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] hover:opacity-90 cursor-pointer disabled:opacity-50"
        >
          {checking() ? t("portCheckChecking") : t("portCheckProbeBtn")}
        </button>
      </div>

      <Show when={results().length > 0}>
        <div class="space-y-1.5 pt-1">
          <For each={results()}>
            {(item) => (
              <div class="flex flex-wrap items-center justify-between gap-2 rounded border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] px-2.5 py-1.5">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="uppercase text-[10px] px-1.5 py-0.5 rounded bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa] shrink-0">
                    {item.key}
                  </span>
                  <span class="font-mono text-[#171717] dark:text-[#ededed] truncate">
                    {item.addr}
                  </span>
                </div>
                <span
                  class={
                    item.in_use_by_self
                      ? "text-sky-600 dark:text-sky-400 font-medium"
                      : item.available
                        ? "text-emerald-600 dark:text-emerald-400 font-medium"
                        : "text-rose-600 dark:text-rose-400 font-medium"
                  }
                >
                  {formatCheckHint(item)}
                </span>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
