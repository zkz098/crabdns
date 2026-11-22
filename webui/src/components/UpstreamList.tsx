import { For, Show, createMemo, createSignal } from "solid-js";
import { t } from "../i18n";
import type { UpstreamCapabilities } from "../types/UpstreamCapabilities";
import type { UpstreamStatus } from "../types/UpstreamStatus";
import { InfoTooltip } from "./InfoTooltip";

interface UpstreamListProps {
  upstreamsText: string;
  onUpstreamsChange: (val: string) => void;
  upstreamHealth: UpstreamStatus[];
  probingUpstreams: boolean;
  onProbeUpstreams: () => void;
  upstreamCapabilities: UpstreamCapabilities[];
  probingCapabilities: boolean;
  probeCapabilitiesError: string;
  onProbeCapabilities: () => void;
  onReplaceUpstream: (fromInput: string, toUrl: string) => void;
  dnssecEnabled: boolean;
  ecsEnabled: boolean;
}

export function UpstreamList(props: UpstreamListProps) {
  const [adding, setAdding] = createSignal(false);
  const [newUpstream, setNewUpstream] = createSignal("");
  const [editingIndex, setEditingIndex] = createSignal<number | null>(null);
  const [editingValue, setEditingValue] = createSignal("");

  let addInputRef: HTMLInputElement | undefined;
  let editInputRef: HTMLInputElement | undefined;

  const upstreams = createMemo(() =>
    props.upstreamsText
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );

  function commitList(next: string[]) {
    props.onUpstreamsChange(next.join("\n"));
  }

  function startAdd() {
    setAdding(true);
    setNewUpstream("");
    queueMicrotask(() => addInputRef?.focus());
  }

  function confirmAdd() {
    const raw = newUpstream().trim();
    if (!raw) {
      setAdding(false);
      return;
    }
    const additions = raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (additions.length > 0) {
      const current = upstreams();
      const merged = [...current];
      for (const item of additions) {
        if (!merged.includes(item)) {
          merged.push(item);
        }
      }
      commitList(merged);
    }
    setNewUpstream("");
    setAdding(false);
  }

  function cancelAdd() {
    setNewUpstream("");
    setAdding(false);
  }

  function startEdit(index: number, value: string) {
    setEditingIndex(index);
    setEditingValue(value);
    queueMicrotask(() => editInputRef?.focus());
  }

  function confirmEdit(index: number) {
    const trimmed = editingValue().trim();
    const list = upstreams();
    if (!trimmed) {
      commitList(list.filter((_, i) => i !== index));
    } else {
      commitList(list.map((item, i) => (i === index ? trimmed : item)));
    }
    setEditingIndex(null);
  }

  function removeAt(index: number) {
    commitList(upstreams().filter((_, i) => i !== index));
    if (editingIndex() === index) {
      setEditingIndex(null);
    }
  }

  function moveItem(index: number, delta: -1 | 1) {
    const list = [...upstreams()];
    const target = index + delta;
    if (target < 0 || target >= list.length) return;
    [list[index], list[target]] = [list[target], list[index]];
    commitList(list);
  }

  function findCapability(entry: string): UpstreamCapabilities | undefined {
    return props.upstreamCapabilities.find((c) => c.input === entry || c.endpoint === entry);
  }

  function findHealth(entry: string, cap?: UpstreamCapabilities): UpstreamStatus | undefined {
    return props.upstreamHealth.find(
      (h) =>
        h.endpoint === entry ||
        (cap && h.endpoint === cap.endpoint) ||
        h.endpoint === `udp://${entry}` ||
        h.endpoint === `${entry}:53`,
    );
  }

  return (
    <div class="space-y-2.5">
      {/* Header & Actions */}
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
            <span>{t("settingsUpstreamsLabel")}</span>
            <InfoTooltip text={t("tooltipUpstreams")} align="left" />
          </label>
          <span class="px-1.5 py-0.5 rounded-md text-[10px] font-mono tabular-nums bg-zinc-500/10 text-[#666666] dark:text-[#a1a1aa]">
            {upstreams().length}
          </span>
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={startAdd}
            class="h-7 px-2.5 rounded-md text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] inline-flex items-center gap-1 cursor-pointer border-0 transition-colors"
          >
            <span class="i-ri-add-line text-xs" />
            <span>{t("settingsUpstreamAddBtn")}</span>
          </button>

          <button
            type="button"
            disabled={props.probingUpstreams || upstreams().length === 0}
            onClick={props.onProbeUpstreams}
            class="h-7 px-2.5 rounded-md text-xs font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] inline-flex items-center gap-1.5 cursor-pointer hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 transition-colors"
          >
            <span
              class={
                props.probingUpstreams
                  ? "i-ri-loader-4-line animate-spin text-xs"
                  : "i-ri-heart-pulse-line text-xs"
              }
            />
            <span>{t("settingsProbeNow")}</span>
          </button>

          <button
            type="button"
            disabled={props.probingCapabilities || upstreams().length === 0}
            onClick={props.onProbeCapabilities}
            class="h-7 px-2.5 rounded-md text-xs font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] inline-flex items-center gap-1.5 cursor-pointer hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] disabled:opacity-50 transition-colors"
          >
            <span
              class={
                props.probingCapabilities
                  ? "i-ri-loader-4-line animate-spin text-xs"
                  : "i-ri-radar-line text-xs"
              }
            />
            <span>
              {props.probingCapabilities
                ? t("settingsProbingCapabilities")
                : t("settingsProbeCapabilities")}
            </span>
          </button>
        </div>
      </div>

      <Show when={props.probeCapabilitiesError}>
        <p class="text-xs text-rose-600 dark:text-rose-400">{props.probeCapabilitiesError}</p>
      </Show>

      {/* Upstream List */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] divide-y divide-[#eaeaea] dark:divide-[#222222] overflow-hidden">
        <Show
          when={upstreams().length > 0 || adding()}
          fallback={
            <div class="px-4 py-6 text-center text-xs text-[#8f8f8f] dark:text-[#71717a]">
              {t("settingsUpstreamEmpty")}
            </div>
          }
        >
          <For each={upstreams()}>
            {(entry, index) => {
              const cap = () => findCapability(entry);
              const health = () => findHealth(entry, cap());
              const isEditing = () => editingIndex() === index();

              const statusDotClass = () => {
                const c = cap();
                if (c) return c.reachable ? "bg-emerald-500" : "bg-rose-500";
                const h = health();
                if (h) return h.healthy ? "bg-emerald-500" : "bg-rose-500";
                return "bg-zinc-400 dark:bg-zinc-600";
              };

              const protoLabel = () => {
                const c = cap();
                if (!c) return "";
                const base =
                  c.protocol === "doh"
                    ? "DoH"
                    : c.protocol === "dot"
                      ? "DoT"
                      : c.protocol.toUpperCase();
                return c.transport_detail ? `${base} · ${c.transport_detail}` : base;
              };

              return (
                <div class="p-3 bg-white dark:bg-[#0a0a0a] space-y-2 transition-colors">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    {/* Left: Status Dot + Endpoint / Inline Edit */}
                    <div class="flex items-center gap-2.5 min-w-0 flex-1">
                      <span class={`h-2 w-2 rounded-full shrink-0 ${statusDotClass()}`} />

                      <Show
                        when={isEditing()}
                        fallback={
                          <span class="font-mono text-xs text-[#171717] dark:text-[#ededed] truncate">
                            {entry}
                          </span>
                        }
                      >
                        <div class="flex items-center gap-1.5 flex-1 min-w-0">
                          <input
                            ref={(el) => {
                              editInputRef = el;
                            }}
                            type="text"
                            spellcheck={false}
                            value={editingValue()}
                            onInput={(e) => setEditingValue(e.currentTarget.value)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                confirmEdit(index());
                              } else if (e.key === "Escape") {
                                e.preventDefault();
                                setEditingIndex(null);
                              }
                            }}
                            class="flex-1 min-w-0 h-7 bg-[#fafafa] dark:bg-[#000000] border border-[#171717] dark:border-[#ededed] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                          />
                          <button
                            type="button"
                            onClick={() => confirmEdit(index())}
                            class="h-7 px-2 rounded-md text-xs font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] border-0 cursor-pointer shrink-0"
                          >
                            <span class="i-ri-check-line text-xs" />
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingIndex(null)}
                            class="h-7 px-2 rounded-md text-xs bg-transparent border border-[#eaeaea] dark:border-[#262626] text-[#666666] dark:text-[#a1a1aa] cursor-pointer shrink-0"
                          >
                            <span class="i-ri-close-line text-xs" />
                          </button>
                        </div>
                      </Show>
                    </div>

                    {/* Right: Health Status + Protocol Badge + Row Actions */}
                    <div class="flex flex-wrap items-center gap-1.5 shrink-0">
                      <Show when={health()}>
                        {(h) => (
                          <span
                            title={`${h().total_requests} ${t("settingsUpstreamRequests")} · ${h().total_failures} ${t("settingsUpstreamFailures")}`}
                            class={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border tabular-nums ${
                              h().healthy
                                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                                : "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                            }`}
                          >
                            <span>
                              {h().healthy
                                ? t("settingsUpstreamHealthy")
                                : t("settingsUpstreamUnhealthy")}
                            </span>
                            <span>·</span>
                            <span>{h().ewma_latency_ms}ms</span>
                          </span>
                        )}
                      </Show>

                      <Show when={cap()}>
                        {(c) => (
                          <>
                            <span
                              class={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border ${
                                c().encrypted
                                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                                  : "bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border-zinc-500/20"
                              }`}
                            >
                              <Show when={c().encrypted}>
                                <span class="i-ri-lock-line text-[10px]" />
                              </Show>
                              {protoLabel()}
                            </span>
                            <Show
                              when={c().reachable && c().latency_ms !== null}
                              fallback={
                                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                                  {t("settingsCapUnreachable")}
                                </span>
                              }
                            >
                              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums">
                                {c().latency_ms}ms
                              </span>
                            </Show>
                          </>
                        )}
                      </Show>

                      {/* Row actions */}
                      <div class="flex items-center gap-0.5 pl-1 border-l border-[#eaeaea] dark:border-[#262626]">
                        <button
                          type="button"
                          title={t("settingsUpstreamMoveUpTitle")}
                          disabled={index() === 0}
                          onClick={() => moveItem(index(), -1)}
                          class="w-6 h-6 rounded inline-flex items-center justify-center text-[#8f8f8f] hover:text-[#171717] dark:text-[#71717a] dark:hover:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] bg-transparent border-0 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          <span class="i-ri-arrow-up-s-line text-sm" />
                        </button>
                        <button
                          type="button"
                          title={t("settingsUpstreamMoveDownTitle")}
                          disabled={index() === upstreams().length - 1}
                          onClick={() => moveItem(index(), 1)}
                          class="w-6 h-6 rounded inline-flex items-center justify-center text-[#8f8f8f] hover:text-[#171717] dark:text-[#71717a] dark:hover:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] bg-transparent border-0 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          <span class="i-ri-arrow-down-s-line text-sm" />
                        </button>
                        <button
                          type="button"
                          title={t("settingsUpstreamEditTitle")}
                          onClick={() => startEdit(index(), entry)}
                          class="w-6 h-6 rounded inline-flex items-center justify-center text-[#8f8f8f] hover:text-[#171717] dark:text-[#71717a] dark:hover:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] bg-transparent border-0 cursor-pointer"
                        >
                          <span class="i-ri-pencil-line text-xs" />
                        </button>
                        <button
                          type="button"
                          title={t("settingsUpstreamDeleteTitle")}
                          onClick={() => removeAt(index())}
                          class="w-6 h-6 rounded inline-flex items-center justify-center text-[#8f8f8f] hover:text-rose-600 dark:text-[#71717a] dark:hover:text-rose-400 hover:bg-rose-500/10 bg-transparent border-0 cursor-pointer"
                        >
                          <span class="i-ri-delete-bin-line text-xs" />
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Capability Details */}
                  <Show when={cap()}>
                    {(c) => (
                      <div class="pl-4.5 space-y-2">
                        <Show when={c().error}>
                          <p class="text-[11px] text-rose-600 dark:text-rose-400 font-mono break-all">
                            {c().error}
                          </p>
                        </Show>

                        <Show when={c().reachable}>
                          <div class="flex flex-wrap items-center gap-1.5">
                            {/* EDNS0 */}
                            <Show
                              when={c().edns === true}
                              fallback={
                                <Show when={c().edns === false}>
                                  <span class="px-2 py-0.5 rounded-md text-[11px] bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                                    {t("settingsCapNoEdns")}
                                  </span>
                                </Show>
                              }
                            >
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 tabular-nums">
                                {c().edns_udp_size ? `EDNS0 (${c().edns_udp_size}B)` : "EDNS0"}
                              </span>
                            </Show>

                            {/* DNSSEC */}
                            <Show
                              when={c().dnssec_validating === true}
                              fallback={
                                <Show
                                  when={c().dnssec_aware === true}
                                  fallback={
                                    <Show when={c().dnssec_aware === false}>
                                      <span class="px-2 py-0.5 rounded-md text-[11px] bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border border-zinc-500/20">
                                        {t("settingsCapNoDnssec")}
                                      </span>
                                    </Show>
                                  }
                                >
                                  <span class="px-2 py-0.5 rounded-md text-[11px] bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-500/20">
                                    {t("settingsCapDnssecAware")}
                                  </span>
                                </Show>
                              }
                            >
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                                {t("settingsCapDnssecValidating")}
                              </span>
                            </Show>

                            {/* ECS */}
                            <Show
                              when={c().ecs === true}
                              fallback={
                                <Show when={c().ecs === false}>
                                  <span class="px-2 py-0.5 rounded-md text-[11px] bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border border-zinc-500/20">
                                    {t("settingsCapNoEcs")}
                                  </span>
                                </Show>
                              }
                            >
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                                {t("settingsCapEcs")}
                              </span>
                            </Show>

                            {/* NSID node identifier */}
                            <Show when={c().nsid}>
                              {(nsid) => (
                                <span
                                  title={`NSID: ${nsid()}`}
                                  class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border border-indigo-500/20 max-w-[200px] truncate"
                                >
                                  <span class="i-ri-server-line text-[10px] shrink-0" />
                                  <span class="truncate">{nsid()}</span>
                                </span>
                              )}
                            </Show>

                            {/* DNS Cookies (RFC 7873) */}
                            <Show when={c().dns_cookies === true}>
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                                {t("settingsCapCookies")}
                              </span>
                            </Show>

                            {/* EDNS Padding (RFC 7830) */}
                            <Show when={c().edns_padding === true}>
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                                {t("settingsCapPadding")}
                              </span>
                            </Show>

                            {/* Extended DNS Errors (RFC 8914) */}
                            <Show when={c().ede === true}>
                              <span
                                title={c().ede_detail ?? "RFC 8914 Extended DNS Errors"}
                                class="px-2 py-0.5 rounded-md text-[11px] bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20"
                              >
                                {t("settingsCapEde")}
                              </span>
                            </Show>

                            {/* RA warning */}
                            <Show when={c().recursion_available === false}>
                              <span class="px-2 py-0.5 rounded-md text-[11px] bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                                {t("settingsCapNonRecursive")}
                              </span>
                            </Show>

                            {/* NXDOMAIN hijack warning */}
                            <Show when={c().nxdomain_hijack === true}>
                              <span class="px-2 py-0.5 rounded-md text-[11px] font-medium bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                                {t("settingsCapNxdomainHijack")}
                              </span>
                            </Show>
                          </div>

                          {/* Config mismatch hints */}
                          <Show when={props.dnssecEnabled && c().dnssec_aware === false}>
                            <p class="text-[11px] text-amber-700 dark:text-amber-400">
                              {t("settingsCapDnssecMismatchHint")}
                            </p>
                          </Show>
                          <Show when={props.ecsEnabled && c().ecs === false}>
                            <p class="text-[11px] text-amber-700 dark:text-amber-400">
                              {t("settingsCapEcsMismatchHint")}
                            </p>
                          </Show>

                          {/* DDR encrypted upgrade suggestions */}
                          <Show when={c().ddr_upgrades.length > 0}>
                            <div class="flex flex-wrap items-center gap-1.5 pt-0.5">
                              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                                {t("settingsCapDdrUpgradeLabel")}
                              </span>
                              <For each={c().ddr_upgrades}>
                                {(upgradeUrl) => (
                                  <button
                                    type="button"
                                    onClick={() => props.onReplaceUpstream(c().input, upgradeUrl)}
                                    class="px-2 py-0.5 rounded-md text-[11px] font-mono bg-white dark:bg-[#111111] border border-emerald-500/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10 cursor-pointer transition-colors"
                                  >
                                    {upgradeUrl}
                                  </button>
                                )}
                              </For>
                            </div>
                          </Show>
                        </Show>
                      </div>
                    )}
                  </Show>
                </div>
              );
            }}
          </For>
        </Show>

        {/* Inline Add Upstream Row */}
        <Show when={adding()}>
          <div class="p-3 bg-white dark:bg-[#0a0a0a] flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <input
              ref={(el) => {
                addInputRef = el;
              }}
              type="text"
              spellcheck={false}
              placeholder={t("settingsUpstreamAddPlaceholder")}
              value={newUpstream()}
              onInput={(e) => setNewUpstream(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  confirmAdd();
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  cancelAdd();
                }
              }}
              class="flex-1 h-8 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
            />
            <div class="flex items-center justify-end gap-1.5 shrink-0">
              <button
                type="button"
                onClick={confirmAdd}
                class="h-8 px-3 rounded-md text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer transition-colors"
              >
                {t("settingsUpstreamConfirmAdd")}
              </button>
              <button
                type="button"
                onClick={cancelAdd}
                class="h-8 px-3 rounded-md text-xs font-medium bg-transparent border border-[#eaeaea] dark:border-[#262626] text-[#666666] dark:text-[#a1a1aa] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer transition-colors"
              >
                {t("settingsUpstreamCancelAdd")}
              </button>
            </div>
          </div>
        </Show>
      </div>

      <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">{t("settingsUpstreamsHint")}</p>
    </div>
  );
}
