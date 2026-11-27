import { For, Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { UpstreamGroup } from "../types/UpstreamGroup";
import type { UpstreamPolicy } from "../types/UpstreamPolicy";
import {
  UpstreamPolicyEditor,
  emptyUpstreamPolicy,
  upstreamPolicyBadges,
} from "./UpstreamPolicyEditor";

interface UpstreamGroupsCardProps {
  groups: UpstreamGroup[];
  onChange: (next: UpstreamGroup[]) => void;
}

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function UpstreamGroupsCard(props: UpstreamGroupsCardProps) {
  const [formOpen, setFormOpen] = createSignal(false);
  const [editingIndex, setEditingIndex] = createSignal<number | null>(null);
  const [name, setName] = createSignal("");
  const [upstreams, setUpstreams] = createSignal("");
  const [fallbackGroups, setFallbackGroups] = createSignal("");
  const [proxyUrl, setProxyUrl] = createSignal("");
  const [policy, setPolicy] = createSignal<UpstreamPolicy>(emptyUpstreamPolicy());

  function openAdd() {
    setEditingIndex(null);
    setName("");
    setUpstreams("");
    setFallbackGroups("");
    setProxyUrl("");
    setPolicy(emptyUpstreamPolicy());
    setFormOpen(true);
  }

  function openEdit(idx: number, g: UpstreamGroup) {
    setEditingIndex(idx);
    setName(g.name);
    setUpstreams(g.upstreams.join(", "));
    setFallbackGroups(g.fallback_groups.join(", "));
    setProxyUrl(g.proxy_url ?? "");
    setPolicy(g.policy ? { ...g.policy } : emptyUpstreamPolicy());
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditingIndex(null);
  }

  function submitForm() {
    const cleanName = name().trim().toLowerCase();
    const cleanUpstreams = splitTokens(upstreams());
    if (!cleanName || cleanUpstreams.length === 0) return;
    const built: UpstreamGroup = {
      name: cleanName,
      upstreams: cleanUpstreams,
      fallback_groups: splitTokens(fallbackGroups()).map((s) => s.replace(/^@+/, "").toLowerCase()),
      proxy_url: proxyUrl().trim() || null,
      policy: policy(),
    };
    const idx = editingIndex();
    if (idx === null) {
      props.onChange([...props.groups, built]);
    } else {
      props.onChange(props.groups.map((item, i) => (i === idx ? built : item)));
    }
    closeForm();
  }

  function removeAt(idx: number) {
    props.onChange(props.groups.filter((_, i) => i !== idx));
    if (editingIndex() === idx) {
      closeForm();
    }
  }

  return (
    <div class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
            <span class="i-ri-node-tree text-sm text-[#666666] dark:text-[#a1a1aa]" />
            <span>{t("upstreamGroupsTitle")}</span>
          </label>
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-0.5">
            {t("upstreamGroupsHint")}
          </p>
        </div>

        <button
          type="button"
          onClick={openAdd}
          class="h-7 px-2.5 rounded-lg text-[11px] font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] hover:opacity-90 flex items-center gap-1 cursor-pointer transition-opacity"
        >
          <span class="i-ri-add-line text-xs" />
          <span>{t("upstreamGroupsAddBtn")}</span>
        </button>
      </div>

      <Show when={formOpen()}>
        <div class="rounded-lg border border-[#d4d4d8] dark:border-[#3f3f46] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamGroupNameLabel")}
              </label>
              <input
                type="text"
                value={name()}
                placeholder="cn_dns"
                onInput={(e) => setName(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamGroupUpstreamsLabel")}
              </label>
              <input
                type="text"
                value={upstreams()}
                placeholder="https://dns.alidns.com/dns-query, https://doh.pub/dns-query"
                onInput={(e) => setUpstreams(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamGroupFallbackLabel")}
              </label>
              <input
                type="text"
                value={fallbackGroups()}
                placeholder="overseas_doh"
                onInput={(e) => setFallbackGroups(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamGroupProxyLabel")}
              </label>
              <input
                type="text"
                value={proxyUrl()}
                placeholder="socks5h://127.0.0.1:7890"
                onInput={(e) => setProxyUrl(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>

          <UpstreamPolicyEditor policy={policy()} onChange={setPolicy} />

          <div class="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={closeForm}
              class="h-7 px-3 rounded-md text-xs bg-white dark:bg-[#111111] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer"
            >
              {t("clientsCancelBtn")}
            </button>
            <button
              type="button"
              disabled={!name().trim() || !upstreams().trim()}
              onClick={submitForm}
              class="h-7 px-3 rounded-md text-xs font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] cursor-pointer disabled:opacity-40"
            >
              {t("clientsSaveBtn")}
            </button>
          </div>
        </div>
      </Show>

      <Show
        when={props.groups.length > 0}
        fallback={
          <div class="rounded-lg border border-dashed border-[#eaeaea] dark:border-[#262626] px-3 py-3 text-center text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
            {t("upstreamGroupsEmpty")}
          </div>
        }
      >
        <div class="divide-y divide-[#eaeaea] dark:divide-[#262626] border border-[#eaeaea] dark:border-[#262626] rounded-lg bg-[#fafafa] dark:bg-[#050505]">
          <For each={props.groups}>
            {(group, index) => (
              <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3 py-2.5">
                <div class="min-w-0 flex-1 space-y-1">
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span class="px-1.5 py-0.5 rounded font-mono text-xs font-semibold bg-[#171717]/10 dark:bg-[#ededed]/10 text-[#171717] dark:text-[#ededed]">
                      @{group.name}
                    </span>
                    <Show when={group.proxy_url}>
                      <span class="px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-700 dark:text-violet-400 font-mono text-[10px]">
                        Proxy:{group.proxy_url}
                      </span>
                    </Show>
                    <Show when={group.fallback_groups.length > 0}>
                      <span class="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-400 font-mono text-[10px]">
                        Fallback:{group.fallback_groups.map((f) => `@${f}`).join(" -> ")}
                      </span>
                    </Show>
                  </div>
                  <div class="flex flex-wrap items-center gap-1">
                    <For each={group.upstreams}>
                      {(up) => (
                        <span class="px-1.5 py-0.5 rounded bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] font-mono text-[11px] text-[#52525b] dark:text-[#a1a1aa]">
                          {up}
                        </span>
                      )}
                    </For>
                    <For each={upstreamPolicyBadges(group.policy)}>
                      {(badge) => (
                        <span class="px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-700 dark:text-sky-400 font-mono text-[10px]">
                          {badge}
                        </span>
                      )}
                    </For>
                  </div>
                </div>

                <div class="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    onClick={() => openEdit(index(), group)}
                    class="w-7 h-7 rounded-md flex items-center justify-center text-[#666666] dark:text-[#a1a1aa] hover:bg-[#eaeaea]/60 dark:hover:bg-[#1f1f1f] cursor-pointer"
                  >
                    <span class="i-ri-edit-line text-sm" />
                  </button>
                  <button
                    type="button"
                    onClick={() => removeAt(index())}
                    class="w-7 h-7 rounded-md flex items-center justify-center text-rose-500 hover:bg-rose-500/10 cursor-pointer"
                  >
                    <span class="i-ri-delete-bin-line text-sm" />
                  </button>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
