import { createMemo, createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { BlockMode } from "../types/BlockMode";
import type { ClientActivityStats } from "../types/ClientActivityStats";
import type { ClientGroup } from "../types/ClientGroup";
import type { ClientGroupPayload } from "../types/ClientGroupPayload";
import type { ClientProfile } from "../types/ClientProfile";
import type { ClientProfilePayload } from "../types/ClientProfilePayload";
import type { ClientProtocolCounts } from "../types/ClientProtocolCounts";
import type { ClientsOverviewResponse } from "../types/ClientsOverviewResponse";
import type { DiscoveredClient } from "../types/DiscoveredClient";
import type { TopItem } from "../types/TopItem";
import { SelectMenu, type SelectOption } from "./SelectMenu";

interface ClientsViewProps {
  overview: ClientsOverviewResponse | null;
  message: string;
  isError: boolean;
  saving: boolean;
  onCreateGroup: (payload: ClientGroupPayload) => Promise<boolean>;
  onUpdateGroup: (id: string, payload: ClientGroupPayload) => Promise<boolean>;
  onDeleteGroup: (id: string) => Promise<void>;
  onCreateClient: (payload: ClientProfilePayload) => Promise<boolean>;
  onUpdateClient: (id: string, payload: ClientProfilePayload) => Promise<boolean>;
  onDeleteClient: (id: string) => Promise<void>;
  onRefresh: () => void;
}

type TriState = "" | "true" | "false";
type OptBlockMode = "" | BlockMode;

function parseLines(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseTags(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function toTriState(val: boolean | null): TriState {
  if (val === true) return "true";
  if (val === false) return "false";
  return "";
}

function fromTriState(val: TriState): boolean | null {
  if (val === "true") return true;
  if (val === "false") return false;
  return null;
}

function sourceLabel(src: string): string {
  if (src === "profile") return t("clientsSourceProfile");
  if (src === "hosts") return t("clientsSourceHosts");
  if (src === "dhcp") return t("clientsSourceDhcp");
  if (src === "mdns") return t("clientsSourceMdns");
  if (src === "rdns") return t("clientsSourceRdns");
  return t("clientsSourceUnknown");
}

function activityLevel(lastSeen: string | null): "active" | "recent" | "idle" {
  if (!lastSeen) return "idle";
  const ts = Date.parse(lastSeen);
  if (Number.isNaN(ts)) return "idle";
  const ageMs = Date.now() - ts;
  if (ageMs <= 5 * 60_000) return "active";
  if (ageMs <= 60 * 60_000) return "recent";
  return "idle";
}

function formatRelativeTime(lastSeen: string | null): string {
  if (!lastSeen) return "-";
  const ts = Date.parse(lastSeen);
  if (Number.isNaN(ts)) return lastSeen;
  const secs = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (secs < 60) return t("clientsJustNow");
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}${t("clientsMinsAgo")}`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}${t("clientsHoursAgo")}`;
  const days = Math.floor(hours / 24);
  return `${days}${t("clientsDaysAgo")}`;
}

function protocolBadges(p: ClientProtocolCounts): Array<{ label: string; count: number }> {
  const items: Array<{ label: string; count: number }> = [];
  if (p.udp > 0) items.push({ label: "UDP", count: p.udp });
  if (p.tcp > 0) items.push({ label: "TCP", count: p.tcp });
  if (p.dot > 0) items.push({ label: "DoT", count: p.dot });
  if (p.doq > 0) items.push({ label: "DoQ", count: p.doq });
  if (p.doh > 0) items.push({ label: "DoH", count: p.doh });
  return items;
}

const DISCOVERED_SORT_OPTIONS: SelectOption[] = [
  { value: "last_seen", label: () => t("clientsSortLastSeen") },
  { value: "queries", label: () => t("clientsSortQueries") },
  { value: "blocked", label: () => t("clientsSortBlocked") },
];

const TRI_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("clientsInheritLabel") },
  { value: "true", label: () => t("clientsEnabledLabel") },
  { value: "false", label: () => t("clientsDisabledLabel") },
];

const BOOL_OPTIONS: SelectOption[] = [
  { value: "true", label: () => t("clientsEnabledLabel") },
  { value: "false", label: () => t("clientsDisabledLabel") },
];

const BLOCK_MODE_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("clientsInheritLabel") },
  { value: "zero_ip", label: () => t("settingsBlockZeroIp") },
  { value: "nx_domain", label: () => t("settingsBlockNxDomain") },
  { value: "no_data", label: () => t("settingsBlockNoData") },
];

export function ClientsView(props: ClientsViewProps) {
  // Group form state
  const [groupFormOpen, setGroupFormOpen] = createSignal(false);
  const [editingGroupId, setEditingGroupId] = createSignal<string | null>(null);
  const [groupName, setGroupName] = createSignal("");
  const [groupDesc, setGroupDesc] = createSignal("");
  const [groupBlocking, setGroupBlocking] = createSignal(true);
  const [groupUseGlobal, setGroupUseGlobal] = createSignal(true);
  const [groupBlockMode, setGroupBlockMode] = createSignal<OptBlockMode>("");
  const [groupCnameCloak, setGroupCnameCloak] = createSignal<TriState>("");
  const [groupUpstreams, setGroupUpstreams] = createSignal("");
  const [groupRules, setGroupRules] = createSignal("");

  // Client profile form state
  const [clientFormOpen, setClientFormOpen] = createSignal(false);
  const [editingClientId, setEditingClientId] = createSignal<string | null>(null);
  const [clientName, setClientName] = createSignal("");
  const [clientIdentifiers, setClientIdentifiers] = createSignal("");
  const [clientGroupId, setClientGroupId] = createSignal("");
  const [clientBlocking, setClientBlocking] = createSignal<TriState>("");
  const [clientUseGlobal, setClientUseGlobal] = createSignal<TriState>("");
  const [clientBlockMode, setClientBlockMode] = createSignal<OptBlockMode>("");
  const [clientUpstreams, setClientUpstreams] = createSignal("");
  const [clientRules, setClientRules] = createSignal("");
  const [clientTags, setClientTags] = createSignal("");
  const [discoveredSearch, setDiscoveredSearch] = createSignal("");
  const [discoveredSort, setDiscoveredSort] = createSignal("last_seen");
  const [expandedKey, setExpandedKey] = createSignal<string | null>(null);

  const groups = () => props.overview?.groups ?? [];
  const clients = () => props.overview?.clients ?? [];
  const discovered = () => props.overview?.discovered ?? [];
  const profileStatsMap = (): Record<string, ClientActivityStats> =>
    props.overview?.profile_stats ?? {};

  const filteredDiscovered = createMemo(() => {
    const q = discoveredSearch().trim().toLowerCase();
    const list = q
      ? discovered().filter(
          (item) =>
            item.ip.toLowerCase().includes(q) ||
            (item.resolved_name?.toLowerCase().includes(q) ?? false) ||
            (item.last_client_id?.toLowerCase().includes(q) ?? false) ||
            item.name_source.toLowerCase().includes(q),
        )
      : [...discovered()];
    const mode = discoveredSort();
    list.sort((a, b) => {
      if (mode === "queries") return b.query_count - a.query_count;
      if (mode === "blocked") return b.blocked_count - a.blocked_count;
      const ta = a.last_seen ? Date.parse(a.last_seen) : 0;
      const tb = b.last_seen ? Date.parse(b.last_seen) : 0;
      return tb - ta || b.query_count - a.query_count;
    });
    return list;
  });

  function toggleExpanded(key: string) {
    setExpandedKey((prev) => (prev === key ? null : key));
  }

  const groupNameById = (id: string | null) => {
    if (!id) return null;
    return groups().find((g) => g.id === id)?.name ?? id;
  };

  const groupOptions = (): SelectOption[] => [
    { value: "", label: () => t("clientsNoGroup") },
    ...groups().map((g) => ({ value: g.id, label: () => g.name })),
  ];

  function openNewGroup() {
    setEditingGroupId(null);
    setGroupName("");
    setGroupDesc("");
    setGroupBlocking(true);
    setGroupUseGlobal(true);
    setGroupBlockMode("");
    setGroupCnameCloak("");
    setGroupUpstreams("");
    setGroupRules("");
    setGroupFormOpen(true);
  }

  function openEditGroup(g: ClientGroup) {
    setEditingGroupId(g.id);
    setGroupName(g.name);
    setGroupDesc(g.description);
    setGroupBlocking(g.blocking_enabled);
    setGroupUseGlobal(g.use_global_rules);
    setGroupBlockMode(g.block_mode ?? "");
    setGroupCnameCloak(toTriState(g.cname_cloaking_blocking));
    setGroupUpstreams(g.upstreams.join("\n"));
    setGroupRules(g.custom_rules);
    setGroupFormOpen(true);
  }

  async function submitGroup(e: Event) {
    e.preventDefault();
    const payload: ClientGroupPayload = {
      name: groupName().trim(),
      description: groupDesc().trim(),
      blocking_enabled: groupBlocking(),
      use_global_rules: groupUseGlobal(),
      custom_rules: groupRules(),
      upstreams: parseLines(groupUpstreams()),
      block_mode: groupBlockMode() === "" ? null : (groupBlockMode() as BlockMode),
      cname_cloaking_blocking: fromTriState(groupCnameCloak()),
    };
    const editId = editingGroupId();
    const ok = editId
      ? await props.onUpdateGroup(editId, payload)
      : await props.onCreateGroup(payload);
    if (ok) {
      setGroupFormOpen(false);
    }
  }

  function openNewClient(prefillName = "", prefillIdentifier = "") {
    setEditingClientId(null);
    setClientName(prefillName);
    setClientIdentifiers(prefillIdentifier);
    setClientGroupId("");
    setClientBlocking("");
    setClientUseGlobal("");
    setClientBlockMode("");
    setClientUpstreams("");
    setClientRules("");
    setClientTags("");
    setClientFormOpen(true);
  }

  function openEditClient(c: ClientProfile) {
    setEditingClientId(c.id);
    setClientName(c.name);
    setClientIdentifiers(c.identifiers.join("\n"));
    setClientGroupId(c.group_id ?? "");
    setClientBlocking(toTriState(c.blocking_enabled));
    setClientUseGlobal(toTriState(c.use_global_rules));
    setClientBlockMode(c.block_mode ?? "");
    setClientUpstreams(c.upstreams.join("\n"));
    setClientRules(c.custom_rules);
    setClientTags(c.tags.join(", "));
    setClientFormOpen(true);
  }

  function handleConfigureDiscovered(d: DiscoveredClient) {
    if (d.profile_id) {
      const existing = clients().find((c) => c.id === d.profile_id);
      if (existing) {
        openEditClient(existing);
        return;
      }
    }
    openNewClient(d.resolved_name ?? d.ip, d.ip);
  }

  async function submitClient(e: Event) {
    e.preventDefault();
    const payload: ClientProfilePayload = {
      name: clientName().trim(),
      identifiers: parseLines(clientIdentifiers()),
      group_id: clientGroupId() === "" ? null : clientGroupId(),
      blocking_enabled: fromTriState(clientBlocking()),
      use_global_rules: fromTriState(clientUseGlobal()),
      custom_rules: clientRules(),
      upstreams: parseLines(clientUpstreams()),
      block_mode: clientBlockMode() === "" ? null : (clientBlockMode() as BlockMode),
      tags: parseTags(clientTags()),
    };
    const editId = editingClientId();
    const ok = editId
      ? await props.onUpdateClient(editId, payload)
      : await props.onCreateClient(payload);
    if (ok) {
      setClientFormOpen(false);
    }
  }

  return (
    <div class="space-y-5 sm:space-y-6 animate-view-enter">
      {/* Global toast & refresh bar */}
      <div class="flex flex-wrap items-center justify-between gap-3">
        <Show when={props.message} fallback={<div />}>
          <span
            class={`animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
              props.isError
                ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
            }`}
          >
            {props.message}
          </span>
        </Show>

        <button
          type="button"
          onClick={() => props.onRefresh()}
          class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] hover:border-[#d4d4d8] dark:hover:border-[#404040] text-[#171717] dark:text-[#ededed] flex items-center gap-1.5 cursor-pointer"
        >
          <span class="i-ri-refresh-line text-sm" />
          {t("logsRefresh")}
        </button>
      </div>

      {/* Section 1: Client Groups */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
              {t("clientsGroupsTitle")}
            </h2>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("clientsGroupsSubtitle")}</p>
          </div>
          <button
            type="button"
            onClick={openNewGroup}
            class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer shrink-0 flex items-center gap-1.5"
          >
            <span class="i-ri-add-line text-sm" />
            {t("clientsAddGroup")}
          </button>
        </div>

        <Show when={groupFormOpen()}>
          <form
            onSubmit={submitGroup}
            class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-4"
          >
            <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
              {editingGroupId() ? t("clientsEditGroup") : t("clientsAddGroup")}
            </h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsGroupNameLabel")}
                </label>
                <input
                  type="text"
                  required
                  value={groupName()}
                  onInput={(e) => setGroupName(e.currentTarget.value)}
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsGroupDescLabel")}
                </label>
                <input
                  type="text"
                  value={groupDesc()}
                  onInput={(e) => setGroupDesc(e.currentTarget.value)}
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsBlockingLabel")}
                </label>
                <SelectMenu
                  value={groupBlocking() ? "true" : "false"}
                  options={BOOL_OPTIONS}
                  onChange={(v) => setGroupBlocking(v === "true")}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsUseGlobalLabel")}
                </label>
                <SelectMenu
                  value={groupUseGlobal() ? "true" : "false"}
                  options={BOOL_OPTIONS}
                  onChange={(v) => setGroupUseGlobal(v === "true")}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsBlockModeLabel")}
                </label>
                <SelectMenu
                  value={groupBlockMode()}
                  options={BLOCK_MODE_OPTIONS}
                  onChange={(v) => setGroupBlockMode(v as OptBlockMode)}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("settingsCnameCloakingLabel")}
                </label>
                <SelectMenu
                  value={groupCnameCloak()}
                  options={TRI_OPTIONS}
                  onChange={(v) => setGroupCnameCloak(v as TriState)}
                  class="w-full"
                />
              </div>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsUpstreamsLabel")}
                </label>
                <textarea
                  rows={3}
                  spellcheck={false}
                  value={groupUpstreams()}
                  onInput={(e) => setGroupUpstreams(e.currentTarget.value)}
                  placeholder="https://dns.cloudflare.com/dns-query"
                  class="w-full bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsCustomRulesLabel")}
                </label>
                <textarea
                  rows={3}
                  spellcheck={false}
                  value={groupRules()}
                  onInput={(e) => setGroupRules(e.currentTarget.value)}
                  placeholder="||games.example.com^"
                  class="w-full bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
            </div>
            <div class="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setGroupFormOpen(false)}
                class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#666666] dark:text-[#a1a1aa] cursor-pointer"
              >
                {t("clientsCancelBtn")}
              </button>
              <button
                type="submit"
                disabled={props.saving}
                class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer disabled:opacity-50"
              >
                {t("clientsSaveBtn")}
              </button>
            </div>
          </form>
        </Show>

        <Show
          when={groups().length > 0}
          fallback={
            <p class="text-xs text-[#8f8f8f] dark:text-[#71717a] py-2">{t("clientsEmptyGroups")}</p>
          }
        >
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <For each={groups()}>
              {(group) => (
                <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2">
                  <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0">
                      <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-sm font-medium text-[#171717] dark:text-[#ededed] truncate">
                          {group.name}
                        </span>
                        <span
                          class={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                            group.blocking_enabled
                              ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                              : "bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/20"
                          }`}
                        >
                          {group.blocking_enabled
                            ? t("clientsEnabledLabel")
                            : t("clientsDisabledLabel")}
                        </span>
                        <Show when={group.block_mode}>
                          {(bm) => (
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
                              {bm()}
                            </span>
                          )}
                        </Show>
                      </div>
                      <Show when={group.description}>
                        <p class="text-xs text-[#666666] dark:text-[#a1a1aa] mt-0.5">
                          {group.description}
                        </p>
                      </Show>
                    </div>
                    <div class="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        onClick={() => openEditGroup(group)}
                        class="px-2 py-1 rounded text-[11px] font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
                      >
                        {t("clientsEditBtn")}
                      </button>
                      <button
                        type="button"
                        onClick={() => void props.onDeleteGroup(group.id)}
                        class="px-2 py-1 rounded text-[11px] font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 dark:text-rose-400 border border-rose-500/20 cursor-pointer"
                      >
                        {t("clientsDeleteBtn")}
                      </button>
                    </div>
                  </div>
                  <div class="flex flex-wrap gap-3 text-[11px] font-mono text-[#666666] dark:text-[#8f8f8f]">
                    <span>
                      {t("clientsUseGlobalLabel")}:{" "}
                      {group.use_global_rules
                        ? t("clientsEnabledLabel")
                        : t("clientsDisabledLabel")}
                    </span>
                    <Show when={group.upstreams.length > 0}>
                      <span>Upstreams: {group.upstreams.length}</span>
                    </Show>
                    <Show when={group.custom_rules.trim().length > 0}>
                      <span>Rules: {parseLines(group.custom_rules).length}</span>
                    </Show>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>

      {/* Section 2: Configured Client Profiles */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
              {t("clientsProfilesTitle")}
            </h2>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("clientsProfilesSubtitle")}</p>
          </div>
          <button
            type="button"
            onClick={() => openNewClient()}
            class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer shrink-0 flex items-center gap-1.5"
          >
            <span class="i-ri-user-add-line text-sm" />
            {t("clientsAddProfile")}
          </button>
        </div>

        <Show when={clientFormOpen()}>
          <form
            onSubmit={submitClient}
            class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-4"
          >
            <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
              {editingClientId() ? t("clientsEditProfile") : t("clientsAddProfile")}
            </h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsNameLabel")}
                </label>
                <input
                  type="text"
                  required
                  value={clientName()}
                  onInput={(e) => setClientName(e.currentTarget.value)}
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsGroupSelectLabel")}
                </label>
                <SelectMenu
                  value={clientGroupId()}
                  options={groupOptions()}
                  onChange={setClientGroupId}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsBlockingLabel")}
                </label>
                <SelectMenu
                  value={clientBlocking()}
                  options={TRI_OPTIONS}
                  onChange={(v) => setClientBlocking(v as TriState)}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsUseGlobalLabel")}
                </label>
                <SelectMenu
                  value={clientUseGlobal()}
                  options={TRI_OPTIONS}
                  onChange={(v) => setClientUseGlobal(v as TriState)}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsBlockModeLabel")}
                </label>
                <SelectMenu
                  value={clientBlockMode()}
                  options={BLOCK_MODE_OPTIONS}
                  onChange={(v) => setClientBlockMode(v as OptBlockMode)}
                  class="w-full"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsTagsLabel")}
                </label>
                <input
                  type="text"
                  value={clientTags()}
                  onInput={(e) => setClientTags(e.currentTarget.value)}
                  placeholder="laptop, trusted"
                  class="w-full h-9 bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
            </div>

            <div>
              <div class="flex flex-wrap items-center justify-between gap-2 mb-1">
                <label class="text-xs text-[#666666] dark:text-[#a1a1aa]">
                  {t("clientsIdentifiersLabel")}
                </label>
                <span class="text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                  {t("clientsIdentifiersHint")}
                </span>
              </div>
              <textarea
                rows={3}
                spellcheck={false}
                value={clientIdentifiers()}
                onInput={(e) => setClientIdentifiers(e.currentTarget.value)}
                placeholder={"192.168.1.42\n10.0.50.0/24\nalice-laptop"}
                class="w-full bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsUpstreamsLabel")}
                </label>
                <textarea
                  rows={3}
                  spellcheck={false}
                  value={clientUpstreams()}
                  onInput={(e) => setClientUpstreams(e.currentTarget.value)}
                  placeholder="tls://dns.quad9.net"
                  class="w-full bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div>
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("clientsCustomRulesLabel")}
                </label>
                <textarea
                  rows={3}
                  spellcheck={false}
                  value={clientRules()}
                  onInput={(e) => setClientRules(e.currentTarget.value)}
                  placeholder="@@||analytics.example.com^"
                  class="w-full bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
            </div>

            <div class="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setClientFormOpen(false)}
                class="h-8 px-3 rounded-lg text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#666666] dark:text-[#a1a1aa] cursor-pointer"
              >
                {t("clientsCancelBtn")}
              </button>
              <button
                type="submit"
                disabled={props.saving}
                class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer disabled:opacity-50"
              >
                {t("clientsSaveBtn")}
              </button>
            </div>
          </form>
        </Show>

        <Show
          when={clients().length > 0}
          fallback={
            <p class="text-xs text-[#8f8f8f] dark:text-[#71717a] py-2">
              {t("clientsEmptyProfiles")}
            </p>
          }
        >
          <div class="space-y-2.5">
            <For each={clients()}>
              {(client) => {
                const pStats = () => profileStatsMap()[client.id];
                const isExpanded = () => expandedKey() === `profile:${client.id}`;
                return (
                  <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-2.5">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div class="min-w-0 space-y-1">
                        <div class="flex items-center gap-2 flex-wrap">
                          <Show when={pStats()}>
                            {(st) => {
                              const lvl = () => activityLevel(st().last_seen);
                              return (
                                <span
                                  title={`${t("clientsLastSeen")}: ${formatRelativeTime(st().last_seen)}`}
                                  class={`inline-block h-2 w-2 rounded-full shrink-0 ${
                                    lvl() === "active"
                                      ? "bg-emerald-500"
                                      : lvl() === "recent"
                                        ? "bg-amber-500"
                                        : "bg-zinc-400 dark:bg-zinc-600"
                                  }`}
                                />
                              );
                            }}
                          </Show>
                          <span class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
                            {client.name}
                          </span>
                          <Show when={groupNameById(client.group_id)}>
                            {(gname) => (
                              <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-500/20">
                                {gname()}
                              </span>
                            )}
                          </Show>
                          <Show when={client.blocking_enabled !== null}>
                            <span
                              class={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                                client.blocking_enabled
                                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                                  : "bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-500/20"
                              }`}
                            >
                              {client.blocking_enabled
                                ? t("clientsEnabledLabel")
                                : t("clientsDisabledLabel")}
                            </span>
                          </Show>
                          <For each={client.tags}>
                            {(tag) => (
                              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa]">
                                #{tag}
                              </span>
                            )}
                          </For>
                        </div>
                        <div class="flex flex-wrap gap-1.5">
                          <For each={client.identifiers}>
                            {(ident) => (
                              <span class="px-2 py-0.5 rounded font-mono text-[11px] bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed]">
                                {ident}
                              </span>
                            )}
                          </For>
                        </div>
                        <Show when={pStats()}>
                          {(st) => (
                            <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[#666666] dark:text-[#a1a1aa] pt-0.5 tabular-nums">
                              <span>
                                {st().total_queries.toLocaleString()} {t("clientsQueriesSuffix")}
                              </span>
                              <span>
                                {t("statBlocked")}: {st().blocked_queries.toLocaleString()} (
                                {(st().block_rate * 100).toFixed(1)}%)
                              </span>
                              <span>
                                {t("clientsLastSeen")}: {formatRelativeTime(st().last_seen)}
                              </span>
                              <For each={protocolBadges(st().protocols)}>
                                {(pb) => (
                                  <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626]">
                                    {pb.label}:{pb.count}
                                  </span>
                                )}
                              </For>
                            </div>
                          )}
                        </Show>
                      </div>

                      <div class="flex items-center gap-1.5 shrink-0">
                        <Show when={pStats()}>
                          <button
                            type="button"
                            onClick={() => toggleExpanded(`profile:${client.id}`)}
                            class="px-2.5 py-1 rounded text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
                          >
                            {isExpanded() ? t("clientsHideStatsBtn") : t("clientsShowStatsBtn")}
                          </button>
                        </Show>
                        <button
                          type="button"
                          onClick={() => openEditClient(client)}
                          class="px-2.5 py-1 rounded text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
                        >
                          {t("clientsEditBtn")}
                        </button>
                        <button
                          type="button"
                          onClick={() => void props.onDeleteClient(client.id)}
                          class="px-2.5 py-1 rounded text-xs font-medium bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 dark:text-rose-400 border border-rose-500/20 cursor-pointer"
                        >
                          {t("clientsDeleteBtn")}
                        </button>
                      </div>
                    </div>

                    <Show when={isExpanded() && pStats()}>
                      {(st) => (
                        <ClientTopDomainsGrid
                          topDomains={st().top_domains}
                          topBlocked={st().top_blocked}
                        />
                      )}
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>

      {/* Section 3: Discovered Active LAN Clients */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
              {t("clientsDiscoveredTitle")}
            </h2>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">
              {t("clientsDiscoveredSubtitle")}
            </p>
          </div>
          <Show when={discovered().length > 0}>
            <div class="flex items-center gap-2 shrink-0">
              <div class="relative">
                <span class="i-ri-search-line absolute left-2.5 top-1/2 -translate-y-1/2 text-[#8f8f8f] text-xs pointer-events-none" />
                <input
                  type="text"
                  value={discoveredSearch()}
                  onInput={(e) => setDiscoveredSearch(e.currentTarget.value)}
                  placeholder={t("clientsDiscoveredSearchPlaceholder")}
                  class="h-8 w-44 sm:w-52 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg pl-8 pr-2.5 text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <SelectMenu
                value={discoveredSort()}
                options={DISCOVERED_SORT_OPTIONS}
                onChange={setDiscoveredSort}
                class="w-32"
              />
            </div>
          </Show>
        </div>

        <Show
          when={filteredDiscovered().length > 0}
          fallback={
            <p class="text-xs text-[#8f8f8f] dark:text-[#71717a] py-2">{t("noDataRecorded")}</p>
          }
        >
          <div class="divide-y divide-[#f0f0f0] dark:divide-[#1a1a1a]">
            <For each={filteredDiscovered()}>
              {(item) => {
                const lvl = () => activityLevel(item.last_seen);
                const isExpanded = () => expandedKey() === `ip:${item.ip}`;
                return (
                  <div class="py-3 space-y-2.5">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div class="space-y-1 min-w-0">
                        <div class="flex items-center gap-2 min-w-0 flex-wrap">
                          <span
                            title={`${t("clientsLastSeen")}: ${formatRelativeTime(item.last_seen)}`}
                            class={`inline-block h-2 w-2 rounded-full shrink-0 ${
                              lvl() === "active"
                                ? "bg-emerald-500"
                                : lvl() === "recent"
                                  ? "bg-amber-500"
                                  : "bg-zinc-400 dark:bg-zinc-600"
                            }`}
                          />
                          <span class="font-mono text-xs font-medium text-[#171717] dark:text-[#ededed]">
                            {item.ip}
                          </span>
                          <Show when={item.resolved_name}>
                            {(name) => (
                              <span class="text-xs text-[#171717] dark:text-[#ededed] font-medium truncate">
                                {name()}
                              </span>
                            )}
                          </Show>
                          <Show when={item.last_client_id}>
                            {(cid) => (
                              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 border border-indigo-500/20">
                                ID: {cid()}
                              </span>
                            )}
                          </Show>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#666666] dark:text-[#a1a1aa]">
                            {sourceLabel(item.name_source)}
                          </span>
                          <Show when={item.profile_id}>
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                              {t("clientsConfiguredBadge")}
                            </span>
                          </Show>
                        </div>

                        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[#666666] dark:text-[#a1a1aa] tabular-nums">
                          <span>
                            {item.query_count.toLocaleString()} {t("clientsQueriesSuffix")}
                          </span>
                          <span>
                            {t("statBlocked")}: {item.blocked_count.toLocaleString()} (
                            {(item.block_rate * 100).toFixed(1)}%)
                          </span>
                          <span>
                            {t("statCacheHits")}: {item.cached_count.toLocaleString()}
                          </span>
                          <span>
                            {t("clientsLastSeen")}: {formatRelativeTime(item.last_seen)}
                          </span>
                          <For each={protocolBadges(item.protocols)}>
                            {(pb) => (
                              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#fafafa] dark:bg-[#050505] border border-[#eaeaea] dark:border-[#262626]">
                                {pb.label}:{pb.count}
                              </span>
                            )}
                          </For>
                        </div>
                      </div>

                      <div class="flex items-center gap-1.5 shrink-0">
                        <Show when={item.top_domains.length > 0 || item.top_blocked.length > 0}>
                          <button
                            type="button"
                            onClick={() => toggleExpanded(`ip:${item.ip}`)}
                            class="px-2.5 py-1 rounded text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
                          >
                            {isExpanded() ? t("clientsHideStatsBtn") : t("clientsShowStatsBtn")}
                          </button>
                        </Show>
                        <button
                          type="button"
                          onClick={() => handleConfigureDiscovered(item)}
                          class="px-2.5 py-1 rounded text-xs font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] text-[#171717] dark:text-[#ededed] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
                        >
                          {item.profile_id ? t("clientsEditBtn") : t("clientsConfigureBtn")}
                        </button>
                      </div>
                    </div>

                    <Show when={isExpanded()}>
                      <ClientTopDomainsGrid
                        topDomains={item.top_domains}
                        topBlocked={item.top_blocked}
                      />
                    </Show>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}

function ClientTopDomainsGrid(props: { topDomains: TopItem[]; topBlocked: TopItem[] }) {
  return (
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-3 text-xs">
      <div class="space-y-1.5">
        <p class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
          {t("topQueriedDomains")}
        </p>
        <Show
          when={props.topDomains.length > 0}
          fallback={<p class="text-[11px] text-[#8f8f8f]">{t("noDataRecorded")}</p>}
        >
          <div class="space-y-1">
            <For each={props.topDomains}>
              {(row) => (
                <div class="flex items-center justify-between gap-2 font-mono text-[11px]">
                  <span class="truncate text-[#171717] dark:text-[#ededed]">{row.name}</span>
                  <span class="text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {row.count}
                  </span>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>
      <div class="space-y-1.5">
        <p class="text-[11px] font-medium text-[#666666] dark:text-[#a1a1aa]">
          {t("topBlockedDomains")}
        </p>
        <Show
          when={props.topBlocked.length > 0}
          fallback={<p class="text-[11px] text-[#8f8f8f]">{t("noDataRecorded")}</p>}
        >
          <div class="space-y-1">
            <For each={props.topBlocked}>
              {(row) => (
                <div class="flex items-center justify-between gap-2 font-mono text-[11px]">
                  <span class="truncate text-rose-600 dark:text-rose-400">{row.name}</span>
                  <span class="text-[#666666] dark:text-[#a1a1aa] tabular-nums shrink-0">
                    {row.count}
                  </span>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}
