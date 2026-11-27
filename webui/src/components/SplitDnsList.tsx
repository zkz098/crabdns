import { For, Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { SplitDnsRule } from "../types/SplitDnsRule";
import type { UpstreamPolicy } from "../types/UpstreamPolicy";
import { InfoTooltip } from "./InfoTooltip";
import { ToggleSwitch } from "./settings/SettingsControls";
import {
  UpstreamPolicyEditor,
  emptyUpstreamPolicy,
  upstreamPolicyBadges,
} from "./UpstreamPolicyEditor";

type RuleSourceType = "domain" | "url" | "file";

interface SplitDnsListProps {
  rules: SplitDnsRule[];
  onChange: (next: SplitDnsRule[]) => void;
  refreshing?: boolean;
  onRefresh?: () => Promise<void> | void;
}

function ruleSourceType(rule: SplitDnsRule): RuleSourceType {
  if (rule.domains_url) return "url";
  if (rule.domains_file) return "file";
  return "domain";
}

function ruleTarget(rule: SplitDnsRule): string {
  return rule.domains_url ?? rule.domains_file ?? rule.domain;
}

function buildRule(
  kind: RuleSourceType,
  targetRaw: string,
  upstreamsRaw: string,
  fallbackToDefault: boolean,
  policy: UpstreamPolicy,
): SplitDnsRule | null {
  const target = targetRaw.trim();
  const upstreams = upstreamsRaw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (!target || upstreams.length === 0) {
    return null;
  }
  return {
    domain: kind === "domain" ? target : "",
    domains_file: kind === "file" ? target : null,
    domains_url: kind === "url" ? target : null,
    upstreams,
    fallback_to_default: fallbackToDefault,
    policy,
  };
}

export function SplitDnsList(props: SplitDnsListProps) {
  const [formOpen, setFormOpen] = createSignal(false);
  const [editingIndex, setEditingIndex] = createSignal<number | null>(null);
  const [kind, setKind] = createSignal<RuleSourceType>("domain");
  const [target, setTarget] = createSignal("");
  const [upstreams, setUpstreams] = createSignal("");
  const [fallback, setFallback] = createSignal(true);
  const [policy, setPolicy] = createSignal<UpstreamPolicy>(emptyUpstreamPolicy());

  function openAddForm(
    presetKind: RuleSourceType = "domain",
    presetTarget = "",
    presetUpstreams = "",
    presetFallback = true,
    presetPolicy: UpstreamPolicy = emptyUpstreamPolicy(),
  ) {
    setEditingIndex(null);
    setKind(presetKind);
    setTarget(presetTarget);
    setUpstreams(presetUpstreams);
    setFallback(presetFallback);
    setPolicy(presetPolicy);
    setFormOpen(true);
  }

  function openEditForm(index: number, rule: SplitDnsRule) {
    setEditingIndex(index);
    setKind(ruleSourceType(rule));
    setTarget(ruleTarget(rule));
    setUpstreams(rule.upstreams.join(", "));
    setFallback(rule.fallback_to_default);
    setPolicy(rule.policy ? { ...rule.policy } : emptyUpstreamPolicy());
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditingIndex(null);
    setTarget("");
    setUpstreams("");
    setFallback(true);
    setPolicy(emptyUpstreamPolicy());
  }

  function submitForm() {
    const built = buildRule(kind(), target(), upstreams(), fallback(), policy());
    if (!built) return;
    const idx = editingIndex();
    if (idx === null) {
      props.onChange([...props.rules, built]);
    } else {
      props.onChange(props.rules.map((item, i) => (i === idx ? built : item)));
    }
    closeForm();
  }

  function removeAt(index: number) {
    props.onChange(props.rules.filter((_, i) => i !== index));
    if (editingIndex() === index) {
      closeForm();
    }
  }

  function moveItem(index: number, delta: -1 | 1) {
    const nextIdx = index + delta;
    if (nextIdx < 0 || nextIdx >= props.rules.length) return;
    const copy = [...props.rules];
    [copy[index], copy[nextIdx]] = [copy[nextIdx], copy[index]];
    props.onChange(copy);
  }

  function addCnPreset() {
    openAddForm(
      "url",
      "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
      "https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
      true,
    );
  }

  function addLanPreset() {
    openAddForm("domain", "corp.local", "udp://10.0.0.1:53", false);
  }

  const placeholderForKind = () => {
    switch (kind()) {
      case "url":
        return "https://raw.githubusercontent.com/.../accelerated-domains.china.conf";
      case "file":
        return "/etc/crabdns/cn-domains.txt";
      case "domain":
        return "corp.local";
    }
  };

  return (
    <div class="space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <label class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed]">
            <span>{t("settingsSplitDnsLabel")}</span>
            <InfoTooltip text={t("tooltipSplitDns")} align="left" />
          </label>
          <p class="text-[11px] text-[#8f8f8f] dark:text-[#71717a] mt-0.5">
            {t("settingsSplitDnsHint")}
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          <Show when={props.onRefresh}>
            <button
              type="button"
              disabled={props.refreshing}
              onClick={() => props.onRefresh?.()}
              class="h-7 px-2.5 rounded-lg text-[11px] font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1 cursor-pointer transition-colors disabled:opacity-50"
            >
              <span class="i-ri-refresh-line text-xs" />
              <span>{t("settingsSplitDnsRefreshBtn")}</span>
            </button>
          </Show>
          <button
            type="button"
            onClick={() => openAddForm()}
            class="h-7 px-2.5 rounded-lg text-[11px] font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] hover:opacity-90 flex items-center gap-1 cursor-pointer transition-opacity"
          >
            <span class="i-ri-add-line text-xs" />
            <span>{t("splitDnsAddBtn")}</span>
          </button>
        </div>
      </div>

      {/* Quick Presets */}
      <div class="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={addCnPreset}
          class="h-6 px-2 rounded-md text-[11px] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer transition-colors"
        >
          {t("splitDnsPresetCnBtn")}
        </button>
        <button
          type="button"
          onClick={addLanPreset}
          class="h-6 px-2 rounded-md text-[11px] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer transition-colors"
        >
          {t("splitDnsPresetLanBtn")}
        </button>
      </div>

      {/* Add / Edit Form */}
      <Show when={formOpen()}>
        <div class="rounded-lg border border-[#d4d4d8] dark:border-[#3f3f46] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
          <div class="flex flex-wrap items-center gap-1.5">
            {(["domain", "url", "file"] as const).map((option) => (
              <button
                type="button"
                onClick={() => setKind(option)}
                class={`h-7 px-2.5 rounded-md text-[11px] font-medium border cursor-pointer transition-colors ${
                  kind() === option
                    ? "bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] border-[#171717] dark:border-[#ededed]"
                    : "bg-white dark:bg-[#111111] text-[#666666] dark:text-[#a1a1aa] border-[#eaeaea] dark:border-[#262626] hover:text-[#171717] dark:hover:text-[#ededed]"
                }`}
              >
                {option === "domain"
                  ? t("splitDnsTypeDomain")
                  : option === "url"
                    ? t("splitDnsTypeUrl")
                    : t("splitDnsTypeFile")}
              </button>
            ))}
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("splitDnsTargetLabel")}
              </label>
              <input
                type="text"
                value={target()}
                placeholder={placeholderForKind()}
                onInput={(e) => setTarget(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("splitDnsUpstreamsLabel")}
              </label>
              <input
                type="text"
                value={upstreams()}
                placeholder="https://dns.alidns.com/dns-query, https://doh.pub/dns-query"
                onInput={(e) => setUpstreams(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>

          <UpstreamPolicyEditor policy={policy()} onChange={setPolicy} />

          <div class="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div class="flex items-center gap-2.5 text-xs text-[#171717] dark:text-[#ededed]">
              <ToggleSwitch
                compact
                checked={fallback()}
                onChange={setFallback}
                ariaLabel={t("splitDnsFallbackLabel")}
              />
              <span>{t("splitDnsFallbackLabel")}</span>
            </div>
            <div class="flex items-center gap-2">
              <button
                type="button"
                onClick={closeForm}
                class="h-7 px-3 rounded-md text-xs bg-white dark:bg-[#111111] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer"
              >
                {t("clientsCancelBtn")}
              </button>
              <button
                type="button"
                disabled={!target().trim() || !upstreams().trim()}
                onClick={submitForm}
                class="h-7 px-3 rounded-md text-xs font-medium bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] cursor-pointer disabled:opacity-40"
              >
                {t("clientsSaveBtn")}
              </button>
            </div>
          </div>
        </div>
      </Show>

      {/* Rules List */}
      <Show
        when={props.rules.length > 0}
        fallback={
          <div class="rounded-lg border border-dashed border-[#eaeaea] dark:border-[#262626] px-3 py-4 text-center text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
            {t("splitDnsEmpty")}
          </div>
        }
      >
        <div class="divide-y divide-[#eaeaea] dark:divide-[#262626] border border-[#eaeaea] dark:border-[#262626] rounded-lg bg-[#fafafa] dark:bg-[#050505]">
          <For each={props.rules}>
            {(rule, index) => {
              const kindLabel = () => {
                const src = ruleSourceType(rule);
                return src === "url"
                  ? t("splitDnsTypeUrl")
                  : src === "file"
                    ? t("splitDnsTypeFile")
                    : t("splitDnsTypeDomain");
              };
              return (
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3 py-2.5">
                  <div class="min-w-0 flex-1 space-y-1">
                    <div class="flex flex-wrap items-center gap-1.5">
                      <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#eaeaea] dark:bg-[#1f1f1f] text-[#52525b] dark:text-[#a1a1aa]">
                        {kindLabel()}
                      </span>
                      <span class="font-mono text-xs font-medium text-[#171717] dark:text-[#ededed] break-all">
                        {ruleTarget(rule)}
                      </span>
                      <span
                        class={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          rule.fallback_to_default
                            ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                            : "bg-amber-500/10 text-amber-700 dark:text-amber-400"
                        }`}
                      >
                        {rule.fallback_to_default
                          ? t("splitDnsFallbackBadge")
                          : t("splitDnsStrictBadge")}
                      </span>
                    </div>
                    <div class="flex flex-wrap items-center gap-1">
                      <For each={rule.upstreams}>
                        {(up) => (
                          <span class="px-1.5 py-0.5 rounded bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] font-mono text-[11px] text-[#52525b] dark:text-[#a1a1aa]">
                            {up}
                          </span>
                        )}
                      </For>
                      <For each={upstreamPolicyBadges(rule.policy)}>
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
                      disabled={index() === 0}
                      onClick={() => moveItem(index(), -1)}
                      class="w-7 h-7 rounded-md flex items-center justify-center text-[#666666] dark:text-[#a1a1aa] hover:bg-[#eaeaea]/60 dark:hover:bg-[#1f1f1f] disabled:opacity-30 cursor-pointer"
                    >
                      <span class="i-ri-arrow-up-s-line text-sm" />
                    </button>
                    <button
                      type="button"
                      disabled={index() === props.rules.length - 1}
                      onClick={() => moveItem(index(), 1)}
                      class="w-7 h-7 rounded-md flex items-center justify-center text-[#666666] dark:text-[#a1a1aa] hover:bg-[#eaeaea]/60 dark:hover:bg-[#1f1f1f] disabled:opacity-30 cursor-pointer"
                    >
                      <span class="i-ri-arrow-down-s-line text-sm" />
                    </button>
                    <button
                      type="button"
                      onClick={() => openEditForm(index(), rule)}
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
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
