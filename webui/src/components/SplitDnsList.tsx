import { For, Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { QueryProtocol } from "../types/QueryProtocol";
import type { ResponseIpRule } from "../types/ResponseIpRule";
import type { SplitDnsMatchMode } from "../types/SplitDnsMatchMode";
import type { SplitDnsRule } from "../types/SplitDnsRule";
import type { UpstreamGroup } from "../types/UpstreamGroup";
import type { UpstreamPolicy } from "../types/UpstreamPolicy";
import { InfoTooltip } from "./InfoTooltip";
import { SelectMenu, type SelectOption } from "./SelectMenu";
import { ToggleSwitch } from "./settings/SettingsControls";
import {
  UpstreamPolicyEditor,
  emptyUpstreamPolicy,
  upstreamPolicyBadges,
} from "./UpstreamPolicyEditor";

type RuleSourceType = "domain" | "url" | "file";

const ALL_PROTOCOLS: QueryProtocol[] = ["udp", "tcp", "dot", "doq", "doh", "doh3"];

interface SplitDnsListProps {
  rules: SplitDnsRule[];
  onChange: (next: SplitDnsRule[]) => void;
  upstreamGroups?: UpstreamGroup[];
  matchMode?: SplitDnsMatchMode;
  onMatchModeChange?: (next: SplitDnsMatchMode) => void;
  splitBeforeClientUpstreams?: boolean;
  onSplitBeforeClientUpstreamsChange?: (next: boolean) => void;
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

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function localityValue(v: boolean | null | undefined): string {
  if (v === true) return "true";
  if (v === false) return "false";
  return "";
}

function parseLocalityValue(raw: string): boolean | null {
  if (raw === "true") return true;
  if (raw === "false") return false;
  return null;
}

function hasResponseIpConfig(rip?: ResponseIpRule | null): boolean {
  if (!rip) return false;
  return (
    rip.expected_cidrs.length > 0 ||
    Boolean(rip.expected_ip_file) ||
    Boolean(rip.expected_ip_url) ||
    rip.match_cname_domains.length > 0 ||
    rip.fallback_on_empty
  );
}

export function SplitDnsList(props: SplitDnsListProps) {
  const [formOpen, setFormOpen] = createSignal(false);
  const [editingIndex, setEditingIndex] = createSignal<number | null>(null);
  const [advOpen, setAdvOpen] = createSignal(false);
  const [respIpOpen, setRespIpOpen] = createSignal(false);

  const [ruleName, setRuleName] = createSignal("");
  const [ruleEnabled, setRuleEnabled] = createSignal(true);
  const [kind, setKind] = createSignal<RuleSourceType>("domain");
  const [target, setTarget] = createSignal("");
  const [upstreams, setUpstreams] = createSignal("");
  const [fallback, setFallback] = createSignal(true);
  const [policy, setPolicy] = createSignal<UpstreamPolicy>(emptyUpstreamPolicy());

  // Advanced matching & fallback
  const [excludeDomains, setExcludeDomains] = createSignal("");
  const [qtypes, setQtypes] = createSignal("");
  const [clientCidrs, setClientCidrs] = createSignal("");
  const [clientGroups, setClientGroups] = createSignal("");
  const [clientTags, setClientTags] = createSignal("");
  const [protocols, setProtocols] = createSignal<QueryProtocol[]>([]);
  const [isLocal, setIsLocal] = createSignal<boolean | null>(null);
  const [fallbackUpstreams, setFallbackUpstreams] = createSignal("");
  const [fallbackNxdomain, setFallbackNxdomain] = createSignal(false);

  // Response IP routing
  const [ripCidrs, setRipCidrs] = createSignal("");
  const [ripUrl, setRipUrl] = createSignal("");
  const [ripFile, setRipFile] = createSignal("");
  const [ripInvert, setRipInvert] = createSignal(false);
  const [ripFallback, setRipFallback] = createSignal("");
  const [ripDelayMs, setRipDelayMs] = createSignal("");
  const [ripCnames, setRipCnames] = createSignal("");
  const [ripOnEmpty, setRipOnEmpty] = createSignal(false);

  const matchModeOptions: SelectOption<SplitDnsMatchMode>[] = [
    { value: "specificity_first", label: () => t("splitDnsMatchSpecificity") },
    { value: "config_order", label: () => t("splitDnsMatchConfigOrder") },
  ];

  const localityOptions: SelectOption[] = [
    { value: "", label: () => t("splitDnsLocalAuto") },
    { value: "true", label: () => t("splitDnsLocalTrue") },
    { value: "false", label: () => t("splitDnsLocalFalse") },
  ];

  function resetAdvanced(rule?: SplitDnsRule) {
    setExcludeDomains((rule?.exclude_domains ?? []).join(", "));
    setQtypes((rule?.qtypes ?? []).join(", "));
    setClientCidrs((rule?.client_cidrs ?? []).join(", "));
    setClientGroups((rule?.client_groups ?? []).join(", "));
    setClientTags((rule?.client_tags ?? []).join(", "));
    setProtocols(rule?.protocols ? [...rule.protocols] : []);
    setIsLocal(rule?.is_local ?? null);
    setFallbackUpstreams((rule?.fallback_upstreams ?? []).join(", "));
    setFallbackNxdomain(rule?.fallback_on_nxdomain ?? false);

    const rip = rule?.response_ip ?? null;
    setRipCidrs((rip?.expected_cidrs ?? []).join(", "));
    setRipUrl(rip?.expected_ip_url ?? "");
    setRipFile(rip?.expected_ip_file ?? "");
    setRipInvert(rip?.invert ?? false);
    setRipFallback((rip?.fallback_upstreams ?? []).join(", "));
    setRipDelayMs(rip?.fallback_delay_ms ? String(rip.fallback_delay_ms) : "");
    setRipCnames((rip?.match_cname_domains ?? []).join(", "));
    setRipOnEmpty(rip?.fallback_on_empty ?? false);

    const hasAdv = Boolean(
      rule &&
      (rule.exclude_domains.length > 0 ||
        rule.qtypes.length > 0 ||
        rule.client_cidrs.length > 0 ||
        rule.client_groups.length > 0 ||
        rule.client_tags.length > 0 ||
        rule.protocols.length > 0 ||
        (rule.is_local !== null && rule.is_local !== undefined) ||
        rule.fallback_upstreams.length > 0 ||
        rule.fallback_on_nxdomain),
    );
    setAdvOpen(hasAdv);
    setRespIpOpen(hasResponseIpConfig(rip));
  }

  function openAddForm(
    presetKind: RuleSourceType = "domain",
    presetTarget = "",
    presetUpstreams = "",
    presetFallback = true,
    presetPolicy: UpstreamPolicy = emptyUpstreamPolicy(),
    presetRule?: Partial<SplitDnsRule>,
  ) {
    setEditingIndex(null);
    setRuleName(presetRule?.name ?? "");
    setRuleEnabled(presetRule?.enabled ?? true);
    setKind(presetKind);
    setTarget(presetTarget);
    setUpstreams(presetUpstreams);
    setFallback(presetFallback);
    setPolicy(presetPolicy);
    resetAdvanced(
      presetRule
        ? {
            name: presetRule.name ?? null,
            enabled: presetRule.enabled ?? true,
            domain: presetTarget,
            domains_file: null,
            domains_url: null,
            exclude_domains: presetRule.exclude_domains ?? [],
            qtypes: presetRule.qtypes ?? [],
            client_cidrs: presetRule.client_cidrs ?? [],
            client_groups: presetRule.client_groups ?? [],
            client_tags: presetRule.client_tags ?? [],
            protocols: presetRule.protocols ?? [],
            upstreams: [],
            fallback_upstreams: presetRule.fallback_upstreams ?? [],
            fallback_to_default: presetFallback,
            fallback_on_nxdomain: presetRule.fallback_on_nxdomain ?? false,
            is_local: presetRule.is_local ?? null,
            policy: presetPolicy,
            response_ip: presetRule.response_ip ?? null,
          }
        : undefined,
    );
    setFormOpen(true);
  }

  function openEditForm(index: number, rule: SplitDnsRule) {
    setEditingIndex(index);
    setRuleName(rule.name ?? "");
    setRuleEnabled(rule.enabled ?? true);
    setKind(ruleSourceType(rule));
    setTarget(ruleTarget(rule));
    setUpstreams(rule.upstreams.join(", "));
    setFallback(rule.fallback_to_default);
    setPolicy(rule.policy ? { ...rule.policy } : emptyUpstreamPolicy());
    resetAdvanced(rule);
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditingIndex(null);
    setRuleName("");
    setRuleEnabled(true);
    setTarget("");
    setUpstreams("");
    setFallback(true);
    setPolicy(emptyUpstreamPolicy());
    resetAdvanced(undefined);
  }

  function buildResponseIpRule(): ResponseIpRule | null {
    const cidrs = splitTokens(ripCidrs());
    const url = ripUrl().trim() || null;
    const file = ripFile().trim() || null;
    const cnames = splitTokens(ripCnames());
    const onEmpty = ripOnEmpty();
    if (cidrs.length === 0 && !url && !file && cnames.length === 0 && !onEmpty) {
      return null;
    }
    const parsedDelay = Number(ripDelayMs().trim());
    return {
      expected_cidrs: cidrs,
      expected_ip_file: file,
      expected_ip_url: url,
      invert: ripInvert(),
      fallback_upstreams: splitTokens(ripFallback()),
      fallback_delay_ms: Number.isFinite(parsedDelay) && parsedDelay > 0 ? parsedDelay : null,
      match_cname_domains: cnames,
      fallback_on_empty: onEmpty,
    };
  }

  function submitForm() {
    const cleanTarget = target().trim();
    const cleanUpstreams = splitTokens(upstreams());
    if (!cleanTarget || cleanUpstreams.length === 0) return;

    const built: SplitDnsRule = {
      name: ruleName().trim() || null,
      enabled: ruleEnabled(),
      domain: kind() === "domain" ? cleanTarget : "",
      domains_file: kind() === "file" ? cleanTarget : null,
      domains_url: kind() === "url" ? cleanTarget : null,
      exclude_domains: splitTokens(excludeDomains()),
      qtypes: splitTokens(qtypes()).map((s) => s.toUpperCase()),
      client_cidrs: splitTokens(clientCidrs()),
      client_groups: splitTokens(clientGroups()),
      client_tags: splitTokens(clientTags()),
      protocols: protocols(),
      upstreams: cleanUpstreams,
      fallback_upstreams: splitTokens(fallbackUpstreams()),
      fallback_to_default: fallback(),
      fallback_on_nxdomain: fallbackNxdomain(),
      is_local: isLocal(),
      policy: policy(),
      response_ip: buildResponseIpRule(),
    };

    const idx = editingIndex();
    if (idx === null) {
      props.onChange([...props.rules, built]);
    } else {
      props.onChange(props.rules.map((item, i) => (i === idx ? built : item)));
    }
    closeForm();
  }

  function toggleRuleEnabled(index: number) {
    props.onChange(
      props.rules.map((item, i) => (i === index ? { ...item, enabled: !item.enabled } : item)),
    );
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

  function toggleProtocol(proto: QueryProtocol) {
    const current = protocols();
    if (current.includes(proto)) {
      setProtocols(current.filter((p) => p !== proto));
    } else {
      setProtocols([...current, proto]);
    }
  }

  function appendGroupRef(groupName: string) {
    const token = `@${groupName}`;
    const existing = splitTokens(upstreams());
    if (!existing.includes(token)) {
      setUpstreams([...existing, token].join(", "));
    }
  }

  function addCnPreset() {
    openAddForm(
      "url",
      "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
      "https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
      true,
      emptyUpstreamPolicy(),
      { name: "CN List", is_local: false },
    );
  }

  function addLanPreset() {
    openAddForm("domain", "corp.local", "udp://10.0.0.1:53", false, emptyUpstreamPolicy(), {
      name: "LAN",
      is_local: true,
    });
  }

  function addSmartCnGeoipPreset() {
    openAddForm(
      "domain",
      "regexp:.*",
      "https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
      true,
      emptyUpstreamPolicy(),
      {
        name: "Smart CN GeoIP",
        is_local: false,
        response_ip: {
          expected_cidrs: [],
          expected_ip_file: null,
          expected_ip_url:
            "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
          invert: false,
          fallback_upstreams: [
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
          ],
          fallback_delay_ms: 150,
          match_cname_domains: [],
          fallback_on_empty: true,
        },
      },
    );
  }

  const placeholderForKind = () => {
    switch (kind()) {
      case "url":
        return "https://raw.githubusercontent.com/.../accelerated-domains.china.conf";
      case "file":
        return "/etc/crabdns/cn-domains.txt";
      case "domain":
        return "corp.local, keyword:internal, regexp:^api\\.";
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

      {/* Global Split-DNS Matching Mode & Client Precedence */}
      <Show when={props.onMatchModeChange || props.onSplitBeforeClientUpstreamsChange}>
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2">
          <Show when={props.onMatchModeChange}>
            <div class="flex items-center gap-2">
              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">
                {t("splitDnsMatchModeLabel")}
              </span>
              <SelectMenu
                size="xs"
                value={props.matchMode ?? "specificity_first"}
                options={matchModeOptions}
                onChange={(val) => props.onMatchModeChange?.(val)}
                class="w-44"
                triggerClass="dark:bg-[#000000]"
              />
            </div>
          </Show>
          <Show when={props.onSplitBeforeClientUpstreamsChange}>
            <div class="flex items-center gap-2 text-[11px] text-[#171717] dark:text-[#ededed]">
              <ToggleSwitch
                compact
                checked={props.splitBeforeClientUpstreams ?? false}
                onChange={(v) => props.onSplitBeforeClientUpstreamsChange?.(v)}
                ariaLabel={t("splitDnsBeforeClientLabel")}
              />
              <span>{t("splitDnsBeforeClientLabel")}</span>
            </div>
          </Show>
        </div>
      </Show>

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
        <button
          type="button"
          onClick={addSmartCnGeoipPreset}
          class="h-6 px-2 rounded-md text-[11px] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer transition-colors"
        >
          {t("splitDnsPresetSmartCnBtn")}
        </button>
      </div>

      {/* Add / Edit Form */}
      <Show when={formOpen()}>
        <div class="rounded-lg border border-[#d4d4d8] dark:border-[#3f3f46] bg-[#fafafa] dark:bg-[#050505] p-3.5 space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
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
            <input
              type="text"
              value={ruleName()}
              placeholder={t("splitDnsNameLabel")}
              onInput={(e) => setRuleName(e.currentTarget.value)}
              class="h-7 w-44 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 text-xs text-[#171717] dark:text-[#ededed] outline-none"
            />
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
                placeholder="https://dns.alidns.com/dns-query, @cn_dns"
                onInput={(e) => setUpstreams(e.currentTarget.value)}
                class="w-full h-8 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2.5 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
              <Show when={(props.upstreamGroups ?? []).length > 0}>
                <div class="flex flex-wrap items-center gap-1 mt-1">
                  <For each={props.upstreamGroups}>
                    {(g) => (
                      <button
                        type="button"
                        onClick={() => appendGroupRef(g.name)}
                        class="px-1.5 py-0.5 rounded bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] font-mono text-[10px] text-[#52525b] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
                      >
                        +@{g.name}
                      </button>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </div>

          <UpstreamPolicyEditor policy={policy()} onChange={setPolicy} />

          {/* Advanced Matching & Fallback */}
          <div class="rounded-md border border-[#eaeaea] dark:border-[#262626] bg-white/60 dark:bg-[#0a0a0a]/60">
            <button
              type="button"
              onClick={() => setAdvOpen(!advOpen())}
              class="w-full flex items-center justify-between px-2.5 py-1.5 text-[11px] font-medium text-[#52525b] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
            >
              <span class="flex items-center gap-1.5">
                <span class={advOpen() ? "i-ri-arrow-down-s-line" : "i-ri-arrow-right-s-line"} />
                <span>{t("splitDnsAdvToggle")}</span>
              </span>
            </button>
            <Show when={advOpen()}>
              <div class="px-2.5 pb-2.5 pt-2 border-t border-[#eaeaea] dark:border-[#262626] space-y-2.5">
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsExcludeLabel")}
                    </label>
                    <input
                      type="text"
                      value={excludeDomains()}
                      placeholder="apple.com, keyword:icloud"
                      onInput={(e) => setExcludeDomains(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsQtypesLabel")}
                    </label>
                    <input
                      type="text"
                      value={qtypes()}
                      placeholder="A, AAAA, SRV"
                      onInput={(e) => setQtypes(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsLocalRouteLabel")}
                    </label>
                    <SelectMenu
                      size="xs"
                      value={localityValue(isLocal())}
                      options={localityOptions}
                      onChange={(raw) => setIsLocal(parseLocalityValue(raw))}
                      class="w-full"
                      triggerClass="dark:bg-[#000000]"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsClientCidrsLabel")}
                    </label>
                    <input
                      type="text"
                      value={clientCidrs()}
                      placeholder="192.168.10.0/24"
                      onInput={(e) => setClientCidrs(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsClientGroupsLabel")}
                    </label>
                    <input
                      type="text"
                      value={clientGroups()}
                      placeholder="kids, work"
                      onInput={(e) => setClientGroups(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsClientTagsLabel")}
                    </label>
                    <input
                      type="text"
                      value={clientTags()}
                      placeholder="vip, tv"
                      onInput={(e) => setClientTags(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsFallbackUpstreamsLabel")}
                    </label>
                    <input
                      type="text"
                      value={fallbackUpstreams()}
                      placeholder="@overseas_doh, https://dns.google/dns-query"
                      onInput={(e) => setFallbackUpstreams(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsProtocolsLabel")}
                    </label>
                    <div class="flex flex-wrap items-center gap-1">
                      <For each={ALL_PROTOCOLS}>
                        {(proto) => (
                          <button
                            type="button"
                            onClick={() => toggleProtocol(proto)}
                            class={`h-7 px-2 rounded text-[10px] font-mono uppercase border cursor-pointer transition-colors ${
                              protocols().includes(proto)
                                ? "bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a] border-[#171717] dark:border-[#ededed]"
                                : "bg-white dark:bg-[#111111] text-[#666666] dark:text-[#a1a1aa] border-[#eaeaea] dark:border-[#262626]"
                            }`}
                          >
                            {proto}
                          </button>
                        )}
                      </For>
                    </div>
                  </div>
                </div>

                <div class="flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed]">
                  <ToggleSwitch
                    compact
                    checked={fallbackNxdomain()}
                    onChange={setFallbackNxdomain}
                    ariaLabel={t("splitDnsFallbackNxdomainLabel")}
                  />
                  <span>{t("splitDnsFallbackNxdomainLabel")}</span>
                </div>
              </div>
            </Show>
          </div>

          {/* Response IP / GeoIP Routing */}
          <div class="rounded-md border border-[#eaeaea] dark:border-[#262626] bg-white/60 dark:bg-[#0a0a0a]/60">
            <button
              type="button"
              onClick={() => setRespIpOpen(!respIpOpen())}
              class="w-full flex items-center justify-between px-2.5 py-1.5 text-[11px] font-medium text-[#52525b] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
            >
              <span class="flex items-center gap-1.5">
                <span class={respIpOpen() ? "i-ri-arrow-down-s-line" : "i-ri-arrow-right-s-line"} />
                <span>{t("splitDnsRespIpToggle")}</span>
              </span>
            </button>
            <Show when={respIpOpen()}>
              <div class="px-2.5 pb-2.5 pt-2 border-t border-[#eaeaea] dark:border-[#262626] space-y-2.5">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpUrlLabel")}
                    </label>
                    <input
                      type="text"
                      value={ripUrl()}
                      placeholder="https://raw.githubusercontent.com/.../china_ip_list.txt"
                      onInput={(e) => setRipUrl(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpFileLabel")}
                    </label>
                    <input
                      type="text"
                      value={ripFile()}
                      placeholder="/etc/crabdns/cn-cidr.txt"
                      onInput={(e) => setRipFile(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpCidrsLabel")}
                    </label>
                    <input
                      type="text"
                      value={ripCidrs()}
                      placeholder="1.0.1.0/24, 223.5.5.0/24"
                      onInput={(e) => setRipCidrs(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpFallbackLabel")}
                    </label>
                    <input
                      type="text"
                      value={ripFallback()}
                      placeholder="@overseas_doh, https://dns.google/dns-query"
                      onInput={(e) => setRipFallback(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpCnameLabel")}
                    </label>
                    <input
                      type="text"
                      value={ripCnames()}
                      placeholder="kunlun.com, alicdn.com"
                      onInput={(e) => setRipCnames(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                  <div>
                    <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                      {t("splitDnsRespIpDelayLabel")}
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={10000}
                      value={ripDelayMs()}
                      placeholder="150"
                      onInput={(e) => setRipDelayMs(e.currentTarget.value)}
                      class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                    />
                  </div>
                </div>
                <div class="flex flex-wrap items-center gap-4 text-xs text-[#171717] dark:text-[#ededed]">
                  <div class="flex items-center gap-2">
                    <ToggleSwitch
                      compact
                      checked={ripInvert()}
                      onChange={setRipInvert}
                      ariaLabel={t("splitDnsRespIpInvertLabel")}
                    />
                    <span>{t("splitDnsRespIpInvertLabel")}</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <ToggleSwitch
                      compact
                      checked={ripOnEmpty()}
                      onChange={setRipOnEmpty}
                      ariaLabel={t("splitDnsRespIpEmptyLabel")}
                    />
                    <span>{t("splitDnsRespIpEmptyLabel")}</span>
                  </div>
                </div>
              </div>
            </Show>
          </div>

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
              const isEnabled = () => rule.enabled ?? true;
              return (
                <div
                  class={`flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3 py-2.5 ${
                    isEnabled() ? "" : "opacity-55"
                  }`}
                >
                  <div class="min-w-0 flex-1 space-y-1">
                    <div class="flex flex-wrap items-center gap-1.5">
                      <ToggleSwitch
                        compact
                        checked={isEnabled()}
                        onChange={() => toggleRuleEnabled(index())}
                        ariaLabel={rule.name ?? ruleTarget(rule)}
                      />
                      <Show when={rule.name}>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-[#171717]/10 dark:bg-[#ededed]/10 text-[#171717] dark:text-[#ededed]">
                          {rule.name}
                        </span>
                      </Show>
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
                      <Show when={hasResponseIpConfig(rule.response_ip)}>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-indigo-500/10 text-indigo-700 dark:text-indigo-400">
                          {t("splitDnsRespIpBadge")}
                        </span>
                      </Show>
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
