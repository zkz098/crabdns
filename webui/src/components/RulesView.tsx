import { createMemo, createSignal, For, Show } from "solid-js";
import { t, type TranslationKey } from "../i18n";
import type { CreateSubscriptionPayload } from "../types/CreateSubscriptionPayload";
import type { FilterSubscription } from "../types/FilterSubscription";
import type { TestRuleResponse } from "../types/TestRuleResponse";
import { SelectMenu, type SelectOption } from "./SelectMenu";

interface RulesViewProps {
  rulesText: string;
  rulesEnabled: boolean;
  onRulesChange: (val: string) => void;
  onRulesEnabledChange: (enabled: boolean) => void;
  saveMessage: string;
  onSave: () => void;
  subscriptions: FilterSubscription[];
  subMessage: string;
  subIsError: boolean;
  refreshingIds: Record<string, boolean>;
  refreshingAll: boolean;
  addingSub: boolean;
  onAddSubscription: (payload: CreateSubscriptionPayload) => Promise<boolean>;
  onToggleSubscription: (sub: FilterSubscription) => void;
  onRefreshSubscription: (id: string) => void;
  onRefreshAllSubscriptions: () => void;
  onDeleteSubscription: (id: string) => void;
  onTestRule?: (
    domain: string,
    qtype?: string | null,
    clientIp?: string | null,
    clientId?: string | null,
  ) => Promise<TestRuleResponse | null>;
}

const QTYPE_TEST_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("rulesTesterTypeAny") },
  { value: "A", label: () => "A" },
  { value: "AAAA", label: () => "AAAA" },
  { value: "HTTPS", label: () => "HTTPS" },
  { value: "SVCB", label: () => "SVCB" },
  { value: "CNAME", label: () => "CNAME" },
  { value: "TXT", label: () => "TXT" },
  { value: "MX", label: () => "MX" },
  { value: "PTR", label: () => "PTR" },
];

type PresetCategory = "general" | "regional" | "tracking" | "security";

interface PresetCatalogItem {
  name: string;
  url: string;
  category: PresetCategory;
  syntax: "AdGuard" | "Hosts";
  descEn: string;
  descZh: string;
}

const PRESET_CATALOG: PresetCatalogItem[] = [
  {
    name: "AdGuard DNS Filter",
    url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    category: "general",
    syntax: "AdGuard",
    descEn:
      "Comprehensive blocklist merging AdGuard Base, Social, Tracking, and Mobile Ads filters.",
    descZh: "AdGuard 官方综合 DNS 过滤规则，整合基础广告、移动广告与防追踪列表。",
  },
  {
    name: "OISD Blocklist Small",
    url: "https://small.oisd.nl",
    category: "general",
    syntax: "AdGuard",
    descEn:
      "Low false-positive curated blocklist optimized for home networks without breaking sites.",
    descZh: "极低误杀率的精选拦截列表，适合家庭全局开启且几乎不影响正常网页功能。",
  },
  {
    name: "StevenBlack Unified Hosts",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    category: "general",
    syntax: "Hosts",
    descEn: "Classic consolidated hosts file blocking adware and malware domains.",
    descZh: "经典聚合 Hosts 规则源，覆盖主流广告与恶意软件域名。",
  },
  {
    name: "Anti-AD (CN)",
    url: "https://anti-ad.net/easylist.txt",
    category: "regional",
    syntax: "AdGuard",
    descEn: "High-hit-rate Chinese region ad-blocking & TV box telemetry filter list.",
    descZh: "针对中文区网站、移动 App 与智能电视盒优化的高命中率去广告规则集。",
  },
  {
    name: "AdRules DNS List (CN)",
    url: "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    category: "regional",
    syntax: "AdGuard",
    descEn: "Actively maintained Chinese and global DNS filter rules for AdGuardHome / CrabDNS.",
    descZh: "Cats-Team 维护的中文区与全球混合 DNS 广告过滤列表。",
  },
  {
    name: "HaGeZi Multi Light",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    category: "tracking",
    syntax: "AdGuard",
    descEn: "Balanced multi-source blocklist against ads, telemetry, and tracking.",
    descZh: "HaGeZi 轻量级多源聚合列表，平衡拦截广告、遥测与追踪器。",
  },
  {
    name: "AdGuard Tracking Protection",
    url: "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filter_3.txt",
    category: "tracking",
    syntax: "AdGuard",
    descEn: "Blocks analytics, web beacons, and user behavior telemetry collectors.",
    descZh: "专注拦截各类统计分析、埋点信标与用户行为遥测收集域名。",
  },
  {
    name: "URLHaus Malicious Domains",
    url: "https://urlhaus.abuse.ch/downloads/hostfile/",
    category: "security",
    syntax: "Hosts",
    descEn: "abuse.ch URLHaus feed blocking active malware distribution sites.",
    descZh: "由 abuse.ch 维护的活跃恶意软件分发与木马C2域名拦截列表。",
  },
  {
    name: "Phishing Army Extended",
    url: "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    category: "security",
    syntax: "Hosts",
    descEn: "Continuously updated blocklist protecting against phishing and credential harvesting.",
    descZh: "持续更新的防网络钓鱼与欺诈域名安全列表。",
  },
];

const CATEGORY_TABS: Array<{ key: PresetCategory; labelKey: TranslationKey }> = [
  { key: "general", labelKey: "subsCatGeneral" },
  { key: "regional", labelKey: "subsCatRegional" },
  { key: "tracking", labelKey: "subsCatTracking" },
  { key: "security", labelKey: "subsCatSecurity" },
];

function formatTimestamp(iso: string | null): string {
  if (!iso) return t("subsNeverUpdated");
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function RulesView(props: RulesViewProps) {
  const [showAddForm, setShowAddForm] = createSignal(false);
  const [showCatalog, setShowCatalog] = createSignal(false);
  const [catalogCategory, setCatalogCategory] = createSignal<PresetCategory>("general");
  const [newName, setNewName] = createSignal("");
  const [newUrl, setNewUrl] = createSignal("");
  const [newEnabled, setNewEnabled] = createSignal(true);
  const [formError, setFormError] = createSignal("");
  const [testDomain, setTestDomain] = createSignal("");
  const [testQtype, setTestQtype] = createSignal("A");
  const [testClient, setTestClient] = createSignal("");
  const [testResult, setTestResult] = createSignal<TestRuleResponse | null>(null);
  const [testing, setTesting] = createSignal(false);

  const subscribedUrls = createMemo(
    () => new Set(props.subscriptions.map((s) => s.url.trim().toLowerCase())),
  );

  const filteredCatalog = createMemo(() =>
    PRESET_CATALOG.filter((item) => item.category === catalogCategory()),
  );

  async function handleTestRule(e: Event) {
    e.preventDefault();
    const d = testDomain().trim();
    if (!d || !props.onTestRule) return;
    const rawClient = testClient().trim();
    let clientIp: string | null = null;
    let clientId: string | null = null;
    if (rawClient.length > 0) {
      if (rawClient.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(rawClient)) {
        clientIp = rawClient;
      } else {
        clientId = rawClient;
      }
    }
    setTesting(true);
    try {
      const qt = testQtype().trim() || null;
      setTestResult(await props.onTestRule(d, qt, clientIp, clientId));
    } finally {
      setTesting(false);
    }
  }

  const lineCount = () => {
    const text = props.rulesText.trim();
    return text ? text.split("\n").length : 0;
  };

  const enabledSubsCount = () => props.subscriptions.filter((s) => s.enabled).length;

  const totalSubRules = () =>
    props.subscriptions.reduce((acc, s) => (s.enabled ? acc + s.rule_count : acc), 0);

  async function handleCreateSubmit(e: Event) {
    e.preventDefault();
    const name = newName().trim();
    const url = newUrl().trim();
    if (!name || !url) {
      setFormError("Name and URL are required");
      return;
    }
    setFormError("");
    const ok = await props.onAddSubscription({
      name,
      url,
      enabled: newEnabled(),
    });
    if (ok) {
      setNewName("");
      setNewUrl("");
      setNewEnabled(true);
      setShowAddForm(false);
    }
  }

  async function handleSubscribePreset(preset: PresetCatalogItem) {
    await props.onAddSubscription({
      name: preset.name,
      url: preset.url,
      enabled: true,
    });
  }

  return (
    <div class="animate-view-enter space-y-5">
      {/* Rule Tester Card */}
      <Show when={props.onTestRule}>
        <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-3">
          <h2 class="text-sm font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
            {t("rulesTesterTitle")}
          </h2>
          <form onSubmit={handleTestRule} class="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={testDomain()}
              onInput={(e) => setTestDomain(e.currentTarget.value)}
              placeholder={t("rulesTesterPlaceholder")}
              class="flex-1 h-9 bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm font-mono text-[#171717] dark:text-[#ededed] outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
            />
            <SelectMenu
              value={testQtype()}
              options={QTYPE_TEST_OPTIONS}
              onChange={setTestQtype}
              class="sm:w-28"
            />
            <input
              type="text"
              value={testClient()}
              onInput={(e) => setTestClient(e.currentTarget.value)}
              placeholder={t("rulesTesterClientPlaceholder")}
              class="sm:w-52 h-9 bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm font-mono text-[#171717] dark:text-[#ededed] outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
            />
            <button
              type="submit"
              disabled={testing()}
              class="h-9 px-4 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer disabled:opacity-50"
            >
              {t("rulesTesterBtn")}
            </button>
          </form>
          <Show when={testResult()}>
            {(res) => (
              <div class="text-xs font-mono px-3 py-2 rounded-lg bg-[#fafafa] dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] flex flex-wrap items-center gap-2">
                <span class="font-semibold uppercase text-[#171717] dark:text-[#ededed]">
                  {res().action}
                </span>
                <Show when={res().matched_list}>
                  {(listName) => (
                    <span class="px-1.5 py-0.5 rounded text-[11px] font-sans bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-500/20">
                      {t("logsMatchedList")}: {listName()}
                    </span>
                  )}
                </Show>
                <Show
                  when={res().matched_rule}
                  fallback={
                    <span class="text-[#666666] dark:text-[#a1a1aa]">
                      {t("rulesTesterNoMatch")}
                    </span>
                  }
                >
                  <span class="text-[#666666] dark:text-[#a1a1aa]">
                    {t("rulesTesterMatched")}: {res().matched_rule}
                    {res().rewrite ? ` (${res().rewrite})` : ""}
                  </span>
                </Show>
              </div>
            )}
          </Show>
        </div>
      </Show>

      {/* Subscriptions Card */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
                {t("subsTitle")}
              </h2>
              <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] tabular-nums">
                {enabledSubsCount()}/{props.subscriptions.length} {t("subsEnabledCount")} ·{" "}
                {totalSubRules().toLocaleString()} {t("subsRulesSuffix")}
              </span>
            </div>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
              {t("subsSubtitle")}
            </p>
          </div>

          <div class="flex flex-wrap items-center justify-end gap-2 shrink-0">
            <Show when={props.subMessage}>
              <span
                class={`animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                  props.subIsError
                    ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                    : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                }`}
              >
                <span class={props.subIsError ? "i-ri-error-warning-line" : "i-ri-check-line"} />
                {props.subMessage}
              </span>
            </Show>

            <button
              type="button"
              onClick={() => setShowCatalog((prev) => !prev)}
              class={`h-9 px-3 rounded-lg text-xs font-medium border flex items-center gap-1.5 cursor-pointer transition-all duration-150 ${
                showCatalog()
                  ? "bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/30"
                  : "bg-[#fafafa] hover:bg-[#f4f4f5] dark:bg-[#111111] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border-[#eaeaea] dark:border-[#262626]"
              }`}
            >
              <span class="i-ri-compass-3-line text-sm" />
              <span>{t("subsCatalogBtn")}</span>
            </button>

            <Show when={props.subscriptions.length > 0}>
              <button
                type="button"
                disabled={props.refreshingAll}
                onClick={props.onRefreshAllSubscriptions}
                class="h-9 px-3 rounded-lg text-xs font-medium bg-[#fafafa] hover:bg-[#f4f4f5] dark:bg-[#111111] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <span
                  class={`i-ri-refresh-line text-sm ${props.refreshingAll ? "animate-spin" : ""}`}
                />
                <span>{props.refreshingAll ? t("subsRefreshing") : t("subsRefreshAll")}</span>
              </button>
            </Show>

            <button
              type="button"
              onClick={() => setShowAddForm((prev) => !prev)}
              class="h-9 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer border-0 transition-all duration-200 active:scale-[0.97]"
            >
              <span class="i-ri-add-line text-sm" />
              <span>{t("subsAdd")}</span>
            </button>
          </div>
        </div>

        {/* Curated Preset Catalog Drawer */}
        <Show when={showCatalog()}>
          <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-3.5">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div>
                <h3 class="text-xs font-semibold text-[#171717] dark:text-[#ededed]">
                  {t("subsCatalogTitle")}
                </h3>
                <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] mt-0.5">
                  {t("subsCatalogSubtitle")}
                </p>
              </div>
              <div class="flex flex-wrap items-center gap-1">
                <For each={CATEGORY_TABS}>
                  {(cat) => (
                    <button
                      type="button"
                      onClick={() => setCatalogCategory(cat.key)}
                      class={`h-7 px-2.5 rounded-lg text-xs font-medium cursor-pointer border transition-colors ${
                        catalogCategory() === cat.key
                          ? "bg-[#171717] text-white dark:bg-[#ededed] dark:text-[#0a0a0a] border-transparent"
                          : "bg-white dark:bg-[#111111] text-[#666666] dark:text-[#a1a1aa] border-[#eaeaea] dark:border-[#262626] hover:text-[#171717] dark:hover:text-[#ededed]"
                      }`}
                    >
                      {t(cat.labelKey)}
                    </button>
                  )}
                </For>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              <For each={filteredCatalog()}>
                {(preset) => {
                  const isSubscribed = () => subscribedUrls().has(preset.url.trim().toLowerCase());
                  const desc = () => (t("langToggle") === "EN" ? preset.descZh : preset.descEn);
                  return (
                    <div class="rounded-lg border border-[#eaeaea] dark:border-[#222222] bg-white dark:bg-[#0a0a0a] p-3 flex flex-col justify-between gap-2.5">
                      <div class="space-y-1">
                        <div class="flex items-center justify-between gap-2">
                          <span class="text-xs font-semibold text-[#171717] dark:text-[#ededed] truncate">
                            {preset.name}
                          </span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] shrink-0">
                            {preset.syntax}
                          </span>
                        </div>
                        <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
                          {desc()}
                        </p>
                      </div>

                      <div class="flex items-center justify-between gap-2 pt-1 border-t border-[#f4f4f5] dark:border-[#171717]">
                        <span class="font-mono text-[10px] text-[#8f8f8f] dark:text-[#71717a] truncate">
                          {preset.url}
                        </span>
                        <Show
                          when={!isSubscribed()}
                          fallback={
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 shrink-0">
                              <span class="i-ri-check-line text-xs" />
                              {t("subsPresetSubscribed")}
                            </span>
                          }
                        >
                          <button
                            type="button"
                            disabled={props.addingSub}
                            onClick={() => void handleSubscribePreset(preset)}
                            class="h-6 px-2.5 rounded text-[11px] font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer shrink-0 disabled:opacity-50"
                          >
                            {t("subsPresetAddBtn")}
                          </button>
                        </Show>
                      </div>
                    </div>
                  );
                }}
              </For>
            </div>
          </div>
        </Show>

        {/* Inline Add Subscription Form */}
        <Show when={showAddForm()}>
          <form
            onSubmit={handleCreateSubmit}
            class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-3"
          >
            <div class="flex flex-wrap items-center gap-1.5">
              <span class="text-[11px] text-[#666666] dark:text-[#a1a1aa] mr-1">
                {t("subsPresetsLabel")}
              </span>
              <For each={PRESET_CATALOG.slice(0, 5)}>
                {(preset) => (
                  <button
                    type="button"
                    onClick={() => {
                      setNewName(preset.name);
                      setNewUrl(preset.url);
                    }}
                    class="px-2 py-0.5 rounded-md text-[11px] font-medium bg-white dark:bg-[#111111] border border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed] hover:border-[#a1a1aa] dark:hover:border-[#52525b] cursor-pointer transition-colors"
                  >
                    {preset.name}
                  </button>
                )}
              </For>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1">
                  {t("subsNameLabel")}
                </label>
                <input
                  type="text"
                  value={newName()}
                  onInput={(e) => setNewName(e.currentTarget.value)}
                  placeholder={t("subsNamePlaceholder")}
                  class="w-full h-9 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#52525b] outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
                />
              </div>
              <div>
                <label class="block text-xs font-medium text-[#171717] dark:text-[#ededed] mb-1">
                  {t("subsUrlLabel")}
                </label>
                <input
                  type="url"
                  value={newUrl()}
                  onInput={(e) => setNewUrl(e.currentTarget.value)}
                  placeholder={t("subsUrlPlaceholder")}
                  class="w-full h-9 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#52525b] outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
                />
              </div>
            </div>

            <Show when={formError()}>
              <p class="text-xs text-rose-600 dark:text-rose-400">{formError()}</p>
            </Show>

            <div class="flex items-center justify-between pt-1">
              <label class="inline-flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                <input
                  type="checkbox"
                  checked={newEnabled()}
                  onChange={(e) => setNewEnabled(e.currentTarget.checked)}
                  class="rounded border-[#d4d4d8] dark:border-[#404040]"
                />
                <span>{t("rulesEnabledLabel")}</span>
              </label>

              <div class="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowAddForm(false);
                    setFormError("");
                  }}
                  class="h-8 px-3 rounded-lg text-xs font-medium bg-transparent hover:bg-[#eaeaea]/60 dark:hover:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] cursor-pointer"
                >
                  {t("subsCancel")}
                </button>
                <button
                  type="submit"
                  disabled={props.addingSub}
                  class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 border-0 cursor-pointer disabled:opacity-50"
                >
                  <Show when={props.addingSub}>
                    <span class="i-ri-loader-4-line animate-spin text-sm" />
                  </Show>
                  <span>{props.addingSub ? t("subsAdding") : t("subsSubmit")}</span>
                </button>
              </div>
            </div>
          </form>
        </Show>

        {/* Subscriptions List */}
        <Show
          when={props.subscriptions.length > 0}
          fallback={
            <div class="rounded-lg border border-dashed border-[#eaeaea] dark:border-[#262626] p-6 text-center text-xs text-[#8f8f8f] dark:text-[#71717a]">
              {t("subsEmpty")}
            </div>
          }
        >
          <div class="divide-y divide-[#eaeaea] dark:divide-[#262626] rounded-lg border border-[#eaeaea] dark:border-[#262626] overflow-hidden">
            <For each={props.subscriptions}>
              {(sub) => {
                const isRefreshing = () => Boolean(props.refreshingIds[sub.id]);
                return (
                  <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#fafafa]/50 dark:bg-[#050505] hover:bg-[#fafafa] dark:hover:bg-[#0d0d0d] transition-colors">
                    <div class="flex items-start gap-3 min-w-0">
                      <button
                        type="button"
                        role="switch"
                        aria-checked={sub.enabled}
                        onClick={() => props.onToggleSubscription(sub)}
                        class={`mt-0.5 relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          sub.enabled
                            ? "bg-[#171717] dark:bg-[#ededed]"
                            : "bg-[#d4d4d8] dark:bg-[#333333]"
                        }`}
                      >
                        <span
                          class={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white dark:bg-[#000000] shadow-sm transition duration-200 ease-in-out ${
                            sub.enabled ? "translate-x-4" : "translate-x-0"
                          }`}
                        />
                      </button>

                      <div class="min-w-0 space-y-1">
                        <div class="flex flex-wrap items-center gap-2">
                          <span
                            class={`text-sm font-medium truncate ${
                              sub.enabled
                                ? "text-[#171717] dark:text-[#ededed]"
                                : "text-[#8f8f8f] dark:text-[#71717a] line-through"
                            }`}
                          >
                            {sub.name}
                          </span>
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] tabular-nums">
                            {sub.rule_count.toLocaleString()} {t("subsRulesSuffix")}
                          </span>
                          <Show when={!sub.enabled}>
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#f4f4f5] dark:bg-[#171717] text-[#8f8f8f] dark:text-[#71717a]">
                              {t("rulesDisabledLabel")}
                            </span>
                          </Show>
                        </div>

                        <p class="font-mono text-[11px] text-[#666666] dark:text-[#71717a] break-all">
                          {sub.url}
                        </p>

                        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-[#8f8f8f] dark:text-[#71717a]">
                          <span class="inline-flex items-center gap-1">
                            <span class="i-ri-time-line text-xs" />
                            {t("subsLastUpdated")}: {formatTimestamp(sub.last_updated)}
                          </span>
                          <Show when={sub.last_error}>
                            <span class="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
                              <span class="i-ri-error-warning-line text-xs" />
                              {sub.last_error}
                            </span>
                          </Show>
                        </div>
                      </div>
                    </div>

                    <div class="flex items-center justify-end gap-1.5 shrink-0">
                      <button
                        type="button"
                        disabled={isRefreshing()}
                        onClick={() => props.onRefreshSubscription(sub.id)}
                        title={t("subsRefreshOne")}
                        class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1 cursor-pointer transition-colors disabled:opacity-50"
                      >
                        <span
                          class={`i-ri-refresh-line text-sm ${isRefreshing() ? "animate-spin" : ""}`}
                        />
                        <span class="hidden sm:inline">{t("subsRefreshOne")}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => props.onDeleteSubscription(sub.id)}
                        title={t("subsDelete")}
                        class="h-8 w-8 rounded-lg bg-white dark:bg-[#111111] hover:bg-rose-50 dark:hover:bg-rose-950/40 text-[#666666] hover:text-rose-600 dark:text-[#a1a1aa] dark:hover:text-rose-400 border border-[#eaeaea] dark:border-[#262626] flex items-center justify-center cursor-pointer transition-colors"
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

      {/* Custom Rules Card */}
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
                {t("rulesTitle")}
              </h2>
              <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] tabular-nums">
                {lineCount()} {t("rulesLinesSuffix")}
              </span>
              <button
                type="button"
                role="switch"
                aria-checked={props.rulesEnabled}
                onClick={() => props.onRulesEnabledChange(!props.rulesEnabled)}
                class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#111111] text-[#171717] dark:text-[#ededed] cursor-pointer"
              >
                <span
                  class={`inline-block h-2 w-2 rounded-full ${
                    props.rulesEnabled ? "bg-emerald-500" : "bg-[#a1a1aa] dark:bg-[#52525b]"
                  }`}
                />
                <span>{props.rulesEnabled ? t("rulesEnabledLabel") : t("rulesDisabledLabel")}</span>
              </button>
            </div>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
              {t("rulesSubtitle")}
            </p>
          </div>

          <div class="flex items-center justify-end gap-3 shrink-0">
            <Show when={props.saveMessage}>
              <span class="animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                <span class="i-ri-check-line text-sm" />
                {props.saveMessage}
              </span>
            </Show>
            <button
              type="button"
              onClick={props.onSave}
              class="w-full sm:w-auto h-9 px-4 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center justify-center gap-1.5 cursor-pointer border-0 transition-all duration-200 active:scale-[0.97]"
            >
              <span class="i-ri-save-3-line text-sm" />
              <span>{t("rulesApply")}</span>
            </button>
          </div>
        </div>

        <textarea
          value={props.rulesText}
          onInput={(e) => props.onRulesChange(e.currentTarget.value)}
          rows={12}
          spellcheck={false}
          placeholder={
            "||doubleclick.net^\n@@||safe.doubleclick.net^\n||apple.com^$dnstype=HTTPS|SVCB\n||example.com^$denyallow=api.example.com\n||games.test^$client='kid-phone'|192.168.10.0/24\n/^ad-[0-9]+\\.tracker\\.net$/"
          }
          class={`w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3.5 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#52525b] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10 resize-y min-h-48 ${
            props.rulesEnabled ? "" : "opacity-60"
          }`}
        />
      </div>
    </div>
  );
}
