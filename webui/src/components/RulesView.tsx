import { createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { CreateSubscriptionPayload } from "../types/CreateSubscriptionPayload";
import type { FilterSubscription } from "../types/FilterSubscription";
import type { TestRuleResponse } from "../types/TestRuleResponse";

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
  onTestRule?: (domain: string) => Promise<TestRuleResponse | null>;
}

const PRESETS = [
  {
    name: "AdGuard DNS Filter",
    url: "https://adguardteam.github.io/AdGuardDNSFilter/Filters/filter.txt",
  },
  {
    name: "StevenBlack Hosts",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  },
  {
    name: "Anti-AD (CN)",
    url: "https://anti-ad.net/easylist.txt",
  },
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
  const [newName, setNewName] = createSignal("");
  const [newUrl, setNewUrl] = createSignal("");
  const [newEnabled, setNewEnabled] = createSignal(true);
  const [formError, setFormError] = createSignal("");
  const [testDomain, setTestDomain] = createSignal("");
  const [testResult, setTestResult] = createSignal<TestRuleResponse | null>(null);
  const [testing, setTesting] = createSignal(false);

  async function handleTestRule(e: Event) {
    e.preventDefault();
    const d = testDomain().trim();
    if (!d || !props.onTestRule) return;
    setTesting(true);
    try {
      setTestResult(await props.onTestRule(d));
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
              <For each={PRESETS}>
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
          placeholder="||doubleclick.net^&#10;@@||safe.doubleclick.net^&#10;||myrouter.local^$dnsrewrite=192.168.1.1"
          class={`w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3.5 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#52525b] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10 resize-y min-h-48 ${
            props.rulesEnabled ? "" : "opacity-60"
          }`}
        />
      </div>
    </div>
  );
}
