import { createMemo, createSignal, For, Show } from "solid-js";
import { t, toggleLocale } from "../i18n";
import type { BlockMode } from "../types/BlockMode";
import type { SetupCompletePayload } from "../types/SetupCompletePayload";
import type { SetupStatusResponse } from "../types/SetupStatusResponse";
import type { UpstreamCapabilities } from "../types/UpstreamCapabilities";
import { PortPrecheckPanel } from "./PortPrecheckPanel";
import { SelectMenu, type SelectOption } from "./SelectMenu";

const BLOCK_MODE_OPTIONS: SelectOption<BlockMode>[] = [
  { value: "zero_ip", label: () => t("settingsBlockZeroIp") },
  { value: "nx_domain", label: () => t("settingsBlockNxDomain") },
  { value: "no_data", label: () => t("settingsBlockNoData") },
];

interface SetupWizardViewProps {
  status: SetupStatusResponse;
  onComplete: (payload: SetupCompletePayload) => Promise<string | null>;
}

const UPSTREAM_PRESETS: Array<{ labelKey: Parameters<typeof t>[0]; urls: string[] }> = [
  { labelKey: "setupWizardPresetAli", urls: ["https://dns.alidns.com/dns-query"] },
  { labelKey: "setupWizardPresetDnspod", urls: ["https://doh.pub/dns-query"] },
  { labelKey: "setupWizardPresetCloudflare", urls: ["https://cloudflare-dns.com/dns-query"] },
  { labelKey: "setupWizardPresetQuad9", urls: ["https://dns.quad9.net/dns-query"] },
];

export function SetupWizardView(props: SetupWizardViewProps) {
  const [step, setStep] = createSignal<1 | 2 | 3>(1);
  const [enableAuth, setEnableAuth] = createSignal(true);
  const [username, setUsername] = createSignal(props.status.web_username || "admin");
  const [password, setPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");

  const [upstreamsText, setUpstreamsText] = createSignal(props.status.upstreams.join("\n"));
  const [blockMode, setBlockMode] = createSignal<BlockMode>(props.status.block_mode);
  const [dnssecEnabled, setDnssecEnabled] = createSignal(props.status.dnssec_enabled);

  const [probing, setProbing] = createSignal(false);
  const [probeResults, setProbeResults] = createSignal<UpstreamCapabilities[]>([]);
  const [error, setError] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);

  const parsedUpstreams = createMemo(() =>
    upstreamsText()
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );

  function validateStep1(): boolean {
    if (!enableAuth()) return true;
    if (!username().trim()) {
      setError("Username cannot be empty");
      return false;
    }
    if (!password().trim()) {
      setError(t("setupWizardPasswordRequired"));
      return false;
    }
    if (password() !== confirmPassword()) {
      setError(t("setupWizardPasswordMismatch"));
      return false;
    }
    return true;
  }

  function validateStep2(): boolean {
    if (parsedUpstreams().length === 0) {
      setError(t("setupWizardUpstreamsRequired"));
      return false;
    }
    return true;
  }

  function handleNext() {
    setError("");
    if (step() === 1) {
      if (!validateStep1()) return;
      setStep(2);
    } else if (step() === 2) {
      if (!validateStep2()) return;
      setStep(3);
    }
  }

  function handleBack() {
    setError("");
    if (step() === 2) setStep(1);
    else if (step() === 3) setStep(2);
  }

  async function handleProbe() {
    const list = parsedUpstreams();
    if (list.length === 0) {
      setError(t("setupWizardUpstreamsRequired"));
      return;
    }
    setError("");
    setProbing(true);
    try {
      const res = await fetch("/api/upstreams/probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ upstreams: list, bootstrap_dns: null, timeout_ms: 3000 }),
      });
      if (res.ok) {
        const data = (await res.json()) as { results?: UpstreamCapabilities[] };
        setProbeResults(data.results ?? []);
      }
    } catch {
      // Ignore probe network errors in wizard
    } finally {
      setProbing(false);
    }
  }

  async function handleFinish(skip = false) {
    setError("");
    if (!skip && (!validateStep1() || !validateStep2())) {
      return;
    }
    setSubmitting(true);
    const payload: SetupCompletePayload = skip
      ? {
          skip: true,
          enable_auth: false,
          username: null,
          password: null,
          upstreams: null,
          block_mode: null,
          dnssec_enabled: null,
        }
      : {
          skip: false,
          enable_auth: enableAuth(),
          username: enableAuth() ? username().trim() : null,
          password: enableAuth() ? password() : null,
          upstreams: parsedUpstreams(),
          block_mode: blockMode(),
          dnssec_enabled: dnssecEnabled(),
        };
    const err = await props.onComplete(payload);
    setSubmitting(false);
    if (err) {
      setError(err);
    }
  }

  return (
    <div class="min-h-screen flex items-center justify-center px-4 py-8 bg-[#fafafa] dark:bg-black text-[#171717] dark:text-[#ededed]">
      <div class="w-full max-w-2xl rounded-2xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-6 sm:p-8 shadow-sm space-y-6">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] flex items-center justify-center shrink-0">
              <span class="i-ri-shield-check-fill text-lg" />
            </div>
            <div>
              <h1 class="text-base font-semibold tracking-tight">CrabDNS</h1>
              <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("setupWizardSubtitle")}</p>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <button
              type="button"
              onClick={toggleLocale}
              class="h-8 px-2.5 rounded-lg text-xs border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
            >
              {t("langToggle")}
            </button>
            <button
              type="button"
              disabled={submitting()}
              onClick={() => void handleFinish(true)}
              class="h-8 px-2.5 rounded-lg text-xs text-[#666666] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer disabled:opacity-50"
            >
              {t("setupWizardSkip")}
            </button>
          </div>
        </div>

        <div class="grid grid-cols-3 gap-2 text-xs">
          {(
            [
              { num: 1 as const, label: t("setupWizardStep1") },
              { num: 2 as const, label: t("setupWizardStep2") },
              { num: 3 as const, label: t("setupWizardStep3") },
            ] as const
          ).map((item) => (
            <div
              class={`rounded-lg border px-3 py-2 flex items-center gap-2 transition-colors ${
                step() === item.num
                  ? "border-[#171717] dark:border-[#ededed] bg-[#fafafa] dark:bg-[#141414] font-medium text-[#171717] dark:text-[#ededed]"
                  : step() > item.num
                    ? "border-[#eaeaea] dark:border-[#262626] text-[#171717] dark:text-[#ededed]"
                    : "border-[#eaeaea] dark:border-[#262626] text-[#8f8f8f] dark:text-[#71717a]"
              }`}
            >
              <span
                class={`w-5 h-5 rounded-full text-[11px] flex items-center justify-center shrink-0 ${
                  step() >= item.num
                    ? "bg-[#171717] dark:bg-[#ededed] text-white dark:text-[#0a0a0a]"
                    : "bg-[#eaeaea] dark:bg-[#262626] text-[#666666] dark:text-[#a1a1aa]"
                }`}
              >
                {item.num}
              </span>
              <span class="truncate">{item.label}</span>
            </div>
          ))}
        </div>

        <Show when={step() === 1}>
          <div class="space-y-4">
            <label class="flex items-center gap-2.5 text-sm font-medium cursor-pointer select-none">
              <input
                type="checkbox"
                checked={enableAuth()}
                onChange={(e) => setEnableAuth(e.currentTarget.checked)}
                class="w-4 h-4 accent-[#171717] dark:accent-[#ededed] cursor-pointer"
              />
              <span>{t("setupWizardAuthEnableLabel")}</span>
            </label>

            <Show
              when={enableAuth()}
              fallback={
                <div class="rounded-lg border border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300 px-3.5 py-2.5 text-xs">
                  {t("setupWizardAuthDisabledHint")}
                </div>
              }
            >
              <div class="space-y-3">
                <div>
                  <label class="block text-xs font-medium mb-1.5">{t("authUsernameLabel")}</label>
                  <input
                    type="text"
                    autocomplete="username"
                    value={username()}
                    onInput={(e) => setUsername(e.currentTarget.value)}
                    class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
                  />
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label class="block text-xs font-medium mb-1.5">{t("authPasswordLabel")}</label>
                    <input
                      type="password"
                      autocomplete="new-password"
                      value={password()}
                      onInput={(e) => setPassword(e.currentTarget.value)}
                      class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
                    />
                  </div>
                  <div>
                    <label class="block text-xs font-medium mb-1.5">
                      {t("setupWizardPasswordConfirmLabel")}
                    </label>
                    <input
                      type="password"
                      autocomplete="new-password"
                      value={confirmPassword()}
                      onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                      class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
                    />
                  </div>
                </div>
              </div>
            </Show>
          </div>
        </Show>

        <Show when={step() === 2}>
          <div class="space-y-4">
            <div class="space-y-1.5">
              <div class="text-xs text-[#666666] dark:text-[#a1a1aa]">
                {t("setupWizardPresetsLabel")}
              </div>
              <div class="flex flex-wrap gap-2">
                <For each={UPSTREAM_PRESETS}>
                  {(preset) => (
                    <button
                      type="button"
                      onClick={() => {
                        setUpstreamsText(preset.urls.join("\n"));
                        setProbeResults([]);
                      }}
                      class="px-2.5 py-1 rounded-lg text-xs border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer"
                    >
                      {t(preset.labelKey)}
                    </button>
                  )}
                </For>
              </div>
            </div>

            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-medium">{t("setupWizardUpstreamsLabel")}</label>
                <button
                  type="button"
                  disabled={probing()}
                  onClick={() => void handleProbe()}
                  class="text-xs px-2.5 py-1 rounded-md border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer disabled:opacity-50"
                >
                  {probing() ? t("setupWizardProbing") : t("setupWizardProbeBtn")}
                </button>
              </div>
              <textarea
                rows={4}
                value={upstreamsText()}
                onInput={(e) => setUpstreamsText(e.currentTarget.value)}
                class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 font-mono text-xs outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
              />
              <Show when={probeResults().length > 0}>
                <div class="mt-2 space-y-1">
                  <For each={probeResults()}>
                    {(item) => (
                      <div class="flex items-center justify-between text-[11px] px-2.5 py-1.5 rounded border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505]">
                        <span class="font-mono truncate">{item.input}</span>
                        <span
                          class={
                            item.reachable
                              ? "text-emerald-600 dark:text-emerald-400 shrink-0 ml-2"
                              : "text-rose-600 dark:text-rose-400 shrink-0 ml-2"
                          }
                        >
                          {item.reachable
                            ? `${item.latency_ms ?? 0} ms`
                            : (item.error ?? "Unreachable")}
                        </span>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2 flex items-center justify-between gap-2">
                <span class="text-xs font-medium">{t("settingsBlockModeLabel")}</span>
                <SelectMenu
                  size="sm"
                  align="right"
                  value={blockMode()}
                  options={BLOCK_MODE_OPTIONS}
                  onChange={setBlockMode}
                  class="w-48 shrink-0"
                />
              </div>
              <label class="flex items-center gap-2.5 text-xs font-medium rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3 py-2.5 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={dnssecEnabled()}
                  onChange={(e) => setDnssecEnabled(e.currentTarget.checked)}
                  class="w-4 h-4 accent-[#171717] dark:accent-[#ededed] cursor-pointer"
                />
                <span>{t("setupWizardDnssecLabel")}</span>
              </label>
            </div>
          </div>
        </Show>

        <Show when={step() === 3}>
          <div class="space-y-4">
            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-2.5 text-xs">
              <div class="font-medium text-[#171717] dark:text-[#ededed]">
                {t("setupWizardSummaryTitle")}
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div>
                  <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                    {t("setupWizardSummaryAuth")}
                  </span>
                  <span class="font-medium">
                    {enableAuth()
                      ? `${t("setupWizardSummaryAuthOn")} (${username().trim()})`
                      : t("setupWizardSummaryAuthOff")}
                  </span>
                </div>
                <div>
                  <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                    {t("setupWizardSummaryUpstreams")}
                  </span>
                  <span class="font-mono">{parsedUpstreams().length}</span>
                </div>
                <div>
                  <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                    {t("setupWizardSummaryBlocking")}
                  </span>
                  <span class="font-mono">{blockMode()}</span>
                </div>
              </div>
            </div>

            <div class="rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-2 text-xs">
              <div class="font-medium text-[#171717] dark:text-[#ededed]">
                {t("setupWizardListenTitle")}
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                    {t("setupWizardListenDns")}
                  </span>
                  <span class="font-mono">{props.status.listen_dns}</span>
                </div>
                <div>
                  <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                    {t("setupWizardListenWeb")}
                  </span>
                  <span class="font-mono">{props.status.listen_web}</span>
                </div>
                <Show when={props.status.tls_configured && props.status.listen_web_tls}>
                  <div>
                    <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                      {t("settingsWebTlsListen")}
                    </span>
                    <span class="font-mono">{props.status.listen_web_tls}</span>
                  </div>
                </Show>
                <Show when={props.status.tls_configured && props.status.listen_dot}>
                  <div>
                    <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                      {t("settingsDotListen")}
                    </span>
                    <span class="font-mono">{props.status.listen_dot}</span>
                  </div>
                </Show>
                <Show when={props.status.tls_configured && props.status.listen_doq}>
                  <div>
                    <span class="text-[#8f8f8f] dark:text-[#71717a] block">
                      {t("settingsDoqListen")}
                    </span>
                    <span class="font-mono">{props.status.listen_doq}</span>
                  </div>
                </Show>
              </div>
            </div>

            <PortPrecheckPanel
              listenDns={props.status.listen_dns}
              listenWeb={props.status.listen_web}
              listenWebTls={props.status.listen_web_tls}
              listenDot={props.status.listen_dot}
              listenDoq={props.status.listen_doq}
            />
          </div>
        </Show>

        <Show when={error()}>
          <div class="rounded-lg border border-rose-500/20 bg-rose-500/10 text-rose-600 dark:text-rose-400 px-3 py-2 text-xs flex items-center gap-1.5">
            <span class="i-ri-error-warning-line shrink-0" />
            <span>{error()}</span>
          </div>
        </Show>

        <div class="flex items-center justify-between pt-2 border-t border-[#eaeaea] dark:border-[#262626]">
          <div>
            <Show when={step() > 1}>
              <button
                type="button"
                disabled={submitting()}
                onClick={handleBack}
                class="h-9 px-4 rounded-lg text-sm font-medium border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] cursor-pointer disabled:opacity-50"
              >
                {t("setupWizardBack")}
              </button>
            </Show>
          </div>
          <div>
            <Show
              when={step() === 3}
              fallback={
                <button
                  type="button"
                  onClick={handleNext}
                  class="h-9 px-4 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0 transition-all active:scale-[0.98]"
                >
                  {t("setupWizardNext")}
                </button>
              }
            >
              <button
                type="button"
                disabled={submitting()}
                onClick={() => void handleFinish(false)}
                class="h-9 px-4 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0 transition-all active:scale-[0.98] disabled:opacity-50"
              >
                {submitting() ? t("setupWizardFinishing") : t("setupWizardFinish")}
              </button>
            </Show>
          </div>
        </div>
      </div>
    </div>
  );
}
