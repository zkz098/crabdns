import { Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { UpstreamPolicy } from "../types/UpstreamPolicy";
import type { UpstreamStrategy } from "../types/UpstreamStrategy";
import { SelectMenu, type SelectOption } from "./SelectMenu";

const TRI_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("upstreamPolicyInherit") },
  { value: "true", label: () => t("upstreamPolicyEnable"), dotClass: "bg-emerald-500" },
  { value: "false", label: () => t("upstreamPolicyDisable"), dotClass: "bg-rose-500" },
];

const STRATEGY_OPTIONS: SelectOption[] = [
  { value: "", label: () => t("upstreamPolicyInherit") },
  { value: "failover", label: "Failover" },
  { value: "parallel", label: "Parallel" },
  { value: "least_latency", label: "Least Latency" },
];

export function emptyUpstreamPolicy(): UpstreamPolicy {
  return {};
}

function isSet<T>(v: T | null | undefined): v is T {
  return v !== null && v !== undefined;
}

export function countPolicyOverrides(policy?: UpstreamPolicy | null): number {
  if (!policy) return 0;
  let count = 0;
  if (isSet(policy.upstream_strategy)) count++;
  if (isSet(policy.upstream_timeout_ms)) count++;
  if (isSet(policy.dnssec_enabled)) count++;
  if (isSet(policy.ecs_enabled)) count++;
  if (policy.ecs_custom_ip) count++;
  if (isSet(policy.ecs_ipv4_prefix)) count++;
  if (isSet(policy.ecs_ipv6_prefix)) count++;
  if (isSet(policy.dns_rebinding_protection)) count++;
  if (isSet(policy.dns64_enabled)) count++;
  if (isSet(policy.svcb_strip_ech)) count++;
  if (isSet(policy.svcb_strip_hints)) count++;
  if (isSet(policy.cf_cdn_enabled)) count++;
  if (isSet(policy.disable_ipv6)) count++;
  return count;
}

export function upstreamPolicyBadges(policy?: UpstreamPolicy | null): string[] {
  if (!policy) return [];
  const badges: string[] = [];
  if (isSet(policy.upstream_strategy)) badges.push(`Strategy:${policy.upstream_strategy}`);
  if (isSet(policy.upstream_timeout_ms)) badges.push(`Timeout:${policy.upstream_timeout_ms}ms`);
  if (isSet(policy.dnssec_enabled)) badges.push(`DNSSEC:${policy.dnssec_enabled ? "On" : "Off"}`);
  if (isSet(policy.ecs_enabled)) badges.push(`ECS:${policy.ecs_enabled ? "On" : "Off"}`);
  if (policy.ecs_custom_ip) badges.push(`ECS-IP:${policy.ecs_custom_ip}`);
  if (isSet(policy.dns_rebinding_protection))
    badges.push(`Rebind:${policy.dns_rebinding_protection ? "On" : "Off"}`);
  if (isSet(policy.dns64_enabled)) badges.push(`DNS64:${policy.dns64_enabled ? "On" : "Off"}`);
  if (isSet(policy.svcb_strip_ech)) badges.push(`NoECH:${policy.svcb_strip_ech ? "On" : "Off"}`);
  if (isSet(policy.svcb_strip_hints))
    badges.push(`NoHints:${policy.svcb_strip_hints ? "On" : "Off"}`);
  if (isSet(policy.cf_cdn_enabled)) badges.push(`CF-CDN:${policy.cf_cdn_enabled ? "On" : "Off"}`);
  if (isSet(policy.disable_ipv6)) badges.push(`NoIPv6:${policy.disable_ipv6 ? "On" : "Off"}`);
  return badges;
}

interface UpstreamPolicyEditorProps {
  policy: UpstreamPolicy;
  onChange: (next: UpstreamPolicy) => void;
}

function triValue(v: boolean | null | undefined): string {
  if (v === true) return "true";
  if (v === false) return "false";
  return "";
}

function parseTriValue(raw: string): boolean | null {
  if (raw === "true") return true;
  if (raw === "false") return false;
  return null;
}

export function UpstreamPolicyEditor(props: UpstreamPolicyEditorProps) {
  const [expanded, setExpanded] = createSignal(countPolicyOverrides(props.policy) > 0);

  const update = (patch: Partial<UpstreamPolicy>) => {
    props.onChange({ ...props.policy, ...patch });
  };

  const triSelect = (
    label: string,
    value: boolean | null | undefined,
    onSet: (v: boolean | null) => void,
  ) => (
    <div>
      <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">{label}</label>
      <SelectMenu
        size="xs"
        value={triValue(value)}
        options={TRI_OPTIONS}
        onChange={(raw) => onSet(parseTriValue(raw))}
        class="w-full"
        triggerClass="dark:bg-[#000000]"
      />
    </div>
  );

  return (
    <div class="rounded-md border border-[#eaeaea] dark:border-[#262626] bg-white/60 dark:bg-[#0a0a0a]/60">
      <button
        type="button"
        onClick={() => setExpanded(!expanded())}
        class="w-full flex items-center justify-between px-2.5 py-1.5 text-[11px] font-medium text-[#52525b] dark:text-[#a1a1aa] hover:text-[#171717] dark:hover:text-[#ededed] cursor-pointer"
      >
        <span class="flex items-center gap-1.5">
          <span class={expanded() ? "i-ri-arrow-down-s-line" : "i-ri-arrow-right-s-line"} />
          <span>{t("upstreamPolicyTitle")}</span>
          <Show when={countPolicyOverrides(props.policy) > 0}>
            <span class="px-1.5 py-0.2 rounded bg-sky-500/10 text-sky-600 dark:text-sky-400 text-[10px]">
              {countPolicyOverrides(props.policy)}
            </span>
          </Show>
        </span>
      </button>

      <Show when={expanded()}>
        <div class="px-2.5 pb-2.5 pt-1 border-t border-[#eaeaea] dark:border-[#262626] space-y-2.5">
          <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {triSelect(t("upstreamPolicyDnssec"), props.policy.dnssec_enabled, (v) =>
              update({ dnssec_enabled: v }),
            )}
            {triSelect(t("upstreamPolicyEcs"), props.policy.ecs_enabled, (v) =>
              update({ ecs_enabled: v }),
            )}
            {triSelect(t("upstreamPolicyRebinding"), props.policy.dns_rebinding_protection, (v) =>
              update({ dns_rebinding_protection: v }),
            )}
            {triSelect(t("upstreamPolicyDns64"), props.policy.dns64_enabled, (v) =>
              update({ dns64_enabled: v }),
            )}
            {triSelect(t("upstreamPolicySvcbEch"), props.policy.svcb_strip_ech, (v) =>
              update({ svcb_strip_ech: v }),
            )}
            {triSelect(t("upstreamPolicySvcbHints"), props.policy.svcb_strip_hints, (v) =>
              update({ svcb_strip_hints: v }),
            )}
            {triSelect(t("upstreamPolicyCfCdn"), props.policy.cf_cdn_enabled, (v) =>
              update({ cf_cdn_enabled: v }),
            )}
            {triSelect(t("upstreamPolicyDisableIpv6"), props.policy.disable_ipv6, (v) =>
              update({ disable_ipv6: v }),
            )}
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyStrategy")}
              </label>
              <SelectMenu
                size="xs"
                value={props.policy.upstream_strategy ?? ""}
                options={STRATEGY_OPTIONS}
                onChange={(val) => {
                  update({
                    upstream_strategy: val === "" ? null : (val as UpstreamStrategy),
                  });
                }}
                class="w-full"
                triggerClass="dark:bg-[#000000]"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyTimeout")}
              </label>
              <input
                type="number"
                min={100}
                max={30000}
                placeholder={t("upstreamPolicyInherit")}
                value={props.policy.upstream_timeout_ms ?? ""}
                onInput={(e) => {
                  const raw = e.currentTarget.value.trim();
                  const parsed = raw === "" ? null : Number(raw);
                  update({
                    upstream_timeout_ms:
                      parsed !== null && Number.isFinite(parsed) && parsed > 0 ? parsed : null,
                  });
                }}
                class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyEcsIp")}
              </label>
              <input
                type="text"
                placeholder={t("upstreamPolicyInherit")}
                value={props.policy.ecs_custom_ip ?? ""}
                onInput={(e) => {
                  const v = e.currentTarget.value.trim();
                  update({ ecs_custom_ip: v === "" ? null : v });
                }}
                class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyEcsV4")}
              </label>
              <input
                type="number"
                min={0}
                max={32}
                placeholder={t("upstreamPolicyInherit")}
                value={props.policy.ecs_ipv4_prefix ?? ""}
                onInput={(e) => {
                  const raw = e.currentTarget.value.trim();
                  const parsed = raw === "" ? null : Number(raw);
                  update({
                    ecs_ipv4_prefix: parsed !== null && Number.isFinite(parsed) ? parsed : null,
                  });
                }}
                class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyEcsV6")}
              </label>
              <input
                type="number"
                min={0}
                max={128}
                placeholder={t("upstreamPolicyInherit")}
                value={props.policy.ecs_ipv6_prefix ?? ""}
                onInput={(e) => {
                  const raw = e.currentTarget.value.trim();
                  const parsed = raw === "" ? null : Number(raw);
                  update({
                    ecs_ipv6_prefix: parsed !== null && Number.isFinite(parsed) ? parsed : null,
                  });
                }}
                class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
              />
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
