import { Show, createSignal } from "solid-js";
import { t } from "../i18n";
import type { UpstreamPolicy } from "../types/UpstreamPolicy";
import type { UpstreamStrategy } from "../types/UpstreamStrategy";

export function emptyUpstreamPolicy(): UpstreamPolicy {
  return {};
}

export function countPolicyOverrides(policy?: UpstreamPolicy | null): number {
  if (!policy) return 0;
  let count = 0;
  if (policy.upstream_strategy != null) count++;
  if (policy.upstream_timeout_ms != null) count++;
  if (policy.dnssec_enabled != null) count++;
  if (policy.ecs_enabled != null) count++;
  if (policy.ecs_custom_ip) count++;
  if (policy.ecs_ipv4_prefix != null) count++;
  if (policy.ecs_ipv6_prefix != null) count++;
  if (policy.dns_rebinding_protection != null) count++;
  if (policy.dns64_enabled != null) count++;
  if (policy.svcb_strip_ech != null) count++;
  if (policy.svcb_strip_hints != null) count++;
  if (policy.cf_cdn_enabled != null) count++;
  return count;
}

export function upstreamPolicyBadges(policy?: UpstreamPolicy | null): string[] {
  if (!policy) return [];
  const badges: string[] = [];
  if (policy.upstream_strategy != null) badges.push(`Strategy:${policy.upstream_strategy}`);
  if (policy.upstream_timeout_ms != null) badges.push(`Timeout:${policy.upstream_timeout_ms}ms`);
  if (policy.dnssec_enabled != null)
    badges.push(`DNSSEC:${policy.dnssec_enabled ? "On" : "Off"}`);
  if (policy.ecs_enabled != null) badges.push(`ECS:${policy.ecs_enabled ? "On" : "Off"}`);
  if (policy.ecs_custom_ip) badges.push(`ECS-IP:${policy.ecs_custom_ip}`);
  if (policy.dns_rebinding_protection != null)
    badges.push(`Rebind:${policy.dns_rebinding_protection ? "On" : "Off"}`);
  if (policy.dns64_enabled != null) badges.push(`DNS64:${policy.dns64_enabled ? "On" : "Off"}`);
  if (policy.svcb_strip_ech != null)
    badges.push(`NoECH:${policy.svcb_strip_ech ? "On" : "Off"}`);
  if (policy.svcb_strip_hints != null)
    badges.push(`NoHints:${policy.svcb_strip_hints ? "On" : "Off"}`);
  if (policy.cf_cdn_enabled != null) badges.push(`CF-CDN:${policy.cf_cdn_enabled ? "On" : "Off"}`);
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
      <select
        value={triValue(value)}
        onChange={(e) => onSet(parseTriValue(e.currentTarget.value))}
        class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 text-xs text-[#171717] dark:text-[#ededed] outline-none"
      >
        <option value="">{t("upstreamPolicyInherit")}</option>
        <option value="true">{t("upstreamPolicyEnable")}</option>
        <option value="false">{t("upstreamPolicyDisable")}</option>
      </select>
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
            <div>
              <label class="block text-[11px] text-[#666666] dark:text-[#a1a1aa] mb-1">
                {t("upstreamPolicyStrategy")}
              </label>
              <select
                value={props.policy.upstream_strategy ?? ""}
                onChange={(e) => {
                  const val = e.currentTarget.value;
                  update({
                    upstream_strategy: val === "" ? null : (val as UpstreamStrategy),
                  });
                }}
                class="w-full h-7 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-md px-2 text-xs text-[#171717] dark:text-[#ededed] outline-none"
              >
                <option value="">{t("upstreamPolicyInherit")}</option>
                <option value="failover">Failover</option>
                <option value="parallel">Parallel</option>
                <option value="least_latency">Least Latency</option>
              </select>
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
                    ecs_ipv4_prefix:
                      parsed !== null && Number.isFinite(parsed) ? parsed : null,
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
                    ecs_ipv6_prefix:
                      parsed !== null && Number.isFinite(parsed) ? parsed : null,
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
