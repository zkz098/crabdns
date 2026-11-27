import { Show, type JSX } from "solid-js";
import { InfoTooltip } from "../InfoTooltip";

export const INPUT_CLASS =
  "w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10";

export const NUMBER_INPUT_CLASS = `${INPUT_CLASS} tabular-nums`;

export const MONO_INPUT_CLASS =
  "w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10";

export const TEXTAREA_MONO_CLASS =
  "w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10";

interface SettingsSectionHeaderProps {
  icon: string;
  title: string;
  description: string;
}

export function SettingsSectionHeader(props: SettingsSectionHeaderProps) {
  return (
    <div class="flex items-center gap-3 pb-1">
      <div class="w-8 h-8 rounded-lg bg-[#f4f4f5] dark:bg-[#141414] border border-[#eaeaea] dark:border-[#262626] flex items-center justify-center shrink-0">
        <span class={`${props.icon} text-base text-[#171717] dark:text-[#ededed]`} />
      </div>
      <div class="min-w-0">
        <h3 class="text-sm font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
          {props.title}
        </h3>
        <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
          {props.description}
        </p>
      </div>
    </div>
  );
}

interface SettingsCardProps {
  icon?: string;
  title?: string;
  description?: string;
  tooltip?: string;
  tooltipAlign?: "left" | "center" | "right";
  action?: JSX.Element;
  children: JSX.Element;
}

export function SettingsCard(props: SettingsCardProps) {
  return (
    <section class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-5 space-y-4">
      <Show when={props.title || props.action}>
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div class="min-w-0 space-y-0.5">
            <Show when={props.title}>
              <div class="flex items-center gap-1.5">
                <Show when={props.icon}>
                  <span
                    class={`${props.icon} text-sm text-[#666666] dark:text-[#a1a1aa] shrink-0`}
                  />
                </Show>
                <h4 class="text-xs font-semibold text-[#171717] dark:text-[#ededed]">
                  {props.title}
                </h4>
                <Show when={props.tooltip}>
                  {(tip) => <InfoTooltip text={tip()} align={props.tooltipAlign ?? "left"} />}
                </Show>
              </div>
            </Show>
            <Show when={props.description}>
              <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
                {props.description}
              </p>
            </Show>
          </div>
          <Show when={props.action}>
            <div class="flex items-center gap-2 shrink-0">{props.action}</div>
          </Show>
        </div>
      </Show>
      {props.children}
    </section>
  );
}

interface ToggleSwitchProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  ariaLabel?: string;
  compact?: boolean;
}

export function ToggleSwitch(props: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.checked}
      aria-label={props.ariaLabel}
      onClick={() => props.onChange(!props.checked)}
      class={`relative inline-flex shrink-0 cursor-pointer rounded-full border-0 p-0.5 transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#171717]/30 dark:focus-visible:ring-[#ededed]/30 ${
        props.compact ? "h-5 w-9" : "h-6 w-11"
      } ${props.checked ? "bg-[#171717] dark:bg-[#ededed]" : "bg-[#d4d4d8] dark:bg-[#3f3f46]"}`}
    >
      <span
        class={`pointer-events-none inline-block rounded-full bg-white dark:bg-[#0a0a0a] shadow-sm transition-transform duration-200 ease-in-out ${
          props.compact ? "h-4 w-4" : "h-5 w-5"
        } ${props.checked ? (props.compact ? "translate-x-4" : "translate-x-5") : "translate-x-0"}`}
      />
    </button>
  );
}

interface ToggleRowProps {
  label: string;
  description?: string;
  tooltip?: string;
  tooltipAlign?: "left" | "center" | "right";
  checked: boolean;
  onChange: (next: boolean) => void;
  compact?: boolean;
}

export function ToggleRow(props: ToggleRowProps) {
  return (
    <div class="flex items-center justify-between gap-3 rounded-lg border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] px-3.5 py-2.5">
      <div class="min-w-0 space-y-0.5">
        <span class="inline-flex items-center gap-1.5 text-xs font-medium text-[#171717] dark:text-[#ededed] leading-snug">
          <span>{props.label}</span>
          <Show when={props.tooltip}>
            {(tip) => <InfoTooltip text={tip()} align={props.tooltipAlign ?? "left"} />}
          </Show>
        </span>
        <Show when={props.description}>
          <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
            {props.description}
          </p>
        </Show>
      </div>
      <ToggleSwitch
        checked={props.checked}
        onChange={props.onChange}
        ariaLabel={props.label}
        compact={props.compact}
      />
    </div>
  );
}
