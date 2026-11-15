import { Show } from "solid-js";
import { t } from "../i18n";

interface RulesViewProps {
  rulesText: string;
  onRulesChange: (val: string) => void;
  saveMessage: string;
  onSave: () => void;
}

export function RulesView(props: RulesViewProps) {
  const lineCount = () => {
    const text = props.rulesText.trim();
    return text ? text.split("\n").length : 0;
  };

  return (
    <div class="animate-view-enter rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
              {t("rulesTitle")}
            </h2>
            <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] tabular-nums">
              {lineCount()} {t("rulesLinesSuffix")}
            </span>
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
        rows={16}
        spellcheck={false}
        placeholder="||doubleclick.net^&#10;@@||safe.doubleclick.net^&#10;||myrouter.local^$dnsrewrite=192.168.1.1"
        class="w-full bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg p-3.5 font-mono text-xs leading-relaxed text-[#171717] dark:text-[#ededed] placeholder:text-[#8f8f8f] dark:placeholder:text-[#52525b] outline-none transition-all duration-150 hover:border-[#d4d4d8] dark:hover:border-[#404040] focus:border-[#171717] dark:focus:border-[#ededed] focus:ring-2 focus:ring-black/5 dark:focus:ring-white/10 resize-y min-h-64"
      />
    </div>
  );
}
