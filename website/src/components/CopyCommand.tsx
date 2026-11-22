import { createSignal } from "solid-js";

interface CopyCommandProps {
  command: string;
  copyLabel: string;
  copiedLabel: string;
}

export function CopyCommand(props: CopyCommandProps) {
  const [copied, setCopied] = createSignal(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(props.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Fallback ignored if clipboard unavailable
    }
  };

  return (
    <div class="flex items-center justify-between gap-3 rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] px-3.5 py-2.5 text-left shadow-sm transition-colors hover:border-[#d4d4d8] dark:hover:border-[#404040]">
      <div class="flex items-center gap-2.5 min-w-0 overflow-x-auto">
        <span class="text-[#8f8f8f] dark:text-[#71717a] font-mono text-xs select-none shrink-0">$</span>
        <code class="font-mono text-xs text-[#171717] dark:text-[#ededed] whitespace-nowrap">
          {props.command}
        </code>
      </div>
      <button
        type="button"
        onClick={handleCopy}
        class="h-7 px-2.5 rounded-lg text-[11px] font-medium shrink-0 bg-[#f4f4f5] dark:bg-[#161616] hover:bg-[#eaeaea] dark:hover:bg-[#222222] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer transition-colors"
      >
        <span class={copied() ? "i-ri-check-line text-emerald-500" : "i-ri-file-copy-line"} />
        <span>{copied() ? props.copiedLabel : props.copyLabel}</span>
      </button>
    </div>
  );
}
