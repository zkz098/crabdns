import { createSignal } from "solid-js";

interface CodeBlockProps {
  lang: string;
  content: string;
  copyLabel: string;
  copiedLabel: string;
}

export function CodeBlock(props: CodeBlockProps) {
  const [copied, setCopied] = createSignal(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(props.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore clipboard failure
    }
  };

  return (
    <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] overflow-hidden">
      <div class="px-3.5 py-2 border-b border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] flex items-center justify-between gap-2">
        <span class="text-[11px] font-mono uppercase tracking-wider text-[#8f8f8f] dark:text-[#71717a]">
          {props.lang}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          class="h-6 px-2 rounded-md text-[11px] font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#1a1a1a] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1 cursor-pointer transition-colors"
        >
          <span class={copied() ? "i-ri-check-line text-emerald-500" : "i-ri-file-copy-line"} />
          <span>{copied() ? props.copiedLabel : props.copyLabel}</span>
        </button>
      </div>
      <pre class="p-4 overflow-x-auto text-xs font-mono leading-relaxed text-[#171717] dark:text-[#ededed] m-0">
        <code>{props.content}</code>
      </pre>
    </div>
  );
}
