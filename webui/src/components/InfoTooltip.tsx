import { Show, createSignal, createUniqueId } from "solid-js";

interface InfoTooltipProps {
  text: string;
  label?: string;
  align?: "left" | "center" | "right";
}

export function InfoTooltip(props: InfoTooltipProps) {
  const [open, setOpen] = createSignal(false);
  const tooltipId = createUniqueId();

  const alignClass = () => {
    switch (props.align) {
      case "left":
        return "left-0";
      case "right":
        return "right-0";
      default:
        return "left-0 sm:left-1/2 sm:-translate-x-1/2";
    }
  };

  return (
    <span class="relative inline-flex items-center align-middle">
      <button
        type="button"
        aria-label={props.label ?? "More info"}
        aria-expanded={open()}
        aria-describedby={open() ? tooltipId : undefined}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen((prev) => !prev);
        }}
        class="inline-flex items-center justify-center w-4 h-4 rounded-full text-[#8f8f8f] hover:text-[#171717] dark:text-[#71717a] dark:hover:text-[#ededed] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#171717]/30 dark:focus-visible:ring-[#ededed]/30 bg-transparent border-0 p-0 cursor-help transition-colors"
      >
        <span class="i-ri-information-line text-[13px]" />
      </button>

      <Show when={open()}>
        <span
          id={tooltipId}
          role="tooltip"
          class={`animate-toast-in absolute bottom-full mb-2 z-50 w-64 max-w-[min(18rem,calc(100vw-3rem))] rounded-lg px-3 py-2 text-[11px] leading-relaxed font-normal normal-case tracking-normal text-left whitespace-normal shadow-lg pointer-events-none bg-[#171717] text-[#fafafa] border border-[#262626] dark:bg-[#1f1f23] dark:text-[#ededed] dark:border-[#3f3f46] ${alignClass()}`}
        >
          {props.text}
        </span>
      </Show>
    </span>
  );
}
