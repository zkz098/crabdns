import { createSignal, For, onCleanup, onMount, Show } from "solid-js";

export interface SelectOption {
  value: string;
  label: () => string;
  dotClass?: string;
}

interface SelectMenuProps {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  class?: string;
}

export function SelectMenu(props: SelectMenuProps) {
  const [open, setOpen] = createSignal(false);
  let containerRef: HTMLDivElement | undefined;

  const selectedOption = () =>
    props.options.find((opt) => opt.value === props.value) ?? props.options[0];

  function handleDocClick(e: MouseEvent) {
    if (containerRef && !containerRef.contains(e.target as Node)) {
      setOpen(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      setOpen(false);
    }
  }

  onMount(() => {
    document.addEventListener("mousedown", handleDocClick);
    document.addEventListener("keydown", handleKeyDown);
    onCleanup(() => {
      document.removeEventListener("mousedown", handleDocClick);
      document.removeEventListener("keydown", handleKeyDown);
    });
  });

  return (
    <div
      ref={(el) => {
        containerRef = el;
      }}
      class={`relative ${props.class ?? ""}`}
    >
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open()}
        onClick={() => setOpen((prev) => !prev)}
        class={`w-full h-9 px-3 rounded-lg text-sm font-medium bg-white dark:bg-[#0a0a0a] border text-[#171717] dark:text-[#ededed] flex items-center justify-between gap-2.5 cursor-pointer transition-all duration-150 shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none ${
          open()
            ? "border-[#171717] dark:border-[#ededed] ring-2 ring-black/5 dark:ring-white/10"
            : "border-[#eaeaea] dark:border-[#262626] hover:border-[#d4d4d8] dark:hover:border-[#404040]"
        }`}
      >
        <span class="flex items-center gap-2 truncate">
          <Show when={selectedOption()?.dotClass}>
            <span class={`w-1.5 h-1.5 rounded-full shrink-0 ${selectedOption()?.dotClass}`} />
          </Show>
          <span class="truncate">{selectedOption()?.label()}</span>
        </span>
        <span
          class={`i-ri-arrow-down-s-line text-base text-[#8f8f8f] dark:text-[#71717a] shrink-0 transition-transform duration-200 ${
            open() ? "rotate-180" : "rotate-0"
          }`}
        />
      </button>

      <Show when={open()}>
        <div
          role="listbox"
          class="animate-toast-in absolute right-0 mt-1.5 min-w-full w-44 z-50 rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white/95 dark:bg-[#0a0a0a]/95 backdrop-blur-xl p-1 shadow-lg shadow-black/5 dark:shadow-black/40"
        >
          <For each={props.options}>
            {(opt) => {
              const isSelected = () => opt.value === props.value;
              return (
                <button
                  type="button"
                  role="option"
                  aria-selected={isSelected()}
                  onClick={() => {
                    props.onChange(opt.value);
                    setOpen(false);
                  }}
                  class={`w-full px-2.5 py-1.5 rounded-lg text-xs font-medium flex items-center justify-between gap-2 cursor-pointer border-0 transition-colors ${
                    isSelected()
                      ? "bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#171717] dark:text-white"
                      : "bg-transparent text-[#666666] dark:text-[#a1a1aa] hover:bg-[#fafafa] dark:hover:bg-[#141414] hover:text-[#171717] dark:hover:text-[#ededed]"
                  }`}
                >
                  <span class="flex items-center gap-2 truncate">
                    <Show when={opt.dotClass}>
                      <span class={`w-1.5 h-1.5 rounded-full shrink-0 ${opt.dotClass}`} />
                    </Show>
                    <span class="truncate">{opt.label()}</span>
                  </span>
                  <Show when={isSelected()}>
                    <span class="i-ri-check-line text-sm text-[#171717] dark:text-white shrink-0" />
                  </Show>
                </button>
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
