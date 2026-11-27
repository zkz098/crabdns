import { createEffect, createSignal, createUniqueId, For, onCleanup, Show } from "solid-js";
import { Portal } from "solid-js/web";

export interface SelectOption<T extends string = string> {
  value: T;
  label: string | (() => string);
  description?: string | (() => string);
  icon?: string;
  dotClass?: string;
  disabled?: boolean;
}

export type SelectSize = "xs" | "sm" | "md";
export type SelectVariant = "surface" | "subtle";

export interface SelectMenuProps<T extends string = string> {
  value: T;
  options: SelectOption<T>[];
  onChange: (value: T) => void;
  size?: SelectSize;
  variant?: SelectVariant;
  align?: "left" | "right";
  placeholder?: string;
  disabled?: boolean;
  id?: string;
  ariaLabel?: string;
  class?: string;
  triggerClass?: string;
  menuClass?: string;
}

interface MenuPosition {
  top: string;
  bottom: string;
  left: string;
  minWidth: string;
  maxWidth: string;
  maxHeight: string;
  placement: "bottom" | "top";
}

function resolveText(val: string | (() => string) | undefined): string {
  if (val === undefined) return "";
  return typeof val === "function" ? val() : val;
}

const SIZE_CLASSES: Record<SelectSize, string> = {
  xs: "h-7 px-2 rounded-md text-xs gap-1.5",
  sm: "h-8 px-2.5 rounded-lg text-xs gap-2",
  md: "h-9 px-3 rounded-lg text-sm gap-2.5",
};

const VARIANT_CLASSES: Record<SelectVariant, string> = {
  surface: "bg-white dark:bg-[#0a0a0a] shadow-[0_1px_2px_rgba(0,0,0,0.03)] dark:shadow-none",
  subtle: "bg-[#fafafa] dark:bg-[#000000]",
};

export function SelectMenu<T extends string = string>(props: SelectMenuProps<T>) {
  const [open, setOpen] = createSignal(false);
  const [activeIndex, setActiveIndex] = createSignal(-1);
  const [position, setPosition] = createSignal<MenuPosition>({
    top: "0px",
    bottom: "auto",
    left: "0px",
    minWidth: "160px",
    maxWidth: "320px",
    maxHeight: "260px",
    placement: "bottom",
  });

  const listboxId = createUniqueId();
  let triggerRef: HTMLButtonElement | undefined;
  let menuRef: HTMLDivElement | undefined;
  let typeAheadBuffer = "";
  let typeAheadTimer: ReturnType<typeof setTimeout> | undefined;

  const size = () => props.size ?? "md";
  const variant = () => props.variant ?? "surface";
  const align = () => props.align ?? "left";

  const optionId = (index: number) => `${listboxId}-opt-${index}`;

  const matchedOption = () => props.options.find((opt) => opt.value === props.value);
  const displayOption = () =>
    matchedOption() ?? (props.placeholder === undefined ? props.options[0] : undefined);

  function firstEnabledIndex(): number {
    return props.options.findIndex((opt) => !opt.disabled);
  }

  function lastEnabledIndex(): number {
    for (let i = props.options.length - 1; i >= 0; i--) {
      if (!props.options[i]?.disabled) return i;
    }
    return -1;
  }

  function findNextEnabledIndex(start: number, step: 1 | -1): number {
    const len = props.options.length;
    if (len === 0) return -1;
    for (let offset = 1; offset <= len; offset++) {
      const idx = (start + step * offset + len) % len;
      if (!props.options[idx]?.disabled) return idx;
    }
    return -1;
  }

  function initialActiveIndex(): number {
    const selectedIdx = props.options.findIndex(
      (opt) => opt.value === props.value && !opt.disabled,
    );
    return selectedIdx >= 0 ? selectedIdx : firstEnabledIndex();
  }

  function scrollOptionIntoView(index: number) {
    if (index < 0) return;
    const el = document.getElementById(optionId(index));
    el?.scrollIntoView({ block: "nearest" });
  }

  function updatePosition(): boolean {
    if (!triggerRef) return false;
    const rect = triggerRef.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    if (
      rect.bottom < 0 ||
      rect.top > vh ||
      rect.right < 0 ||
      rect.left > vw ||
      (rect.width === 0 && rect.height === 0)
    ) {
      return false;
    }

    const gap = 6;
    const margin = 8;
    const spaceBelow = vh - rect.bottom - gap - margin;
    const spaceAbove = rect.top - gap - margin;
    const estimatedHeight = Math.min(260, Math.max(44, props.options.length * 34 + 10));
    const measuredHeight = menuRef
      ? Math.min(260, menuRef.scrollHeight || estimatedHeight)
      : estimatedHeight;

    const placement: "bottom" | "top" =
      spaceBelow < measuredHeight && spaceAbove > spaceBelow ? "top" : "bottom";
    const availableSpace = placement === "bottom" ? spaceBelow : spaceAbove;
    const maxHeight = Math.max(120, Math.min(260, availableSpace));

    const maxWidth = Math.max(120, vw - margin * 2);
    const minWidth = Math.min(rect.width, maxWidth);
    const actualWidth = menuRef
      ? Math.min(maxWidth, Math.max(minWidth, menuRef.offsetWidth))
      : Math.min(maxWidth, Math.max(minWidth, 176));

    const desiredLeft = align() === "right" ? rect.right - actualWidth : rect.left;
    const clampedLeft = Math.max(margin, Math.min(desiredLeft, vw - actualWidth - margin));

    setPosition({
      top: placement === "bottom" ? `${rect.bottom + gap}px` : "auto",
      bottom: placement === "top" ? `${vh - rect.top + gap}px` : "auto",
      left: `${clampedLeft}px`,
      minWidth: `${minWidth}px`,
      maxWidth: `${maxWidth}px`,
      maxHeight: `${maxHeight}px`,
      placement,
    });

    return true;
  }

  function openMenu(targetIdx?: number) {
    if (props.disabled || props.options.length === 0) return;
    const idx = targetIdx !== undefined ? targetIdx : initialActiveIndex();
    setActiveIndex(idx);
    updatePosition();
    setOpen(true);
    requestAnimationFrame(() => {
      updatePosition();
      if (idx >= 0) scrollOptionIntoView(idx);
    });
  }

  function closeMenu(focusTrigger = false) {
    setOpen(false);
    if (focusTrigger) {
      triggerRef?.focus();
    }
  }

  function selectOption(opt: SelectOption<T>) {
    if (opt.disabled) return;
    props.onChange(opt.value);
    closeMenu(true);
  }

  function findTypeAheadIndex(query: string): number {
    const len = props.options.length;
    if (len === 0) return -1;
    const lower = query.toLowerCase();
    const current = activeIndex();
    const start = current >= 0 ? (query.length === 1 ? (current + 1) % len : current) : 0;

    for (let offset = 0; offset < len; offset++) {
      const idx = (start + offset) % len;
      const opt = props.options[idx];
      if (!opt || opt.disabled) continue;
      if (resolveText(opt.label).toLowerCase().startsWith(lower)) {
        return idx;
      }
    }
    return -1;
  }

  function handleTypeAhead(char: string) {
    if (typeAheadTimer) clearTimeout(typeAheadTimer);
    typeAheadBuffer += char;
    typeAheadTimer = setTimeout(() => {
      typeAheadBuffer = "";
    }, 500);

    let matchIdx = findTypeAheadIndex(typeAheadBuffer);
    if (matchIdx < 0 && typeAheadBuffer.length > 1) {
      typeAheadBuffer = char;
      matchIdx = findTypeAheadIndex(typeAheadBuffer);
    }

    if (open()) {
      if (matchIdx >= 0) {
        setActiveIndex(matchIdx);
        scrollOptionIntoView(matchIdx);
      }
    } else {
      openMenu(matchIdx >= 0 ? matchIdx : undefined);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (props.disabled) return;

    if (!open()) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openMenu();
        return;
      }
      if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        handleTypeAhead(e.key);
      }
      return;
    }

    switch (e.key) {
      case "ArrowDown": {
        e.preventDefault();
        const curr = activeIndex();
        const next = curr >= 0 ? findNextEnabledIndex(curr, 1) : firstEnabledIndex();
        if (next >= 0) {
          setActiveIndex(next);
          scrollOptionIntoView(next);
        }
        break;
      }
      case "ArrowUp": {
        e.preventDefault();
        const curr = activeIndex();
        const prev = curr >= 0 ? findNextEnabledIndex(curr, -1) : lastEnabledIndex();
        if (prev >= 0) {
          setActiveIndex(prev);
          scrollOptionIntoView(prev);
        }
        break;
      }
      case "Home": {
        e.preventDefault();
        const first = firstEnabledIndex();
        if (first >= 0) {
          setActiveIndex(first);
          scrollOptionIntoView(first);
        }
        break;
      }
      case "End": {
        e.preventDefault();
        const last = lastEnabledIndex();
        if (last >= 0) {
          setActiveIndex(last);
          scrollOptionIntoView(last);
        }
        break;
      }
      case "Enter":
      case " ": {
        e.preventDefault();
        const idx = activeIndex();
        const opt = idx >= 0 ? props.options[idx] : undefined;
        if (opt && !opt.disabled) {
          selectOption(opt);
        } else {
          closeMenu(true);
        }
        break;
      }
      case "Escape": {
        e.preventDefault();
        e.stopPropagation();
        closeMenu(true);
        break;
      }
      case "Tab": {
        closeMenu(false);
        break;
      }
      default: {
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          handleTypeAhead(e.key);
        }
      }
    }
  }

  createEffect(() => {
    if (!open()) return;

    const handlePointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (triggerRef?.contains(target) || menuRef?.contains(target)) return;
      setOpen(false);
    };

    const handleResize = () => {
      if (!updatePosition()) {
        setOpen(false);
      }
    };

    const handleScroll = (e: Event) => {
      const target = e.target as Node | null;
      if (target && menuRef?.contains(target)) return;
      if (!updatePosition()) {
        setOpen(false);
      }
    };

    document.addEventListener("pointerdown", handlePointerDown, true);
    window.addEventListener("resize", handleResize);
    window.addEventListener("scroll", handleScroll, true);

    onCleanup(() => {
      document.removeEventListener("pointerdown", handlePointerDown, true);
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("scroll", handleScroll, true);
    });
  });

  onCleanup(() => {
    if (typeAheadTimer) clearTimeout(typeAheadTimer);
  });

  return (
    <div class={`relative ${props.class ?? ""}`}>
      <button
        ref={(el) => {
          triggerRef = el;
        }}
        id={props.id}
        type="button"
        disabled={props.disabled}
        aria-haspopup="listbox"
        aria-expanded={open()}
        aria-controls={open() ? listboxId : undefined}
        aria-activedescendant={open() && activeIndex() >= 0 ? optionId(activeIndex()) : undefined}
        aria-label={props.ariaLabel}
        onClick={() => {
          if (open()) {
            closeMenu(false);
          } else {
            openMenu();
          }
        }}
        onKeyDown={handleKeyDown}
        class={`w-full font-medium border text-[#171717] dark:text-[#ededed] flex items-center justify-between outline-none transition-all duration-150 ${SIZE_CLASSES[size()]} ${VARIANT_CLASSES[variant()]} ${
          props.disabled
            ? "opacity-50 cursor-not-allowed border-[#eaeaea] dark:border-[#262626]"
            : open()
              ? "cursor-pointer border-[#171717] dark:border-[#ededed] ring-2 ring-black/5 dark:ring-white/10"
              : "cursor-pointer border-[#eaeaea] dark:border-[#262626] hover:border-[#d4d4d8] dark:hover:border-[#404040] focus-visible:border-[#171717] dark:focus-visible:border-[#ededed] focus-visible:ring-2 focus-visible:ring-black/5 dark:focus-visible:ring-white/10"
        } ${props.triggerClass ?? ""}`}
      >
        <span class="flex items-center gap-2 min-w-0 truncate">
          <Show when={displayOption()?.dotClass}>
            <span class={`w-1.5 h-1.5 rounded-full shrink-0 ${displayOption()?.dotClass}`} />
          </Show>
          <Show when={displayOption()?.icon}>
            {(icon) => (
              <span class={`${icon()} text-sm text-[#666666] dark:text-[#a1a1aa] shrink-0`} />
            )}
          </Show>
          <Show
            when={displayOption()}
            fallback={
              <span class="truncate text-[#8f8f8f] dark:text-[#71717a]">{props.placeholder}</span>
            }
          >
            {(opt) => <span class="truncate">{resolveText(opt().label)}</span>}
          </Show>
        </span>
        <span
          class={`i-ri-arrow-down-s-line ${
            size() === "md" ? "text-base" : "text-sm"
          } text-[#8f8f8f] dark:text-[#71717a] shrink-0 transition-transform duration-200 ${
            open() ? "rotate-180" : "rotate-0"
          }`}
        />
      </button>

      <Show when={open()}>
        <Portal>
          <div
            ref={(el) => {
              menuRef = el;
            }}
            id={listboxId}
            role="listbox"
            aria-label={props.ariaLabel}
            style={{
              position: "fixed",
              top: position().top,
              bottom: position().bottom,
              left: position().left,
              "min-width": position().minWidth,
              "max-width": position().maxWidth,
              "max-height": position().maxHeight,
            }}
            class={`${
              position().placement === "top" ? "animate-dropdown-in-up" : "animate-dropdown-in"
            } z-[60] w-max overflow-y-auto overscroll-contain rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white/95 dark:bg-[#0a0a0a]/95 backdrop-blur-xl p-1 shadow-[0_10px_30px_-8px_rgba(0,0,0,0.12),0_2px_8px_-2px_rgba(0,0,0,0.05)] dark:shadow-[0_12px_32px_-8px_rgba(0,0,0,0.65)] ${
              props.menuClass ?? ""
            }`}
          >
            <For each={props.options}>
              {(opt, index) => {
                const isSelected = () => opt.value === props.value;
                const isActive = () => activeIndex() === index();
                return (
                  <button
                    id={optionId(index())}
                    type="button"
                    role="option"
                    aria-selected={isSelected()}
                    aria-disabled={opt.disabled}
                    disabled={opt.disabled}
                    onMouseDown={(e) => e.preventDefault()}
                    onMouseEnter={() => {
                      if (!opt.disabled) setActiveIndex(index());
                    }}
                    onClick={() => selectOption(opt)}
                    class={`w-full px-2.5 py-1.5 rounded-lg text-xs font-medium flex items-center justify-between gap-3 border-0 text-left transition-colors ${
                      opt.disabled
                        ? "opacity-45 cursor-not-allowed bg-transparent text-[#8f8f8f] dark:text-[#71717a]"
                        : isSelected()
                          ? "cursor-pointer bg-[#f4f4f5] dark:bg-[#1a1a1a] text-[#171717] dark:text-white"
                          : isActive()
                            ? "cursor-pointer bg-[#fafafa] dark:bg-[#141414] text-[#171717] dark:text-[#ededed]"
                            : "cursor-pointer bg-transparent text-[#666666] dark:text-[#a1a1aa] hover:bg-[#fafafa] dark:hover:bg-[#141414] hover:text-[#171717] dark:hover:text-[#ededed]"
                    }`}
                  >
                    <span class="flex items-center gap-2 min-w-0">
                      <Show when={opt.dotClass}>
                        <span class={`w-1.5 h-1.5 rounded-full shrink-0 ${opt.dotClass}`} />
                      </Show>
                      <Show when={opt.icon}>
                        {(icon) => <span class={`${icon()} text-sm shrink-0 opacity-80`} />}
                      </Show>
                      <span class="min-w-0">
                        <span class="block truncate">{resolveText(opt.label)}</span>
                        <Show when={opt.description}>
                          {(desc) => (
                            <span class="block text-[11px] font-normal text-[#8f8f8f] dark:text-[#71717a] truncate">
                              {resolveText(desc())}
                            </span>
                          )}
                        </Show>
                      </span>
                    </span>
                    <Show when={isSelected()}>
                      <span class="i-ri-check-line text-sm text-[#171717] dark:text-white shrink-0" />
                    </Show>
                  </button>
                );
              }}
            </For>
          </div>
        </Portal>
      </Show>
    </div>
  );
}
