import { createMemo, createSignal, For, Show } from "solid-js";
import { t } from "../i18n";
import type { DnsRewriteEntry } from "../types/DnsRewriteEntry";
import type { DnsRewriteKind } from "../types/DnsRewriteKind";
import type { DnsRewritePayload } from "../types/DnsRewritePayload";
import { SelectMenu, type SelectOption } from "./SelectMenu";

interface RewritesViewProps {
  rewrites: DnsRewriteEntry[];
  message: string;
  isError: boolean;
  saving: boolean;
  onCreate: (payload: DnsRewritePayload) => Promise<boolean>;
  onUpdate: (id: string, payload: DnsRewritePayload) => Promise<boolean>;
  onDelete: (id: string) => Promise<void>;
  onRefresh: () => void;
}

const KIND_OPTIONS: SelectOption[] = [
  { value: "auto", label: () => t("rewritesKindAuto") },
  { value: "a", label: () => "A (IPv4)" },
  { value: "aaaa", label: () => "AAAA (IPv6)" },
  { value: "cname", label: () => "CNAME" },
  { value: "txt", label: () => "TXT" },
];

function kindBadgeLabel(kind: DnsRewriteKind): string {
  if (kind === "auto") return "AUTO";
  return kind.toUpperCase();
}

export function RewritesView(props: RewritesViewProps) {
  const [formOpen, setFormOpen] = createSignal(false);
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [domain, setDomain] = createSignal("");
  const [kind, setKind] = createSignal<DnsRewriteKind>("auto");
  const [answer, setAnswer] = createSignal("");
  const [comment, setComment] = createSignal("");
  const [enabled, setEnabled] = createSignal(true);
  const [search, setSearch] = createSignal("");

  const filteredRewrites = createMemo(() => {
    const q = search().trim().toLowerCase();
    if (!q) return props.rewrites;
    return props.rewrites.filter(
      (r) =>
        r.domain.toLowerCase().includes(q) ||
        r.answer.toLowerCase().includes(q) ||
        r.comment.toLowerCase().includes(q) ||
        r.kind.toLowerCase().includes(q),
    );
  });

  const enabledCount = createMemo(() => props.rewrites.filter((r) => r.enabled).length);

  function openNew() {
    setEditingId(null);
    setDomain("");
    setKind("auto");
    setAnswer("");
    setComment("");
    setEnabled(true);
    setFormOpen(true);
  }

  function openEdit(item: DnsRewriteEntry) {
    setEditingId(item.id);
    setDomain(item.domain);
    setKind(item.kind);
    setAnswer(item.answer);
    setComment(item.comment);
    setEnabled(item.enabled);
    setFormOpen(true);
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    const payload: DnsRewritePayload = {
      domain: domain().trim(),
      kind: kind(),
      answer: answer().trim(),
      enabled: enabled(),
      comment: comment().trim(),
    };
    const editId = editingId();
    const ok = editId ? await props.onUpdate(editId, payload) : await props.onCreate(payload);
    if (ok) {
      setFormOpen(false);
    }
  }

  function handleToggle(item: DnsRewriteEntry) {
    void props.onUpdate(item.id, {
      domain: item.domain,
      kind: item.kind,
      answer: item.answer,
      enabled: !item.enabled,
      comment: item.comment,
    });
  }

  return (
    <div class="animate-view-enter space-y-5">
      <div class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-4 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <h2 class="text-base font-semibold tracking-tight text-[#171717] dark:text-[#ededed]">
                {t("rewritesTitle")}
              </h2>
              <span class="px-2 py-0.5 rounded-full text-[11px] font-mono bg-[#f4f4f5] dark:bg-[#171717] text-[#666666] dark:text-[#a1a1aa] border border-[#eaeaea] dark:border-[#262626] tabular-nums">
                {enabledCount()}/{props.rewrites.length} {t("subsEnabledCount")}
              </span>
            </div>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa] leading-relaxed">
              {t("rewritesSubtitle")}
            </p>
          </div>

          <div class="flex flex-wrap items-center justify-end gap-2 shrink-0">
            <Show when={props.message}>
              <span
                class={`animate-toast-in inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                  props.isError
                    ? "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                    : "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20"
                }`}
              >
                <span class={props.isError ? "i-ri-error-warning-line" : "i-ri-check-line"} />
                {props.message}
              </span>
            </Show>

            <button
              type="button"
              onClick={() => props.onRefresh()}
              class="h-9 px-3 rounded-lg text-xs font-medium bg-[#fafafa] hover:bg-[#f4f4f5] dark:bg-[#111111] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] flex items-center gap-1.5 cursor-pointer"
            >
              <span class="i-ri-refresh-line text-sm" />
              <span>{t("logsRefresh")}</span>
            </button>

            <button
              type="button"
              onClick={openNew}
              class="h-9 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] flex items-center gap-1.5 cursor-pointer border-0"
            >
              <span class="i-ri-add-line text-sm" />
              <span>{t("rewritesAddBtn")}</span>
            </button>
          </div>
        </div>

        {/* Add / Edit Form */}
        <Show when={formOpen()}>
          <form
            onSubmit={handleSubmit}
            class="rounded-xl border border-[#eaeaea] dark:border-[#262626] bg-[#fafafa] dark:bg-[#050505] p-4 space-y-3.5"
          >
            <h3 class="text-sm font-medium text-[#171717] dark:text-[#ededed]">
              {editingId() ? t("rewritesEditTitle") : t("rewritesAddBtn")}
            </h3>
            <div class="grid grid-cols-1 sm:grid-cols-12 gap-3">
              <div class="sm:col-span-5">
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("rewritesDomainLabel")}
                </label>
                <input
                  type="text"
                  required
                  value={domain()}
                  onInput={(e) => setDomain(e.currentTarget.value)}
                  placeholder="nas.local / *.home.arpa"
                  class="w-full h-9 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div class="sm:col-span-2">
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("rewritesTypeLabel")}
                </label>
                <SelectMenu
                  value={kind()}
                  options={KIND_OPTIONS}
                  onChange={(v) => setKind(v as DnsRewriteKind)}
                  class="w-full"
                />
              </div>
              <div class="sm:col-span-5">
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("rewritesAnswerLabel")}
                </label>
                <input
                  type="text"
                  required
                  value={answer()}
                  onInput={(e) => setAnswer(e.currentTarget.value)}
                  placeholder="192.168.1.50 / fd00::50 / target.local"
                  class="w-full h-9 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 font-mono text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
              <div class="sm:col-span-8">
                <label class="block text-xs text-[#666666] dark:text-[#a1a1aa] mb-1">
                  {t("rewritesCommentLabel")}
                </label>
                <input
                  type="text"
                  value={comment()}
                  onInput={(e) => setComment(e.currentTarget.value)}
                  placeholder={t("rewritesCommentPlaceholder")}
                  class="w-full h-9 bg-white dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-xs text-[#171717] dark:text-[#ededed] outline-none"
                />
              </div>
              <div class="sm:col-span-4 flex items-center justify-between sm:justify-end gap-3">
                <label class="inline-flex items-center gap-2 text-xs text-[#171717] dark:text-[#ededed] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enabled()}
                    onChange={(e) => setEnabled(e.currentTarget.checked)}
                    class="rounded border-[#d4d4d8] dark:border-[#404040]"
                  />
                  <span>{t("rulesEnabledLabel")}</span>
                </label>
                <div class="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setFormOpen(false)}
                    class="h-8 px-3 rounded-lg text-xs font-medium bg-white dark:bg-[#0a0a0a] border border-[#eaeaea] dark:border-[#262626] text-[#666666] dark:text-[#a1a1aa] cursor-pointer"
                  >
                    {t("clientsCancelBtn")}
                  </button>
                  <button
                    type="submit"
                    disabled={props.saving}
                    class="h-8 px-3.5 rounded-lg text-xs font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] border-0 cursor-pointer disabled:opacity-50"
                  >
                    {t("clientsSaveBtn")}
                  </button>
                </div>
              </div>
            </div>
          </form>
        </Show>

        {/* Search */}
        <Show when={props.rewrites.length > 0}>
          <div class="relative">
            <span class="i-ri-search-line absolute left-3 top-1/2 -translate-y-1/2 text-[#8f8f8f] text-sm pointer-events-none" />
            <input
              type="text"
              value={search()}
              onInput={(e) => setSearch(e.currentTarget.value)}
              placeholder={t("rewritesSearchPlaceholder")}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg pl-9 pr-3 text-xs text-[#171717] dark:text-[#ededed] outline-none"
            />
          </div>
        </Show>

        {/* List */}
        <Show
          when={filteredRewrites().length > 0}
          fallback={
            <div class="rounded-lg border border-dashed border-[#eaeaea] dark:border-[#262626] p-8 text-center text-xs text-[#8f8f8f] dark:text-[#71717a]">
              {t("rewritesEmpty")}
            </div>
          }
        >
          <div class="divide-y divide-[#eaeaea] dark:divide-[#262626] rounded-lg border border-[#eaeaea] dark:border-[#262626] overflow-hidden">
            <For each={filteredRewrites()}>
              {(item) => (
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-[#fafafa]/50 dark:bg-[#050505] hover:bg-[#fafafa] dark:hover:bg-[#0d0d0d] transition-colors">
                  <div class="flex items-start gap-3 min-w-0">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={item.enabled}
                      onClick={() => handleToggle(item)}
                      class={`mt-0.5 relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        item.enabled
                          ? "bg-[#171717] dark:bg-[#ededed]"
                          : "bg-[#d4d4d8] dark:bg-[#333333]"
                      }`}
                    >
                      <span
                        class={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white dark:bg-[#000000] shadow-sm transition duration-200 ease-in-out ${
                          item.enabled ? "translate-x-4" : "translate-x-0"
                        }`}
                      />
                    </button>

                    <div class="min-w-0 space-y-1">
                      <div class="flex flex-wrap items-center gap-2">
                        <span
                          class={`font-mono text-xs font-medium ${
                            item.enabled
                              ? "text-[#171717] dark:text-[#ededed]"
                              : "text-[#8f8f8f] dark:text-[#71717a] line-through"
                          }`}
                        >
                          {item.domain}
                        </span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-violet-500/10 text-violet-700 dark:text-violet-400 border border-violet-500/20">
                          {kindBadgeLabel(item.kind)}
                        </span>
                        <span class="i-ri-arrow-right-line text-xs text-[#8f8f8f]" />
                        <span class="font-mono text-xs text-[#171717] dark:text-[#ededed] break-all">
                          {item.answer}
                        </span>
                      </div>
                      <Show when={item.comment}>
                        <p class="text-[11px] text-[#666666] dark:text-[#a1a1aa]">{item.comment}</p>
                      </Show>
                    </div>
                  </div>

                  <div class="flex items-center justify-end gap-1.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => openEdit(item)}
                      class="h-8 px-2.5 rounded-lg text-xs font-medium bg-white dark:bg-[#111111] hover:bg-[#f4f4f5] dark:hover:bg-[#171717] text-[#171717] dark:text-[#ededed] border border-[#eaeaea] dark:border-[#262626] cursor-pointer"
                    >
                      {t("clientsEditBtn")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void props.onDelete(item.id)}
                      title={t("clientsDeleteBtn")}
                      class="h-8 w-8 rounded-lg bg-white dark:bg-[#111111] hover:bg-rose-50 dark:hover:bg-rose-950/40 text-[#666666] hover:text-rose-600 dark:text-[#a1a1aa] dark:hover:text-rose-400 border border-[#eaeaea] dark:border-[#262626] flex items-center justify-center cursor-pointer"
                    >
                      <span class="i-ri-delete-bin-line text-sm" />
                    </button>
                  </div>
                </div>
              )}
            </For>
          </div>
        </Show>
      </div>
    </div>
  );
}
