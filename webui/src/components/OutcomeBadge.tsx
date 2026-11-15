import { t } from "../i18n";
import type { QueryOutcome } from "../types/QueryOutcome";

const BADGE_STYLES: Record<QueryOutcome, { pill: string; dot: string }> = {
  blocked: {
    pill: "bg-rose-500/10 text-rose-600 border-rose-500/20 dark:bg-rose-500/15 dark:text-rose-400 dark:border-rose-500/25",
    dot: "bg-rose-500",
  },
  cached: {
    pill: "bg-amber-500/10 text-amber-700 border-amber-500/20 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/25",
    dot: "bg-amber-500",
  },
  forwarded: {
    pill: "bg-sky-500/10 text-sky-700 border-sky-500/20 dark:bg-sky-500/15 dark:text-sky-400 dark:border-sky-500/25",
    dot: "bg-sky-500",
  },
  rewritten: {
    pill: "bg-violet-500/10 text-violet-700 border-violet-500/20 dark:bg-violet-500/15 dark:text-violet-400 dark:border-violet-500/25",
    dot: "bg-violet-500",
  },
  error: {
    pill: "bg-red-500/10 text-red-700 border-red-500/20 dark:bg-red-500/15 dark:text-red-400 dark:border-red-500/25",
    dot: "bg-red-500",
  },
};

const LABEL_MAP: Record<QueryOutcome, () => string> = {
  blocked: () => t("logsOutcomeBlocked"),
  cached: () => t("logsOutcomeCached"),
  forwarded: () => t("logsOutcomeForwarded"),
  rewritten: () => t("logsOutcomeRewritten"),
  error: () => t("logsOutcomeError"),
};

export function OutcomeBadge(props: { outcome: QueryOutcome }) {
  const style = () => BADGE_STYLES[props.outcome];
  return (
    <span
      class={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium border transition-colors ${style().pill}`}
    >
      <span class={`w-1.5 h-1.5 rounded-full ${style().dot}`} />
      {LABEL_MAP[props.outcome]()}
    </span>
  );
}
