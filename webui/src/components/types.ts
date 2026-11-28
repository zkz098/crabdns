export type TabKey =
  | "dashboard"
  | "diagnostics"
  | "logs"
  | "rules"
  | "rewrites"
  | "clients"
  | "settings";

export type UpdateAction = "check" | "apply" | "restart" | null;
