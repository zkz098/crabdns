import { createSignal } from "solid-js";

export type Locale = "en" | "zh-CN";

const STORAGE_KEY = "crabdns_lang";

function detectInitialLocale(): Locale {
  if (typeof window !== "undefined") {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "en" || saved === "zh-CN") {
      return saved;
    }
    if (window.navigator.language.toLowerCase().startsWith("zh")) {
      return "zh-CN";
    }
  }
  return "en";
}

const en = {
  appSubtitle: "Rust DNS Ad-Blocker · Fjall + SolidJS",
  navDashboard: "Overview",
  navLogs: "Query Log",
  navRules: "Filter Rules",
  navSettings: "Settings",
  langToggle: "中文",
  themeLight: "Light",
  themeDark: "Dark",
  statusLive: "Live",
  statusOffline: "Offline",

  statTotalQueries: "Total Queries",
  statBlocked: "Blocked",
  statCacheHits: "Cache Hits",
  statActiveRules: "Active Rules",
  statCacheEntries: "Cache Entries",
  statBlockRate: "Block Rate",
  statHitRate: "Hit Rate",
  queryDistribution: "Query Distribution",
  distForwarded: "Forwarded",
  distCached: "Cached",
  distBlocked: "Blocked",
  distRewritten: "Rewritten",
  distError: "Errors",
  filterBreakdown: "Filter Ruleset",
  filterBlockRules: "Block",
  filterAllowRules: "Allow",
  filterRewriteRules: "Rewrite",
  topBlockedDomains: "Top Blocked Domains",
  topQueriedDomains: "Top Queried Domains",
  topClients: "Top Clients",
  noDataRecorded: "No data recorded yet.",

  logsSearchPlaceholder: "Filter by domain or client IP...",
  logsAllOutcomes: "All Outcomes",
  logsOutcomeBlocked: "Blocked",
  logsOutcomeCached: "Cached",
  logsOutcomeForwarded: "Forwarded",
  logsOutcomeRewritten: "Rewritten",
  logsOutcomeError: "Error",
  logsRefresh: "Refresh",
  logsColTime: "Time",
  logsColClient: "Client",
  logsColDomain: "Domain",
  logsColType: "Type",
  logsColStatus: "Status",
  logsColLatency: "Latency",
  logsEmpty: "No matching query logs found.",
  logsCountSuffix: "events",

  rulesTitle: "Custom Filtering Rules",
  rulesSubtitle:
    "Supports AdGuard syntax (||ads.com^, @@||ok.com^, $important, $dnsrewrite=1.2.3.4) and hosts lines.",
  rulesApply: "Apply & Hot-Reload",
  rulesSaving: "Saving...",
  rulesSaved: "Rules reloaded",
  rulesFailed: "Failed to save",
  rulesNetworkError: "Network error",
  rulesLinesSuffix: "lines",
  rulesEnabledLabel: "Enabled",
  rulesDisabledLabel: "Disabled",

  subsTitle: "Filter Subscriptions",
  subsSubtitle:
    "Subscribe to remote AdGuard or hosts blocklists. Enabled lists are merged with custom rules and auto-updated daily.",
  subsAdd: "Add Subscription",
  subsRefreshAll: "Update All",
  subsRefreshing: "Updating...",
  subsNameLabel: "Subscription Name",
  subsNamePlaceholder: "e.g. AdGuard DNS Filter",
  subsUrlLabel: "Filter List URL",
  subsUrlPlaceholder: "https://example.com/hosts.txt",
  subsPresetsLabel: "Quick Presets:",
  subsCancel: "Cancel",
  subsSubmit: "Add & Fetch",
  subsAdding: "Fetching...",
  subsEmpty: "No filter subscriptions yet. Add a list URL above or pick a preset.",
  subsRulesSuffix: "rules",
  subsLastUpdated: "Updated",
  subsNeverUpdated: "Never updated",
  subsEnabledCount: "enabled",
  subsDelete: "Delete",
  subsRefreshOne: "Update",
  subsUpdatedToast: "Subscriptions updated",

  settingsTitle: "Runtime Configuration",
  settingsSubtitle:
    "Update upstream DNS servers, cache policy, and log retention. Changes take effect immediately and persist across restarts.",
  settingsSave: "Save & Apply",
  settingsSaving: "Applying...",
  settingsSaved: "Config applied & saved",
  settingsUpstreamsLabel: "Upstream DNS Servers (one per line)",
  settingsUpstreamsHint: "Supports udp://, tcp://, tls://, https://",
  settingsCacheSizeLabel: "Cache Capacity (entries)",
  settingsTimeoutLabel: "Upstream Timeout (ms)",
  settingsRetentionLabel: "Log Retention (hours)",
  settingsOptimisticLabel: "Optimistic Cache (serve stale while refreshing)",
  settingsReadonlyTitle: "Startup Bindings (Restart Required to Change)",
  settingsDnsListen: "DNS Listen",
  settingsWebListen: "Web Listen",
  settingsDataDir: "Data Directory",
} as const;

export type TranslationKey = keyof typeof en;

const zhCN: Record<TranslationKey, string> = {
  appSubtitle: "Rust 高性能 DNS 去广告 · Fjall + SolidJS",
  navDashboard: "概览",
  navLogs: "查询日志",
  navRules: "过滤规则",
  navSettings: "配置设置",
  langToggle: "EN",
  themeLight: "日间",
  themeDark: "夜间",
  statusLive: "实时",
  statusOffline: "离线",

  statTotalQueries: "总查询数",
  statBlocked: "已拦截",
  statCacheHits: "缓存命中",
  statActiveRules: "生效规则数",
  statCacheEntries: "缓存条目",
  statBlockRate: "拦截率",
  statHitRate: "命中率",
  queryDistribution: "查询分布",
  distForwarded: "已转发",
  distCached: "缓存命中",
  distBlocked: "已拦截",
  distRewritten: "已重写",
  distError: "错误",
  filterBreakdown: "规则构成",
  filterBlockRules: "拦截",
  filterAllowRules: "放行",
  filterRewriteRules: "重写",
  topBlockedDomains: "拦截域名排行",
  topQueriedDomains: "热门查询域名",
  topClients: "活跃客户端排行",
  noDataRecorded: "暂无记录数据。",

  logsSearchPlaceholder: "按域名或客户端 IP 搜索...",
  logsAllOutcomes: "全部状态",
  logsOutcomeBlocked: "已拦截",
  logsOutcomeCached: "缓存命中",
  logsOutcomeForwarded: "已转发",
  logsOutcomeRewritten: "已重写",
  logsOutcomeError: "错误",
  logsRefresh: "刷新",
  logsColTime: "时间",
  logsColClient: "客户端",
  logsColDomain: "域名",
  logsColType: "类型",
  logsColStatus: "状态",
  logsColLatency: "耗时",
  logsEmpty: "暂无匹配的查询日志。",
  logsCountSuffix: "条记录",

  rulesTitle: "自定义过滤规则",
  rulesSubtitle:
    "支持 AdGuard 语法（||ads.com^、@@||ok.com^、$important、$dnsrewrite=1.2.3.4）及 hosts 格式。",
  rulesApply: "应用并热重载",
  rulesSaving: "保存中...",
  rulesSaved: "规则已重载",
  rulesFailed: "保存失败",
  rulesNetworkError: "网络错误",
  rulesLinesSuffix: "行",
  rulesEnabledLabel: "已启用",
  rulesDisabledLabel: "已禁用",

  subsTitle: "广告过滤规则订阅",
  subsSubtitle:
    "订阅远程 AdGuard 或 hosts 过滤列表。已启用的订阅会与自定义规则合并生效，并每日自动更新。",
  subsAdd: "添加订阅",
  subsRefreshAll: "全部更新",
  subsRefreshing: "更新中...",
  subsNameLabel: "订阅名称",
  subsNamePlaceholder: "例如：AdGuard DNS Filter",
  subsUrlLabel: "规则订阅地址 (URL)",
  subsUrlPlaceholder: "https://example.com/hosts.txt",
  subsPresetsLabel: "常用预设：",
  subsCancel: "取消",
  subsSubmit: "添加并拉取",
  subsAdding: "拉取中...",
  subsEmpty: "暂无规则订阅，点击上方「添加订阅」输入规则 URL 或选择常用预设。",
  subsRulesSuffix: "条规则",
  subsLastUpdated: "最后更新",
  subsNeverUpdated: "从未更新",
  subsEnabledCount: "已启用",
  subsDelete: "删除",
  subsRefreshOne: "更新",
  subsUpdatedToast: "订阅已更新",

  settingsTitle: "运行时配置",
  settingsSubtitle:
    "修改上游 DNS 服务器、缓存策略和日志保留时间。保存后立即热生效并持久化到数据库。",
  settingsSave: "保存并应用",
  settingsSaving: "应用中...",
  settingsSaved: "配置已应用并保存",
  settingsUpstreamsLabel: "上游 DNS 服务器（每行一个）",
  settingsUpstreamsHint: "支持 udp://、tcp://、tls://、https://",
  settingsCacheSizeLabel: "缓存容量（条目数）",
  settingsTimeoutLabel: "上游超时时间（毫秒）",
  settingsRetentionLabel: "日志保留时间（小时）",
  settingsOptimisticLabel: "乐观缓存（过期后先返回旧记录并后台刷新）",
  settingsReadonlyTitle: "启动绑定参数（修改需重启服务）",
  settingsDnsListen: "DNS 监听地址",
  settingsWebListen: "Web 监听地址",
  settingsDataDir: "数据目录",
};

const dictionaries: Record<Locale, Record<TranslationKey, string>> = {
  en,
  "zh-CN": zhCN,
};

const [locale, setLocaleSignal] = createSignal<Locale>(detectInitialLocale());

export function setLocale(next: Locale) {
  setLocaleSignal(next);
  if (typeof window !== "undefined") {
    window.localStorage.setItem(STORAGE_KEY, next);
  }
}

export function toggleLocale() {
  setLocale(locale() === "en" ? "zh-CN" : "en");
}

export function t(key: TranslationKey): string {
  return dictionaries[locale()][key];
}

export { locale };
