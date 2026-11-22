import type { Locale } from "../i18n/translations";

export interface DocSection {
  id: string;
  heading: string;
  body: string[];
  code?: {
    lang: string;
    content: string;
  };
  table?: {
    headers: string[];
    rows: string[][];
  };
}

export interface DocPage {
  slug: string;
  title: string;
  description: string;
  icon: string;
  sections: DocSection[];
}

export const DOC_SLUGS = [
  "getting-started",
  "install-script",
  "configuration",
  "filtering",
  "protocols",
  "benchmarks",
] as const;

export type DocSlug = (typeof DOC_SLUGS)[number];

export function docHref(lang: Locale, slug: string): string {
  const prefix = lang === "zh" ? "/zh/docs" : "/docs";
  return slug === "getting-started" ? `${prefix}/` : `${prefix}/${slug}/`;
}

export const docsContent: Record<Locale, DocPage[]> = {
  en: [
    {
      slug: "getting-started",
      title: "Getting Started",
      description: "Build, run, and update CrabDNS from source or release binaries.",
      icon: "i-ri-rocket-line",
      sections: [
        {
          id: "one-line-install",
          heading: "One-Line Install (Linux & OpenWrt)",
          body: [
            "For Linux (systemd) and OpenWrt (procd) on x86_64 or aarch64, use the official scripts/install.sh deployment script. It downloads the latest release archive, verifies its SHA-256 checksum, installs /usr/bin/crabdns, creates /etc/crabdns/config.toml, and enables the system service.",
          ],
          code: {
            lang: "bash",
            content: `curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh`,
          },
        },
        {
          id: "build-and-run",
          heading: "Build & Run from Source",
          body: [
            "CrabDNS embeds its SolidJS + UnoCSS WebUI directly into the Rust binary via rust-embed. Build the frontend assets once before compiling or running the server.",
            "By default, CrabDNS listens for DNS queries on 0.0.0.0:5353 and serves the WebUI + DoH endpoint on 127.0.0.1:3000.",
          ],
          code: {
            lang: "bash",
            content: `# 1. Build Web UI assets
cd webui && pnpm install && pnpm build && cd ..

# 2. Run CrabDNS
cargo run -p crabdns-server`,
          },
        },
        {
          id: "cli-flags",
          heading: "CLI Flags",
          body: [
            "You can override listener addresses or pass a custom TOML configuration file directly from the command line.",
          ],
          table: {
            headers: ["Flag", "Description", "Example"],
            rows: [
              ["-c, --config <PATH>", "Path to TOML configuration file", "--config /etc/crabdns/crabdns.toml"],
              ["--dns-listen <ADDR>", "Override UDP/TCP DNS listen socket", "--dns-listen 0.0.0.0:53"],
              ["--web-listen <ADDR>", "Override HTTP WebUI & DoH listen socket", "--web-listen 0.0.0.0:3000"],
              ["--web-tls-listen <ADDR>", "Enable HTTPS WebUI & DoH listener", "--web-tls-listen 0.0.0.0:443"],
              ["--dot-listen <ADDR>", "Enable DNS-over-TLS listener", "--dot-listen 0.0.0.0:853"],
              ["--doq-listen <ADDR>", "Enable DNS-over-QUIC listener", "--doq-listen 0.0.0.0:853"],
              ["--doh3-listen <ADDR>", "Enable DNS-over-HTTP/3 listener", "--doh3-listen 0.0.0.0:443"],
            ],
          },
        },
        {
          id: "self-update",
          heading: "Post-Quantum Signed Self-Update",
          body: [
            "CrabDNS integrates sigilup to verify release manifests using Ed25519 + ML-DSA-65 + BLAKE3 + SHA-512 before replacing the binary in-place.",
          ],
          code: {
            lang: "bash",
            content: `# Check for a newer signed release
crabdns update --check

# Download, verify, and apply update
crabdns --self-update`,
          },
        },
      ],
    },
    {
      slug: "install-script",
      title: "Install Script (install.sh)",
      description: "Automated deployment, OpenWrt dnsmasq integration, mirrors, and uninstallation via scripts/install.sh.",
      icon: "i-ri-terminal-box-line",
      sections: [
        {
          id: "overview",
          heading: "Overview & Supported Platforms",
          body: [
            "scripts/install.sh is a POSIX sh script that automates deploying or upgrading CrabDNS on Linux (systemd) and OpenWrt (procd) for x86_64 and aarch64.",
            "It resolves the latest (or pinned) GitHub Release, verifies the .tar.gz archive against its .sha256 file, atomically replaces /usr/bin/crabdns, preserves any existing /etc/crabdns/config.toml, and starts the service.",
          ],
          code: {
            lang: "bash",
            content: `# Install latest release
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh

# Install a specific version via a GitHub download mirror
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | \\
  sudo sh -s -- --version v0.1.6 --mirror https://v6.gh-proxy.org/`,
          },
        },
        {
          id: "options",
          heading: "Script Options & Environment Variables",
          body: [
            "Pass options after `sh -s --` when piping from curl, or set CRABDNS_REPO, CRABDNS_VERSION, and CRABDNS_MIRROR in the environment.",
          ],
          table: {
            headers: ["Option", "Default", "Description"],
            rows: [
              ["--version <tag>", "latest (CRABDNS_VERSION)", "Release tag to install"],
              ["--repo <owner/repo>", "zkz098/crabdns (CRABDNS_REPO)", "GitHub repository"],
              ["--mirror <prefix>", "empty (CRABDNS_MIRROR)", "Download mirror prefix for GitHub releases"],
              ["--bin <path>", "—", "Install from a local crabdns binary instead of downloading"],
              ["--install-path <path>", "/usr/bin/crabdns", "Target binary path"],
              ["--config <path>", "/etc/crabdns/config.toml", "Config file path (preserved on upgrade)"],
              ["--data-dir <path>", "/var/lib/crabdns (Linux) / /etc/crabdns/data (OpenWrt)", "Fjall data & log directory"],
              ["--dns-listen <addr>", "0.0.0.0:5353 (or :53 on takeover)", "Initial DNS listen address"],
              ["--web-listen <addr>", "0.0.0.0:3000", "Initial WebUI listen address"],
              ["--openwrt-dnsmasq <mode>", "none", "OpenWrt dnsmasq mode: none | upstream | takeover"],
              ["--uninstall", "—", "Stop, disable, and remove binary & service"],
              ["--purge", "—", "With --uninstall, also delete config and data directories"],
            ],
          },
        },
        {
          id: "openwrt-integration",
          heading: "OpenWrt (procd & dnsmasq)",
          body: [
            "On OpenWrt, the script generates /etc/init.d/crabdns using procd with automatic respawn and nofile=65536 limits. Use --openwrt-dnsmasq to integrate with dnsmasq:",
            "• none: Leaves dnsmasq untouched (CrabDNS listens on :5353). • upstream: Configures dnsmasq to forward all DNS queries to 127.0.0.1#5353 with noresolv=1. • takeover: Sets dnsmasq port=0 and binds CrabDNS directly to 0.0.0.0:53.",
          ],
          code: {
            lang: "sh",
            content: `# Let CrabDNS take over port 53 directly on OpenWrt
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | \\
  sh -s -- --openwrt-dnsmasq takeover`,
          },
        },
        {
          id: "uninstall",
          heading: "Upgrading & Uninstalling",
          body: [
            "Re-running install.sh upgrades the binary in-place without overwriting /etc/crabdns/config.toml. To remove CrabDNS cleanly:",
          ],
          code: {
            lang: "bash",
            content: `# Remove binary & service (keep config and data)
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh -s -- --uninstall

# Remove everything including /etc/crabdns and data_dir
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh -s -- --uninstall --purge`,
          },
        },
      ],
    },
    {
      slug: "configuration",
      title: "Configuration",
      description: "Core crabdns.toml settings for listeners, upstreams, caching, and ACLs.",
      icon: "i-ri-settings-3-line",
      sections: [
        {
          id: "listeners-storage",
          heading: "Listeners & Storage",
          body: [
            "All settings live in a TOML file loaded via Config::load_or_default. Query logs, 24-hour stats, and custom rules are stored in the embedded fjall LSM-tree under data_dir.",
          ],
          code: {
            lang: "toml",
            content: `listen_dns = "0.0.0.0:5353"
listen_web = "127.0.0.1:3000"
data_dir = "./data"
log_retention_hours = 24
tcp_max_connections = 256
tcp_idle_timeout_secs = 30`,
          },
        },
        {
          id: "upstreams-strategy",
          heading: "Upstreams & Routing Strategy",
          body: [
            "CrabDNS supports UDP, TCP, DoT (tls://), DoH (https://), and DoQ (quic://) upstreams. Choose between failover, parallel, or least_latency probing.",
            "Split-DNS rules allow routing specific internal or private domains to dedicated upstream resolvers.",
          ],
          code: {
            lang: "toml",
            content: `upstream_strategy = "least_latency" # failover | parallel | least_latency
upstream_timeout_ms = 2000
upstreams = [
  "https://1.1.1.1/dns-query",
  "tls://8.8.8.8:853"
]
bootstrap_dns = ["1.1.1.1:53", "9.9.9.9:53"]

[[split_dns]]
domain = "corp.internal"
upstreams = ["10.0.0.53:53"]`,
          },
        },
        {
          id: "cache-acl",
          heading: "Optimistic Cache & Access Control",
          body: [
            "The moka cache uses foldhash and singleflight request coalescing. With optimistic_cache enabled, expired entries are served immediately while refreshed asynchronously in the background.",
          ],
          code: {
            lang: "toml",
            content: `cache_size = 65536
optimistic_cache = true
cache_prefetch_enabled = true
cache_min_ttl_secs = 30
cache_max_ttl_secs = 86400

# Client ACL & Rate Limiting
allow_cidrs = ["192.168.0.0/16", "10.0.0.0/8"]
deny_cidrs = []
rate_limit_qps = 0 # 0 disables per-IP QPS limit`,
          },
        },
      ],
    },
    {
      slug: "filtering",
      title: "Filtering & Rewrites",
      description: "Reversed-label Trie rule syntax, block modes, and DNS rewrites.",
      icon: "i-ri-shield-flash-line",
      sections: [
        {
          id: "rule-syntax",
          heading: "Supported Rule Syntax",
          body: [
            "CrabDNS compiles filter subscriptions and custom rules into a reversed-label Trie and swaps snapshots lock-free via arc-swap. Both AdGuard-style rules and standard /etc/hosts entries are supported.",
          ],
          code: {
            lang: "text",
            content: `# Block domain and all subdomains
||ads.example.com^

# Allowlist exception (overrides block rules)
@@||metrics.example.com^

# High-priority rule ($important)
||telemetry.example.com^$important

# Wildcard pattern
*adservice*.example.net

# Standard hosts syntax
0.0.0.0 tracker.example.org`,
          },
        },
        {
          id: "dns-rewrites",
          heading: "DNS Rewrites ($dnsrewrite)",
          body: [
            "Rewrite responses for local services or custom overrides directly inside the filter engine or from the WebUI Rewrites tab.",
          ],
          code: {
            lang: "text",
            content: `# Rewrite A / AAAA records
||nas.local.dev^$dnsrewrite=192.168.1.50
||nas.local.dev^$dnsrewrite=fd00::50

# Rewrite CNAME or custom NXDOMAIN
||alias.local.dev^$dnsrewrite=NOERROR;CNAME;target.local.dev`,
          },
        },
        {
          id: "block-modes",
          heading: "Block Modes & CNAME Cloaking",
          body: [
            "Configure how blocked queries are answered using block_mode in crabdns.toml or the WebUI Settings page. CNAME cloaking protection (cname_cloaking_blocking = true) inspects upstream CNAME chains against the filter Trie.",
          ],
          table: {
            headers: ["block_mode", "Response", "Notes"],
            rows: [
              ["zero_ip (default)", "0.0.0.0 (A) / :: (AAAA)", "Fastest client-side failure for HTTP/HTTPS"],
              ["nx_domain", "NXDOMAIN (RCODE 3)", "Standard non-existent domain response"],
              ["no_data", "NOERROR with 0 answers", "Empty answer section"],
            ],
          },
        },
      ],
    },
    {
      slug: "protocols",
      title: "Encrypted DNS & Security",
      description: "DoT, DoH, DoH3, DoQ, ACME TLS, DNSSEC, RRL, and SafeSearch.",
      icon: "i-ri-lock-2-line",
      sections: [
        {
          id: "encrypted-listeners",
          heading: "DoT, DoH, DoH3 & DoQ",
          body: [
            "Beyond standard UDP/TCP, CrabDNS natively terminates encrypted DNS using rustls (aws-lc-rs) and quinn for QUIC/HTTP3.",
            "DoH (/dns-query) is served on listen_web (and listen_web_tls when TLS is configured). Dedicated sockets can be enabled for DoT, DoQ, and DoH3.",
          ],
          code: {
            lang: "toml",
            content: `doh_enabled = true
listen_web_tls = "0.0.0.0:443"
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"
listen_doh3 = "0.0.0.0:443"

tls_cert_path = "/etc/crabdns/fullchain.pem"
tls_key_path = "/etc/crabdns/privkey.pem"`,
          },
        },
        {
          id: "security-features",
          heading: "DNSSEC, RRL & DNS Cookies",
          body: [
            "CrabDNS includes built-in protocol hardening modules in crabdns-core:",
            "• DNSSEC validation (dnssec.rs / dnssec_nsec.rs) • Response Rate Limiting (RRL, rrl.rs) against amplification • DNS Cookies (cookies.rs) • SafeSearch enforcement (safesearch.rs) • DNS64 synthesis (dns64.rs) • ACME certificate automation (instant-acme with Http01 or Dns01Local).",
          ],
        },
      ],
    },
    {
      slug: "benchmarks",
      title: "Benchmarks & Quality Gates",
      description: "Criterion microbenchmarks, dns_loadtest, cargo-warden, and fuzzing.",
      icon: "i-ri-speed-up-line",
      sections: [
        {
          id: "perf-suite",
          heading: "Two-Tier Performance Suite",
          body: [
            "CrabDNS uses scripts/perf.sh to unify Criterion hot-path microbenchmarks and the dns_loadtest release-mode load generator (using mimalloc).",
          ],
          code: {
            lang: "bash",
            content: `# Run fast microbenchmarks + all E2E scenarios
./scripts/perf.sh all

# Run full Criterion microbenchmarks (filter, cache, routing, pipeline, storage)
./scripts/perf.sh micro

# Run E2E load test (cached-udp, blocked-udp, upstream-udp, cached-tcp, mixed-udp)
./scripts/perf.sh e2e --scenario all --concurrency 32 --duration-secs 5`,
          },
        },
        {
          id: "warden-fuzz",
          heading: "Quality Gates & Fuzzing",
          body: [
            "The workspace enforces #![forbid(unsafe_code)], strict clippy pedantic lints, DAG architecture checks, and function complexity bounds via cargo-warden.",
          ],
          code: {
            lang: "bash",
            content: `# Static checks (dag, complexity, file-length, hygiene, manifest, ci-parity) + fmt + clippy
cargo warden check

# Full local gate (static checks + workspace nextest + Web UI build)
cargo warden gate

# Nightly fuzz targets
cargo +nightly fuzz run fuzz_filter_parser
cargo +nightly fuzz run fuzz_dns_packet`,
          },
        },
      ],
    },
  ],
  zh: [
    {
      slug: "getting-started",
      title: "快速开始",
      description: "从源码编译运行 CrabDNS，了解常用命令行参数与签名自更新。",
      icon: "i-ri-rocket-line",
      sections: [
        {
          id: "one-line-install",
          heading: "一键安装（Linux 与 OpenWrt）",
          body: [
            "对于 Linux (systemd) 与 OpenWrt (procd) 的 x86_64 / aarch64 设备，可直接使用官方部署脚本 scripts/install.sh。脚本会自动下载对应架构的 Release 压缩包、校验 SHA-256、安装 /usr/bin/crabdns、生成默认配置并启动系统服务。",
          ],
          code: {
            lang: "bash",
            content: `curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh`,
          },
        },
        {
          id: "build-and-run",
          heading: "从源码构建并运行",
          body: [
            "CrabDNS 通过 rust-embed 将 SolidJS + UnoCSS WebUI 直接打包进纯 Rust 二进制文件中。在编译或运行服务端前，请先构建一次前端静态资源。",
            "默认情况下，CrabDNS 在 0.0.0.0:5353 监听 DNS 请求，并在 127.0.0.1:3000 提供 WebUI 控制台与 DoH 接口。",
          ],
          code: {
            lang: "bash",
            content: `# 1. 构建 Web UI 静态资源
cd webui && pnpm install && pnpm build && cd ..

# 2. 启动 CrabDNS
cargo run -p crabdns-server`,
          },
        },
        {
          id: "cli-flags",
          heading: "命令行参数",
          body: [
            "可通过命令行参数直接指定配置文件路径，或覆盖各类 DNS / Web 监听端口。",
          ],
          table: {
            headers: ["参数", "说明", "示例"],
            rows: [
              ["-c, --config <PATH>", "指定 TOML 配置文件路径", "--config /etc/crabdns/crabdns.toml"],
              ["--dns-listen <ADDR>", "覆盖 UDP/TCP DNS 监听地址", "--dns-listen 0.0.0.0:53"],
              ["--web-listen <ADDR>", "覆盖 HTTP WebUI 与 DoH 监听地址", "--web-listen 0.0.0.0:3000"],
              ["--web-tls-listen <ADDR>", "启用 HTTPS WebUI 与 DoH 监听", "--web-tls-listen 0.0.0.0:443"],
              ["--dot-listen <ADDR>", "启用 DNS-over-TLS 监听", "--dot-listen 0.0.0.0:853"],
              ["--doq-listen <ADDR>", "启用 DNS-over-QUIC 监听", "--doq-listen 0.0.0.0:853"],
              ["--doh3-listen <ADDR>", "启用 DNS-over-HTTP/3 监听", "--doh3-listen 0.0.0.0:443"],
            ],
          },
        },
        {
          id: "self-update",
          heading: "后量子签名自更新",
          body: [
            "CrabDNS 集成了 sigilup，在原地替换二进制文件前使用 Ed25519 + ML-DSA-65 + BLAKE3 + SHA-512 对发布清单进行多重签名校验。",
          ],
          code: {
            lang: "bash",
            content: `# 仅检查是否有新版本发布
crabdns update --check

# 下载、校验签名并执行自更新
crabdns --self-update`,
          },
        },
      ],
    },
    {
      slug: "install-script",
      title: "部署脚本 (install.sh)",
      description: "详解 scripts/install.sh 的一键部署、镜像加速、OpenWrt dnsmasq 集成与卸载参数。",
      icon: "i-ri-terminal-box-line",
      sections: [
        {
          id: "overview",
          heading: "功能概览与支持平台",
          body: [
            "scripts/install.sh 是基于 POSIX sh 编写的自动化部署脚本，支持在 Linux (systemd) 与 OpenWrt (procd) 的 x86_64 / aarch64 设备上一键安装或升级 CrabDNS。",
            "脚本会自动解析 GitHub Release 版本，下载 .tar.gz 并通过 sha256sum 校验完整性，原子替换 /usr/bin/crabdns，升级时保留已有的 /etc/crabdns/config.toml 配置。",
          ],
          code: {
            lang: "bash",
            content: `# 安装最新版本
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh

# 指定版本并使用 GitHub 下载镜像加速
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | \\
  sudo sh -s -- --version v0.1.6 --mirror https://v6.gh-proxy.org/`,
          },
        },
        {
          id: "options",
          heading: "脚本参数与环境变量",
          body: [
            "通过管道执行时请在 `sh -s --` 后传递参数；也支持直接设置 CRABDNS_REPO、CRABDNS_VERSION 与 CRABDNS_MIRROR 环境变量。",
          ],
          table: {
            headers: ["参数", "默认值", "说明"],
            rows: [
              ["--version <tag>", "latest (CRABDNS_VERSION)", "指定安装的 Release 标签"],
              ["--repo <owner/repo>", "zkz098/crabdns (CRABDNS_REPO)", "指定 GitHub 仓库"],
              ["--mirror <prefix>", "空 (CRABDNS_MIRROR)", "GitHub Release 下载镜像前缀"],
              ["--bin <path>", "—", "使用本地已编译的二进制文件安装，跳过下载"],
              ["--install-path <path>", "/usr/bin/crabdns", "二进制安装目标路径"],
              ["--config <path>", "/etc/crabdns/config.toml", "配置文件路径（升级时自动保留）"],
              ["--data-dir <path>", "Linux: /var/lib/crabdns · OpenWrt: /etc/crabdns/data", "Fjall 数据与日志存储目录"],
              ["--dns-listen <addr>", "0.0.0.0:5353（takeover 模式为 :53）", "初始 DNS 监听地址"],
              ["--web-listen <addr>", "0.0.0.0:3000", "初始 WebUI 监听地址"],
              ["--openwrt-dnsmasq <mode>", "none", "OpenWrt dnsmasq 集成模式：none | upstream | takeover"],
              ["--uninstall", "—", "停止服务并移除二进制与服务文件"],
              ["--purge", "—", "配合 --uninstall 同时删除配置与数据目录"],
            ],
          },
        },
        {
          id: "openwrt-integration",
          heading: "OpenWrt (procd 与 dnsmasq 集成)",
          body: [
            "在 OpenWrt 上，脚本会自动创建 /etc/init.d/crabdns（启用 procd 自动拉起与 nofile=65536 限制）。可通过 --openwrt-dnsmasq 控制与 dnsmasq 的配合方式：",
            "• none：不修改 dnsmasq（CrabDNS 监听 :5353）。• upstream：将 dnsmasq 上游设为 127.0.0.1#5353 并开启 noresolv=1。• takeover：将 dnsmasq 端口设为 0，由 CrabDNS 直接接管 53 端口。",
          ],
          code: {
            lang: "sh",
            content: `# 在 OpenWrt 上由 CrabDNS 直接接管 53 端口
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | \\
  sh -s -- --openwrt-dnsmasq takeover`,
          },
        },
        {
          id: "uninstall",
          heading: "升级与卸载",
          body: [
            "再次运行 install.sh 即可实现平滑升级并保留现有配置文件。如需卸载 CrabDNS：",
          ],
          code: {
            lang: "bash",
            content: `# 卸载程序与系统服务（保留配置与数据）
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh -s -- --uninstall

# 彻底卸载并清除 /etc/crabdns 与数据目录
curl -fsSL https://raw.githubusercontent.com/zkz098/crabdns/main/scripts/install.sh | sudo sh -s -- --uninstall --purge`,
          },
        },
      ],
    },
    {
      slug: "configuration",
      title: "配置指南",
      description: "详解 crabdns.toml 中的监听端口、上游分流策略、乐观缓存与访问控制。",
      icon: "i-ri-settings-3-line",
      sections: [
        {
          id: "listeners-storage",
          heading: "监听与存储配置",
          body: [
            "所有配置均保存在 TOML 文件中（通过 Config::load_or_default 加载）。查询日志、24 小时统计数据与自定义规则会持久化到 data_dir 下的内嵌 fjall LSM-tree 数据库中。",
          ],
          code: {
            lang: "toml",
            content: `listen_dns = "0.0.0.0:5353"
listen_web = "127.0.0.1:3000"
data_dir = "./data"
log_retention_hours = 24
tcp_max_connections = 256
tcp_idle_timeout_secs = 30`,
          },
        },
        {
          id: "upstreams-strategy",
          heading: "上游服务器与 Split-DNS 分流",
          body: [
            "支持 UDP、TCP、DoT (tls://)、DoH (https://) 与 DoQ (quic://) 上游。上游调度策略支持 failover（故障转移）、parallel（并发竞速）与 least_latency（最低延迟探测）。",
            "通过 [[split_dns]] 可为内网或特定后缀域名指定专用上游解析器。",
          ],
          code: {
            lang: "toml",
            content: `upstream_strategy = "least_latency" # failover | parallel | least_latency
upstream_timeout_ms = 2000
upstreams = [
  "https://1.1.1.1/dns-query",
  "tls://8.8.8.8:853"
]
bootstrap_dns = ["1.1.1.1:53", "9.9.9.9:53"]

[[split_dns]]
domain = "corp.internal"
upstreams = ["10.0.0.53:53"]`,
          },
        },
        {
          id: "cache-acl",
          heading: "乐观缓存与访问控制",
          body: [
            "Moka 缓存采用 foldhash 哈希与 singleflight 请求合并。开启 optimistic_cache 后，过期缓存条目会立即返回并在后台异步刷新，避免尾延迟毛刺。",
          ],
          code: {
            lang: "toml",
            content: `cache_size = 65536
optimistic_cache = true
cache_prefetch_enabled = true
cache_min_ttl_secs = 30
cache_max_ttl_secs = 86400

# 客户端 CIDR 访问控制与限流
allow_cidrs = ["192.168.0.0/16", "10.0.0.0/8"]
deny_cidrs = []
rate_limit_qps = 0 # 0 表示不限制单 IP QPS`,
          },
        },
      ],
    },
    {
      slug: "filtering",
      title: "过滤与重写规则",
      description: "倒排标签 Trie 规则语法、拦截响应模式及 $dnsrewrite 重写。",
      icon: "i-ri-shield-flash-line",
      sections: [
        {
          id: "rule-syntax",
          heading: "支持的规则语法",
          body: [
            "CrabDNS 将订阅规则与自定义规则编译为倒排标签 Trie，并通过 arc-swap 实现无锁热重载。全面兼容 AdGuard 语法与标准 /etc/hosts 格式。",
          ],
          code: {
            lang: "text",
            content: `# 拦截域名及其全部子域名
||ads.example.com^

# 白名单放行（覆盖拦截规则）
@@||metrics.example.com^

# 高优先级规则 ($important)
||telemetry.example.com^$important

# 通配符匹配
*adservice*.example.net

# 标准 hosts 语法
0.0.0.0 tracker.example.org`,
          },
        },
        {
          id: "dns-rewrites",
          heading: "DNS 重写 ($dnsrewrite)",
          body: [
            "可在规则中或 WebUI 的“重写”页面为内网服务、特定域名配置本地解析重写。",
          ],
          code: {
            lang: "text",
            content: `# 重写 A / AAAA 记录
||nas.local.dev^$dnsrewrite=192.168.1.50
||nas.local.dev^$dnsrewrite=fd00::50

# 重写 CNAME 记录
||alias.local.dev^$dnsrewrite=NOERROR;CNAME;target.local.dev`,
          },
        },
        {
          id: "block-modes",
          heading: "拦截模式与 CNAME 伪装防护",
          body: [
            "可通过 block_mode 设置拦截响应类型。开启 cname_cloaking_blocking = true 后，系统还会检查上游返回的 CNAME 解析链是否命中拦截规则。",
          ],
          table: {
            headers: ["block_mode", "返回响应", "说明"],
            rows: [
              ["zero_ip（默认）", "0.0.0.0 (A) / :: (AAAA)", "客户端最快失败，适合拦截 HTTPS 广告请求"],
              ["nx_domain", "NXDOMAIN (RCODE 3)", "标准域名不存在响应"],
              ["no_data", "NOERROR（空应答）", "返回空 Answer 段"],
            ],
          },
        },
      ],
    },
    {
      slug: "protocols",
      title: "加密 DNS 与安全",
      description: "DoT、DoH、DoH3、DoQ、ACME 自动证书与 DNS 安全防护。",
      icon: "i-ri-lock-2-line",
      sections: [
        {
          id: "encrypted-listeners",
          heading: "DoT、DoH、DoH3 与 DoQ",
          body: [
            "除标准 UDP/TCP 外，CrabDNS 基于 rustls (aws-lc-rs) 与 quinn 原生支持多种加密 DNS 协议。",
            "DoH (/dns-query) 挂载在 listen_web（或启用 TLS 后的 listen_web_tls）上；DoT、DoQ 与 DoH3 可分别配置独立监听端口。",
          ],
          code: {
            lang: "toml",
            content: `doh_enabled = true
listen_web_tls = "0.0.0.0:443"
listen_dot = "0.0.0.0:853"
listen_doq = "0.0.0.0:853"
listen_doh3 = "0.0.0.0:443"

tls_cert_path = "/etc/crabdns/fullchain.pem"
tls_key_path = "/etc/crabdns/privkey.pem"`,
          },
        },
        {
          id: "security-features",
          heading: "DNSSEC、RRL 与 DNS Cookies",
          body: [
            "crabdns-core 内置了完整的协议级安全防护模块：",
            "• DNSSEC 签名校验 (dnssec.rs / dnssec_nsec.rs) • 响应速率限制 RRL (rrl.rs) 防范反射放大攻击 • DNS Cookies (cookies.rs) • SafeSearch 强制安全搜索 (safesearch.rs) • DNS64 地址合成 (dns64.rs) • ACME 自动证书申请 (instant-acme，支持 Http01 与 Dns01Local)。",
          ],
        },
      ],
    },
    {
      slug: "benchmarks",
      title: "性能测试与质量门禁",
      description: "Criterion 微基准测试、dns_loadtest 压测、cargo-warden 与模糊测试。",
      icon: "i-ri-speed-up-line",
      sections: [
        {
          id: "perf-suite",
          heading: "双层性能基准测试体系",
          body: [
            "CrabDNS 通过 scripts/perf.sh 统一驱动 Criterion 热点微基准测试与 Release 模式端到端压测工具 dns_loadtest（默认使用 mimalloc 分配器）。",
          ],
          code: {
            lang: "bash",
            content: `# 运行快速微基准测试与全部 E2E 压测场景
./scripts/perf.sh all

# 运行完整 Criterion 微基准测试（filter、cache、routing、pipeline、storage）
./scripts/perf.sh micro

# 运行 E2E 压测（cached-udp、blocked-udp、upstream-udp、cached-tcp、mixed-udp）
./scripts/perf.sh e2e --scenario all --concurrency 32 --duration-secs 5`,
          },
        },
        {
          id: "warden-fuzz",
          heading: "静态质量门禁与 Fuzz 模糊测试",
          body: [
            "整个 Workspace 强制启用 #![forbid(unsafe_code)]，并通过 cargo-warden 校验 DAG 分层、函数圈复杂度、Clippy Pedantic 与 CI 一致性。",
          ],
          code: {
            lang: "bash",
            content: `# 运行静态检查（dag、complexity、file-length、hygiene、manifest、ci-parity）+ fmt + clippy
cargo warden check

# 运行完整本地门禁（静态检查 + workspace nextest + Web UI 构建校验）
cargo warden gate

# 运行 Nightly 模糊测试目标
cargo +nightly fuzz run fuzz_filter_parser
cargo +nightly fuzz run fuzz_dns_packet`,
          },
        },
      ],
    },
  ],
};
