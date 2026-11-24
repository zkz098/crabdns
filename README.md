# CrabDNS

High-performance, pure-Rust DNS ad-blocker and forwarding server (without DHCP), inspired by AdGuardHome.

## Tech Stack

- **DNS Core**: `tokio` + `hickory-proto` + reversed-label Trie filter engine (`arc-swap` hot reload) + `moka` optimistic cache
- **Upstreams**: UDP, TCP, DoT (`tokio-rustls`), DoH (`reqwest`)
- **Storage**: `fjall` (pure-Rust LSM-tree) for async batched query logs, stats, and custom rules
- **Web UI**: `axum` + `rust-embed` + **SolidJS** + **UnoCSS** + **RemixIcon**
- **Quality & Testing**: `cargo-warden`, `cargo-nextest`, `cargo-fuzz`

## Quick Start

```bash
# 1. Build Web UI assets
cd webui && pnpm install && pnpm build && cd ..

# 2. Run CrabDNS (DNS: 0.0.0.0:5354, Web UI: 127.0.0.1:3000)
cargo run -p crabdns-server
```

> [!NOTE]
> **Avoid UDP port `5353` for `listen_dns`:** Port `5353` is reserved for mDNS (`avahi-daemon` / `umdns` on Linux and OpenWrt). Because CrabDNS enables `SO_REUSEPORT` on its UDP DNS sockets, binding to `0.0.0.0:5353` alongside an mDNS daemon silently joins the same kernel `SO_REUSEPORT` group without returning `EADDRINUSE`, causing a fraction of unicast UDP DNS queries to be routed to the mDNS daemon and time out. Use `5354` (the default) or `53` (takeover mode) instead.

## Quality Gates & Tests

```bash
# Run all static checks (dag, complexity, file-length, hygiene, manifest, ci-parity, actions) + fmt + clippy
cargo warden check

# Run the full local gate (static checks + fmt + clippy + workspace nextest + Web UI checks/build)
cargo warden gate

# Fuzz targets (nightly)
cargo +nightly fuzz run fuzz_filter_parser
cargo +nightly fuzz run fuzz_dns_packet
```

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE).
