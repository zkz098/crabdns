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

# 2. Run CrabDNS (DNS: 0.0.0.0:5353, Web UI: 127.0.0.1:3000)
cargo run -p crabdns-server
```

## Quality Gates & Tests

```bash
cargo warden check && cargo warden hygiene && cargo warden manifest
cargo nextest run --workspace
cargo +nightly fuzz run fuzz_filter_parser
cargo +nightly fuzz run fuzz_dns_packet
```

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE).
