use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crabdns_core::cache::{CacheKey, DnsCache, patch_tx_id};
use crabdns_core::upstream::UpstreamEndpoint;
use crabdns_core::{Config, DnsPipeline, FilterAction, FilterEngine, UpstreamPool};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use proptest::prelude::*;

fn arb_label() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,8}"
}

fn arb_domain() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_label(), 2..=4).prop_map(|labels| labels.join("."))
}

fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| IpAddr::V6(Ipv6Addr::from(octets))),
    ]
}

fn arb_rule_line() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_domain().prop_map(|d| format!("||{d}^")),
        arb_domain().prop_map(|d| format!("|{d}^")),
        arb_domain().prop_map(|d| format!("||{d}^$important")),
        arb_domain().prop_map(|d| format!("@@||{d}^")),
        arb_domain().prop_map(|d| format!("@@||{d}^$important")),
        (arb_domain(), arb_ip()).prop_map(|(d, ip)| format!("||{d}^$dnsrewrite={ip}")),
        arb_domain().prop_map(|d| format!("0.0.0.0 {d}")),
        arb_domain().prop_map(|d| format!("! comment {d}")),
        Just(String::new()),
    ]
}

fn arb_qtype() -> impl Strategy<Value = RecordType> {
    prop_oneof![
        Just(RecordType::A),
        Just(RecordType::AAAA),
        Just(RecordType::TXT),
        Just(RecordType::MX),
    ]
}

fn build_dns_query(id: u16, domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(domain).expect("valid generated domain");
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().expect("encode query")
}

proptest! {
    #[test]
    fn prop_filter_never_panics_on_arbitrary_input(
        rules_text in ".*",
        domain in ".*",
    ) {
        let engine = FilterEngine::new(&[]);
        let stats = engine.reload_from_text(&rules_text);
        prop_assert_eq!(
            stats.total_rules,
            stats.block_rules + stats.allow_rules + stats.rewrite_rules
        );
        let _ = engine.evaluate(&domain);
    }

    #[test]
    fn prop_filter_stats_and_reload_equivalence(
        lines in prop::collection::vec(arb_rule_line(), 0..30),
        probe in arb_domain(),
    ) {
        let engine_init = FilterEngine::new(&lines);
        let joined = lines.join("\n");
        let engine_reloaded = FilterEngine::new(&[]);
        let reloaded_stats = engine_reloaded.reload_from_text(&joined);

        let init_stats = engine_init.stats();
        prop_assert_eq!(init_stats.total_rules, reloaded_stats.total_rules);
        prop_assert_eq!(init_stats.block_rules, reloaded_stats.block_rules);
        prop_assert_eq!(init_stats.allow_rules, reloaded_stats.allow_rules);
        prop_assert_eq!(init_stats.rewrite_rules, reloaded_stats.rewrite_rules);
        prop_assert_eq!(
            init_stats.total_rules,
            init_stats.block_rules + init_stats.allow_rules + init_stats.rewrite_rules
        );
        prop_assert_eq!(engine_init.evaluate(&probe), engine_reloaded.evaluate(&probe));
    }

    #[test]
    fn prop_filter_case_and_trailing_dot_invariance(
        lines in prop::collection::vec(arb_rule_line(), 1..20),
        domain in arb_domain(),
    ) {
        let engine = FilterEngine::new(&lines);
        let lower = engine.evaluate(&domain);
        let upper = engine.evaluate(&domain.to_ascii_uppercase());
        let dotted = engine.evaluate(&format!("{domain}."));

        prop_assert_eq!(&lower, &upper);
        prop_assert_eq!(&lower, &dotted);
    }

    #[test]
    fn prop_filter_precedence_hierarchy(
        domain in arb_domain(),
        sub_label in arb_label(),
        ip in arb_ip(),
    ) {
        let sub = format!("{sub_label}.{domain}");

        // 1. important allow > important block > allow > rewrite > block
        let rules = vec![
            format!("||{domain}^"),
            format!("||{domain}^$dnsrewrite={ip}"),
            format!("@@||{domain}^"),
            format!("||{domain}^$important"),
            format!("@@||{domain}^$important"),
        ];
        let engine = FilterEngine::new(&rules);
        prop_assert_eq!(engine.evaluate(&domain).action, FilterAction::Allow);
        prop_assert_eq!(engine.evaluate(&sub).action, FilterAction::Allow);

        // 2. Without important allow, important block wins over normal allow/rewrite/block
        let rules_no_imp_allow = vec![
            format!("||{domain}^"),
            format!("||{domain}^$dnsrewrite={ip}"),
            format!("@@||{domain}^"),
            format!("||{domain}^$important"),
        ];
        let engine2 = FilterEngine::new(&rules_no_imp_allow);
        prop_assert_eq!(engine2.evaluate(&domain).action, FilterAction::Block);
        prop_assert_eq!(engine2.evaluate(&sub).action, FilterAction::Block);

        // 3. Normal allow wins over rewrite and block
        let rules_allow = vec![
            format!("||{domain}^"),
            format!("||{domain}^$dnsrewrite={ip}"),
            format!("@@||{domain}^"),
        ];
        let engine3 = FilterEngine::new(&rules_allow);
        prop_assert_eq!(engine3.evaluate(&domain).action, FilterAction::Allow);

        // 4. Rewrite wins over normal block
        let rules_rewrite = vec![
            format!("||{domain}^"),
            format!("||{domain}^$dnsrewrite={ip}"),
        ];
        let engine4 = FilterEngine::new(&rules_rewrite);
        prop_assert_eq!(
            engine4.evaluate(&domain).action,
            FilterAction::Rewrite(crabdns_core::RewriteAction::Ip(ip))
        );

        // 5. Exact rule `|domain^` only matches exact domain, not subdomain
        let exact_engine = FilterEngine::new(&[format!("|{domain}^")]);
        prop_assert_eq!(exact_engine.evaluate(&domain).action, FilterAction::Block);
        prop_assert_eq!(exact_engine.evaluate(&sub).action, FilterAction::Allow);
    }

    #[test]
    fn prop_cache_patch_tx_id_and_roundtrip(
        mut wire in prop::collection::vec(any::<u8>(), 0..256),
        query_id in any::<u16>(),
        domain in arb_domain(),
        qtype in any::<u16>(),
        ttl in any::<u32>(),
    ) {
        let original_tail = if wire.len() >= 2 {
            wire[2..].to_vec()
        } else {
            wire.clone()
        };

        patch_tx_id(&mut wire, query_id);
        if wire.len() >= 2 {
            prop_assert_eq!(&wire[0..2], &query_id.to_be_bytes());
            prop_assert_eq!(&wire[2..], original_tail.as_slice());
        } else {
            prop_assert_eq!(&wire, &original_tail);
        }

        if wire.len() >= 2 {
            let cache = DnsCache::new(64, true);
            let key = CacheKey {
                qname: format!("{domain}."),
                qtype,
                qclass: 1,
                ecs_subnet: None,
                dnssec_do: false,
                upstream_scope: None,
            };
            cache.insert(key.clone(), wire.clone(), ttl);
            let hit = cache.get(&key, query_id.wrapping_add(1)).expect("fresh cache hit");
            prop_assert!(!hit.is_stale);
            prop_assert_eq!(&hit.wire_bytes[0..2], &query_id.wrapping_add(1).to_be_bytes());
            prop_assert_eq!(&hit.wire_bytes[2..], &wire[2..]);
        }
    }

    #[test]
    fn prop_upstream_endpoint_parse_never_panics_and_schemes(
        arbitrary in ".*",
        ipv4 in any::<[u8; 4]>(),
        port in 1_u16..=65535,
        domain in arb_domain(),
    ) {
        let _ = UpstreamEndpoint::parse(&arbitrary);

        let ip = IpAddr::V4(Ipv4Addr::from(ipv4));
        let udp_spec = format!("udp://{ip}:{port}");
        let parsed_udp = UpstreamEndpoint::parse(&udp_spec).expect("valid udp");
        prop_assert!(matches!(parsed_udp, UpstreamEndpoint::Udp(a) if a == SocketAddr::new(ip, port)));

        let tcp_spec = format!("tcp://{ip}:{port}");
        let parsed_tcp = UpstreamEndpoint::parse(&tcp_spec).expect("valid tcp");
        prop_assert!(matches!(parsed_tcp, UpstreamEndpoint::Tcp(a) if a == SocketAddr::new(ip, port)));

        let tls_spec = format!("tls://{domain}:{port}");
        let parsed_tls = UpstreamEndpoint::parse(&tls_spec).expect("valid tls");
        let is_tls = matches!(
            parsed_tls,
            UpstreamEndpoint::Dot { ref addr, ref server_name }
            if addr == &format!("{domain}:{port}") && server_name == &domain
        );
        prop_assert!(is_tls);

        let doh_spec = format!("https://{domain}/dns-query");
        let parsed_doh = UpstreamEndpoint::parse(&doh_spec).expect("valid doh");
        let is_doh = matches!(parsed_doh, UpstreamEndpoint::Doh { ref url } if url == &doh_spec);
        prop_assert!(is_doh);
    }

    #[test]
    fn prop_config_toml_roundtrip(
        dns_port in 1024_u16..60000,
        web_port in 1024_u16..60000,
        cache_size in 1_u64..100_000,
        optimistic in any::<bool>(),
        timeout_ms in 100_u64..30_000,
        retention_hours in 1_u64..720,
        rules in prop::collection::vec(arb_rule_line(), 0..10),
    ) {
        let cfg = Config {
            listen_dns: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dns_port),
            listen_web: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), web_port),
            upstreams: vec!["udp://127.0.0.1:5353".to_string()],
            cache_size,
            optimistic_cache: optimistic,
            upstream_timeout_ms: timeout_ms,
            custom_rules: rules.clone(),
            log_retention_hours: retention_hours,
            ..Config::default()
        };

        let toml_text = toml::to_string(&cfg).expect("serialize config");
        let decoded = Config::from_toml_str(&toml_text).expect("deserialize config");

        prop_assert_eq!(decoded.listen_dns, cfg.listen_dns);
        prop_assert_eq!(decoded.listen_web, cfg.listen_web);
        prop_assert_eq!(decoded.cache_size, cfg.cache_size);
        prop_assert_eq!(decoded.optimistic_cache, cfg.optimistic_cache);
        prop_assert_eq!(decoded.upstream_timeout_ms, cfg.upstream_timeout_ms);
        prop_assert_eq!(decoded.custom_rules, rules);
        prop_assert_eq!(decoded.log_retention_hours, cfg.log_retention_hours);
    }

    #[test]
    fn prop_pipeline_arbitrary_bytes_never_panic(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");
        let filter = Arc::new(FilterEngine::new(&[]));
        let cache = Arc::new(DnsCache::new(16, true));
        let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).expect("pool"));
        let pipeline = DnsPipeline::new(filter, cache, upstream, None);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let result = rt.block_on(pipeline.handle_packet(&raw, client));
        if let Ok(resp) = result {
            prop_assert!(Message::from_vec(&resp).is_ok());
        }
    }

    #[test]
    fn prop_pipeline_valid_blocked_and_rewritten_queries(
        id in any::<u16>(),
        blocked_domain in arb_domain(),
        rewrite_domain in arb_domain(),
        rewrite_ipv4 in any::<[u8; 4]>(),
        qtype in arb_qtype(),
    ) {
        prop_assume!(blocked_domain != rewrite_domain);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        let ip = IpAddr::V4(Ipv4Addr::from(rewrite_ipv4));
        let filter = Arc::new(FilterEngine::new(&[
            format!("||{blocked_domain}^"),
            format!("||{rewrite_domain}^$dnsrewrite={ip}"),
        ]));
        let cache = Arc::new(DnsCache::new(16, true));
        let upstream = Arc::new(UpstreamPool::new(&["udp://127.0.0.1:1".to_string()], 50).expect("pool"));
        let pipeline = DnsPipeline::new(filter, cache, upstream, None);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);

        let blocked_query = build_dns_query(id, &blocked_domain, qtype);
        let blocked_resp_bytes = rt
            .block_on(pipeline.handle_packet(&blocked_query, client))
            .expect("blocked response");
        let blocked_msg = Message::from_vec(&blocked_resp_bytes).expect("valid dns resp");
        prop_assert_eq!(blocked_msg.id, id);
        prop_assert_eq!(blocked_msg.message_type, MessageType::Response);
        match qtype {
            RecordType::A | RecordType::AAAA => {
                prop_assert_eq!(blocked_msg.response_code, ResponseCode::NoError);
                prop_assert_eq!(blocked_msg.answers.len(), 1);
            }
            _ => {
                prop_assert_eq!(blocked_msg.response_code, ResponseCode::NXDomain);
            }
        }

        let rewrite_query = build_dns_query(id, &rewrite_domain, RecordType::A);
        let rewrite_resp_bytes = rt
            .block_on(pipeline.handle_packet(&rewrite_query, client))
            .expect("rewrite response");
        let rewrite_msg = Message::from_vec(&rewrite_resp_bytes).expect("valid dns resp");
        prop_assert_eq!(rewrite_msg.id, id);
        prop_assert_eq!(rewrite_msg.response_code, ResponseCode::NoError);
        prop_assert_eq!(rewrite_msg.answers.len(), 1);
    }
}
