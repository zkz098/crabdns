use crabdns_core::split_dns::SplitQueryContext;
use crabdns_core::{
    SplitDnsMatchMode, SplitDnsRule, SplitUpstreamRouter, UpstreamGroupRegistry, UpstreamStrategy,
};

fn endpoint(router: &SplitUpstreamRouter, domain: &str) -> Option<String> {
    router
        .resolve(domain)
        .map(|p| p.health_snapshot()[0].endpoint.clone())
}

fn rule(domain: &str, upstream: &str) -> SplitDnsRule {
    SplitDnsRule {
        domain: domain.to_string(),
        upstreams: vec![upstream.to_string()],
        fallback_to_default: true,
        ..Default::default()
    }
}

fn build(
    rules: &[SplitDnsRule],
    mode: SplitDnsMatchMode,
    list: Option<(&'static str, &'static str)>,
) -> SplitUpstreamRouter {
    SplitUpstreamRouter::new_full(
        rules,
        &UpstreamGroupRegistry::empty(),
        mode,
        1000,
        UpstreamStrategy::Failover,
        &[],
        |url| list.and_then(|(u, body)| (u == url).then(|| body.to_string())),
    )
    .expect("valid router")
}

#[test]
fn test_split_dns_longest_suffix_match() {
    let rules = vec![
        rule("local", "udp://192.168.1.1:53"),
        rule("*.corp.local", "udp://10.0.0.1:53"),
    ];
    let router = SplitUpstreamRouter::new(&rules, 1000, UpstreamStrategy::Failover).unwrap();
    assert!(router.resolve("nas.local").is_some());
    assert!(router.resolve("notlocal").is_none());
    assert!(router.resolve("example.com").is_none());
    assert_eq!(
        endpoint(&router, "db.corp.local").as_deref(),
        Some("udp://10.0.0.1:53")
    );
    assert_eq!(
        endpoint(&router, "printer.local").as_deref(),
        Some("udp://192.168.1.1:53")
    );
}

#[test]
fn test_split_dns_domains_file_and_url_resolver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let list_path = dir.path().join("cn-domains.txt");
    std::fs::write(
        &list_path,
        "# CN domains\ndomain:cn\n*.qq.com\n||bilibili.com^\nfull:exact.example.org\n",
    )
    .unwrap();

    let rules = vec![
        SplitDnsRule {
            domains_file: Some(list_path.display().to_string()),
            upstreams: vec!["udp://223.5.5.5:53".to_string()],
            fallback_to_default: true,
            ..Default::default()
        },
        SplitDnsRule {
            domains_url: Some("https://example.invalid/cn.txt".to_string()),
            upstreams: vec!["udp://119.29.29.29:53".to_string()],
            fallback_to_default: true,
            ..Default::default()
        },
    ];
    let router = build(
        &rules,
        SplitDnsMatchMode::SpecificityFirst,
        Some((
            "https://example.invalid/cn.txt",
            "server=/taobao.com/223.5.5.5\n",
        )),
    );
    assert!(router.resolve("gov.cn").is_some());
    assert!(router.resolve("news.qq.com").is_some());
    assert!(router.resolve("api.bilibili.com").is_some());
    assert!(router.resolve("www.taobao.com").is_some());
    assert!(router.resolve("exact.example.org").is_some());
    assert!(router.resolve("sub.exact.example.org").is_none());
    assert!(router.resolve("google.com").is_none());
}

#[test]
fn test_unified_trie_specificity_order_and_exclusions() {
    let rules = vec![
        rule("example.com", "udp://10.0.0.1:53"),
        SplitDnsRule {
            domains_url: Some("https://list.invalid/a.txt".to_string()),
            upstreams: vec!["udp://10.0.0.2:53".to_string()],
            fallback_to_default: true,
            ..Default::default()
        },
        rule("full:www.example.com", "udp://10.0.0.3:53"),
        SplitDnsRule {
            exclude_domains: vec!["skip.example.net".to_string()],
            ..rule("example.net", "udp://10.0.0.4:53")
        },
        rule("skip.example.net, keyword:zzz", "udp://10.0.0.5:53"),
    ];
    let list = Some(("https://list.invalid/a.txt", "api.example.com\n"));

    let spec = build(&rules, SplitDnsMatchMode::SpecificityFirst, list);
    // Longer suffix from list rule beats shorter single-domain rule
    assert_eq!(
        endpoint(&spec, "v1.API.Example.COM").as_deref(),
        Some("udp://10.0.0.2:53")
    );
    // full: exact beats suffix of same length
    assert_eq!(
        endpoint(&spec, "www.example.com").as_deref(),
        Some("udp://10.0.0.3:53")
    );
    assert_eq!(
        endpoint(&spec, "a.www.example.com").as_deref(),
        Some("udp://10.0.0.1:53")
    );
    // Exclusion on rule 3 falls through to rule 4
    assert_eq!(
        endpoint(&spec, "x.skip.example.net").as_deref(),
        Some("udp://10.0.0.5:53")
    );
    assert_eq!(
        endpoint(&spec, "other.example.net").as_deref(),
        Some("udp://10.0.0.4:53")
    );
    // keyword-only match
    assert_eq!(
        endpoint(&spec, "abczzz.org").as_deref(),
        Some("udp://10.0.0.5:53")
    );

    let order = build(&rules, SplitDnsMatchMode::ConfigOrder, list);
    assert_eq!(
        endpoint(&order, "v1.api.example.com").as_deref(),
        Some("udp://10.0.0.1:53")
    );
    assert_eq!(
        endpoint(&order, "x.skip.example.net").as_deref(),
        Some("udp://10.0.0.5:53")
    );

    // resolve() fast path agrees with resolve_plan()
    for d in ["v1.api.example.com", "www.example.com", "other.example.net"] {
        let plan = spec
            .resolve_plan(&SplitQueryContext::domain_only(d))
            .expect("plan");
        assert_eq!(
            plan.primary.pool.health_snapshot()[0].endpoint,
            endpoint(&spec, d).unwrap()
        );
    }
}

#[test]
fn test_unified_trie_many_routes() {
    let rules: Vec<SplitDnsRule> = (0..300)
        .map(|i| {
            rule(
                &format!("r{i}.test"),
                &format!("udp://10.1.{}.{}:53", i / 250, i % 250),
            )
        })
        .collect();
    let router = build(&rules, SplitDnsMatchMode::ConfigOrder, None);
    assert_eq!(
        endpoint(&router, "a.r299.test").as_deref(),
        Some("udp://10.1.1.49:53")
    );
    assert!(router.resolve("r300.test").is_none());
}
