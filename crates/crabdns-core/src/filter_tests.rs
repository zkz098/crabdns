use super::*;
use hickory_proto::rr::RecordType;

#[test]
fn test_adguard_block_and_allow_precedence() {
    let rules = vec![
        "! comment line".to_string(),
        "||ads.example.com^".to_string(),
        "@@||safe.ads.example.com^".to_string(),
        "||malware.example.com^$important".to_string(),
        "@@||malware.example.com^".to_string(),
    ];
    let engine = FilterEngine::new(&rules);

    assert_eq!(
        engine.evaluate("ads.example.com").action,
        FilterAction::Block
    );
    assert_eq!(
        engine.evaluate("sub.ads.example.com").action,
        FilterAction::Block
    );
    assert_eq!(
        engine.evaluate("safe.ads.example.com").action,
        FilterAction::Allow
    );
    assert_eq!(
        engine.evaluate("malware.example.com").action,
        FilterAction::Block
    );
    assert_eq!(engine.evaluate("example.com").action, FilterAction::Allow);
}

#[test]
fn test_hosts_and_rewrite_rules() {
    let rules = vec![
        "0.0.0.0 tracker.test".to_string(),
        "||nas.local^$dnsrewrite=192.168.1.50".to_string(),
        "||nas.local^$dnsrewrite=fd00::50".to_string(),
        "||alias.local^$dnsrewrite=CNAME;nas.local".to_string(),
        "||info.local^$dnsrewrite=TXT;crabdns-ok".to_string(),
        "*.wild.test".to_string(),
    ];
    let engine = FilterEngine::new(&rules);

    assert_eq!(engine.evaluate("tracker.test").action, FilterAction::Block);
    let a_ctx = FilterQueryContext {
        domain: "nas.local",
        qtype: Some(RecordType::A),
        ..Default::default()
    };
    assert_eq!(
        engine.evaluate_with_context(&a_ctx).action,
        FilterAction::Rewrite(RewriteAction::Ip("192.168.1.50".parse().expect("valid ip")))
    );
    let aaaa_ctx = FilterQueryContext {
        domain: "nas.local",
        qtype: Some(RecordType::AAAA),
        ..Default::default()
    };
    assert_eq!(
        engine.evaluate_with_context(&aaaa_ctx).action,
        FilterAction::Rewrite(RewriteAction::Ip("fd00::50".parse().expect("valid ipv6")))
    );
    assert_eq!(
        engine.evaluate("alias.local").action,
        FilterAction::Rewrite(RewriteAction::Cname("nas.local".to_string()))
    );
    assert_eq!(
        engine.evaluate("info.local").action,
        FilterAction::Rewrite(RewriteAction::Txt("crabdns-ok".to_string()))
    );
    assert_eq!(engine.evaluate("wild.test").action, FilterAction::Allow);
    assert_eq!(engine.evaluate("sub.wild.test").action, FilterAction::Block);
}

#[test]
fn test_dnstype_client_denyallow_and_regex_modifiers() {
    let rules = vec![
        "||only-aaaa.example.com^$dnstype=AAAA".to_string(),
        "||no-https.example.com^$dnstype=~A|~AAAA".to_string(),
        "||games.example.com^$client=192.168.10.0/24|'kid-phone'".to_string(),
        "||shop.example.com^$denyallow=pay.shop.example.com|cdn.shop.example.com".to_string(),
        r"/^ad-[0-9]+\.tracker\.net$/".to_string(),
        r"@@/^ad-0+\.tracker\.net$/".to_string(),
    ];
    let engine = FilterEngine::new(&rules);

    let ctx_a = FilterQueryContext {
        domain: "only-aaaa.example.com",
        qtype: Some(RecordType::A),
        ..Default::default()
    };
    let ctx_aaaa = FilterQueryContext {
        domain: "only-aaaa.example.com",
        qtype: Some(RecordType::AAAA),
        ..Default::default()
    };
    assert_eq!(
        engine.evaluate_with_context(&ctx_a).action,
        FilterAction::Allow
    );
    assert_eq!(
        engine.evaluate_with_context(&ctx_aaaa).action,
        FilterAction::Block
    );

    let ctx_https = FilterQueryContext {
        domain: "no-https.example.com",
        qtype: Some(RecordType::HTTPS),
        ..Default::default()
    };
    assert_eq!(
        engine.evaluate_with_context(&ctx_https).action,
        FilterAction::Block
    );

    let kid_ctx = FilterQueryContext {
        domain: "games.example.com",
        client_ip: Some("192.168.10.22".parse().unwrap()),
        ..Default::default()
    };
    let parent_ctx = FilterQueryContext {
        domain: "games.example.com",
        client_ip: Some("192.168.1.5".parse().unwrap()),
        ..Default::default()
    };
    assert_eq!(
        engine.evaluate_with_context(&kid_ctx).action,
        FilterAction::Block
    );
    assert_eq!(
        engine.evaluate_with_context(&parent_ctx).action,
        FilterAction::Allow
    );

    assert_eq!(
        engine.evaluate("shop.example.com").action,
        FilterAction::Block
    );
    assert_eq!(
        engine.evaluate("pay.shop.example.com").action,
        FilterAction::Allow
    );
    assert_eq!(
        engine.evaluate("img.cdn.shop.example.com").action,
        FilterAction::Allow
    );

    assert_eq!(
        engine.evaluate("ad-42.tracker.net").action,
        FilterAction::Block
    );
    assert_eq!(
        engine.evaluate("ad-00.tracker.net").action,
        FilterAction::Allow
    );
    assert_eq!(
        engine.evaluate("blog.tracker.net").action,
        FilterAction::Allow
    );
}

#[test]
fn test_hot_reload_and_count() {
    let sub1 = "||ad1.example.com^\n! comment\n0.0.0.0 ad2.example.com\n/^ad-[0-9]+\\.test$/\n"
        .to_string();
    assert_eq!(FilterEngine::count_rules_in_text(&sub1).total_rules, 3);

    let engine = FilterEngine::new(&["||old.example.com^".to_string()]);
    assert_eq!(
        engine.evaluate("old.example.com").action,
        FilterAction::Block
    );
    let stats = engine.reload_from_text("||new.example.com^\n");
    assert_eq!(stats.block_rules, 1);
    assert_eq!(
        engine.evaluate("old.example.com").action,
        FilterAction::Allow
    );
    assert_eq!(
        engine.evaluate("new.example.com").action,
        FilterAction::Block
    );
}

#[test]
fn test_filter_rejects_overlong_domain_and_counts_without_trie() {
    let overlong = format!("||{}example.com^", "a.".repeat(200));
    assert!(!is_valid_domain_token(&"a.".repeat(200)));

    let mixed = format!(
        "! comment\n\
         {overlong}\n\
         ||ad.example.com^\n\
         @@||ok.example.com^\n\
         ||imp.example.com^$important\n\
         ||rw.example.com^$dnsrewrite=1.2.3.4\n\
         0.0.0.0 host1.test host2.test\n\
         *.wild.example.com\n\
         /^rx-[0-9]+\\.example\\.com$/\n"
    );
    let counted = FilterEngine::count_rules_in_text(&mixed);
    let built = RuleSet::from_named_lines("check", mixed.lines()).stats;
    assert_eq!(counted.total_rules, built.total_rules);
    assert_eq!(counted.block_rules, built.block_rules);
    assert_eq!(counted.allow_rules, built.allow_rules);
    assert_eq!(counted.rewrite_rules, built.rewrite_rules);
    assert_eq!(counted.total_rules, 8);
}

#[test]
fn test_trie_node_dedup_preserves_later_source_and_distinct_variants() {
    let engine = FilterEngine::new(&[]);
    let sub1 = "0.0.0.0 dup.example.com\n||sub.example.com^\n".to_string();
    let sub2 = "127.0.0.1 dup.example.com\n0.0.0.0 sub.example.com\n".to_string();
    let custom = "||dup.example.com^$dnstype=A\n||sub.example.com^\n";

    let stats = engine.reload_from_named_sources(
        custom,
        true,
        &[("sub1".to_string(), sub1), ("sub2".to_string(), sub2)],
    );

    // Effective unique rules:
    // 1. dup.example.com (Exact, replaced by sub2)
    // 2. sub.example.com (DomainAndSubdomains, replaced by custom)
    // 3. sub.example.com (Exact, from sub2)
    // 4. dup.example.com (DomainAndSubdomains + $dnstype=A, from custom)
    assert_eq!(stats.total_rules, 4);
    assert_eq!(stats.block_rules, 4);

    let dup_dec = engine.evaluate("dup.example.com");
    assert_eq!(dup_dec.action, FilterAction::Block);
    assert_eq!(
        dup_dec.matched_rule.as_deref(),
        Some("127.0.0.1 dup.example.com")
    );
    assert_eq!(dup_dec.matched_list.as_deref(), Some("sub2"));

    let sub_dec = engine.evaluate("a.sub.example.com");
    assert_eq!(sub_dec.action, FilterAction::Block);
    assert_eq!(sub_dec.matched_rule.as_deref(), Some("||sub.example.com^"));
    assert_eq!(sub_dec.matched_list.as_deref(), Some("custom"));
}
