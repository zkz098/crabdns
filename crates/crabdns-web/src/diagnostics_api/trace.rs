use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use crabdns_core::{QueryContext, QueryOutcome, QueryProtocol};

use super::types::{
    DiagnosticStatus, DomainTraceRequest, DomainTraceResponse, DomainTraceStep,
    build_dns_query_with_type,
};
use crate::RouterState;

pub(crate) fn parse_qtype_code(qtype: &str) -> Option<(&'static str, u16)> {
    match qtype.trim().to_ascii_uppercase().as_str() {
        "" | "A" => Some(("A", 1)),
        "NS" => Some(("NS", 2)),
        "CNAME" => Some(("CNAME", 5)),
        "SOA" => Some(("SOA", 6)),
        "PTR" => Some(("PTR", 12)),
        "MX" => Some(("MX", 15)),
        "TXT" => Some(("TXT", 16)),
        "AAAA" => Some(("AAAA", 28)),
        "SRV" => Some(("SRV", 33)),
        "HTTPS" => Some(("HTTPS", 65)),
        "ANY" => Some(("ANY", 255)),
        _ => None,
    }
}

fn rcode_name(code: u8) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

fn outcome_label(outcome: &QueryOutcome) -> &'static str {
    match outcome {
        QueryOutcome::Cached => "Cached",
        QueryOutcome::Blocked => "Blocked",
        QueryOutcome::Rewritten => "Rewritten",
        QueryOutcome::Forwarded => "Forwarded",
        QueryOutcome::Error => "Error",
    }
}

fn match_split_dns_rule_summary(
    domain: &str,
    rules: &[crabdns_core::SplitDnsRule],
) -> Option<String> {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let pat = rule
            .domain
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let matched = !pat.is_empty() && (lower == pat || lower.ends_with(&format!(".{pat}")));
        if matched {
            let upstreams = rule.upstreams.join(", ");
            let label = match rule
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(name) => format!("{name} ({upstreams})"),
                None => upstreams,
            };
            return Some(label);
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
pub async fn trace_domain_resolution(
    State(state): State<RouterState>,
    Json(req): Json<DomainTraceRequest>,
) -> Result<Json<DomainTraceResponse>, (StatusCode, Json<serde_json::Value>)> {
    let clean_domain = req.domain.trim().trim_end_matches('.').to_string();
    if clean_domain.is_empty()
        || clean_domain.len() > 253
        || clean_domain.chars().any(char::is_whitespace)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid domain name" })),
        ));
    }

    let Some((qtype_norm, qtype_code)) = parse_qtype_code(&req.qtype) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Unsupported qtype: {}", req.qtype) })),
        ));
    };

    let cfg = state.app.config.load();
    let split_dns_rule = match_split_dns_rule_summary(&clean_domain, &cfg.split_dns);

    let mut rx = state.app.live_tx.subscribe();
    let query_bytes = build_dns_query_with_type(0xD1A6, &clean_domain, qtype_code);
    let ctx = QueryContext {
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        protocol: QueryProtocol::Doh,
        client_id: Some("diagnostics-trace".to_string()),
    };

    let start = Instant::now();
    let packet_res = state
        .app
        .pipeline
        .handle_packet_with_context(&query_bytes, ctx)
        .await;
    let fallback_elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut matched_event = None;
    let deadline = tokio::time::sleep(Duration::from_millis(25));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            recv = rx.recv() => {
                match recv {
                    Ok(ev) if ev.domain.eq_ignore_ascii_case(&clean_domain) && ev.qtype == qtype_norm => {
                        matched_event = Some(ev);
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            () = &mut deadline => break,
        }
    }

    let (rcode, outcome, elapsed_ms, upstream, matched_rule, matched_list, answers) =
        if let Some(ev) = matched_event {
            #[allow(clippy::cast_precision_loss)]
            let ms = ev.elapsed_us as f64 / 1000.0;
            (
                ev.rcode,
                outcome_label(&ev.outcome).to_string(),
                ms,
                ev.upstream,
                ev.matched_rule,
                ev.matched_list,
                ev.answers,
            )
        } else {
            let rcode = match &packet_res {
                Ok(resp) if resp.len() >= 4 => rcode_name(resp[3] & 0x0F).to_string(),
                Ok(_) => "NOERROR".to_string(),
                Err(_) => "SERVFAIL".to_string(),
            };
            let outcome = if packet_res.is_ok() {
                "Completed".to_string()
            } else {
                "Error".to_string()
            };
            (
                rcode,
                outcome,
                fallback_elapsed_ms,
                None,
                None,
                None,
                Vec::new(),
            )
        };

    let mut steps = Vec::new();
    steps.push(DomainTraceStep {
        stage: "filter".to_string(),
        status: if outcome == "Blocked" {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Ok
        },
        detail: if let Some(ref rule) = matched_rule {
            format!("Matched rule: {rule}")
        } else {
            "No blocking or rewrite rule matched".to_string()
        },
    });

    steps.push(DomainTraceStep {
        stage: "routing".to_string(),
        status: DiagnosticStatus::Ok,
        detail: if let Some(ref split) = split_dns_rule {
            format!("Matched Split DNS: {split}")
        } else if outcome == "Cached" {
            "Served from local DNS cache".to_string()
        } else {
            "Default upstream pool".to_string()
        },
    });

    steps.push(DomainTraceStep {
        stage: "result".to_string(),
        status: if outcome == "Error" || rcode == "SERVFAIL" {
            DiagnosticStatus::Error
        } else {
            DiagnosticStatus::Ok
        },
        detail: format!(
            "{outcome} ({rcode}) in {elapsed_ms:.1} ms{}",
            upstream.as_ref().map_or_default(|u| format!(" via {u}"))
        ),
    });

    Ok(Json(DomainTraceResponse {
        domain: clean_domain,
        qtype: qtype_norm.to_string(),
        rcode,
        outcome,
        elapsed_ms,
        upstream,
        matched_rule,
        matched_list,
        split_dns_rule,
        answers,
        steps,
    }))
}
