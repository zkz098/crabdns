use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use crabdns_core::{BlockMode, UpstreamPool, validate_client_id};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::RouterState;
use crate::auth::{hash_password, is_https_request, session_cookie_header};

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct SetupStatusResponse {
    pub setup_required: bool,
    pub listen_dns: String,
    pub listen_web: String,
    pub listen_web_tls: Option<String>,
    pub listen_dot: Option<String>,
    pub listen_doq: Option<String>,
    pub tls_configured: bool,
    pub upstreams: Vec<String>,
    pub block_mode: BlockMode,
    pub dnssec_enabled: bool,
    pub web_username: String,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct SetupCompletePayload {
    #[serde(default)]
    pub skip: bool,
    #[serde(default)]
    pub enable_auth: bool,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub upstreams: Option<Vec<String>>,
    #[serde(default)]
    pub block_mode: Option<BlockMode>,
    #[serde(default)]
    pub dnssec_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct SetupCompleteResponse {
    pub status: String,
    pub auth_enabled: bool,
    pub authenticated: bool,
    pub username: String,
}

#[derive(Debug, Deserialize, TS)]
#[ts(export)]
pub struct PortCheckRequest {
    #[serde(default)]
    pub dns_addr: Option<String>,
    #[serde(default)]
    pub web_addr: Option<String>,
    #[serde(default)]
    pub web_tls_addr: Option<String>,
    #[serde(default)]
    pub dot_addr: Option<String>,
    #[serde(default)]
    pub doq_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct PortCheckItem {
    pub key: String,
    pub addr: String,
    pub available: bool,
    pub in_use_by_self: bool,
    pub reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct PortCheckResponse {
    pub results: Vec<PortCheckItem>,
}

pub async fn get_setup_status(State(state): State<RouterState>) -> Json<SetupStatusResponse> {
    let cfg = state.app.config.load();
    let setup_required = !cfg.setup_completed && !cfg.web_auth_enabled;
    if !setup_required {
        return Json(SetupStatusResponse {
            setup_required: false,
            listen_dns: String::new(),
            listen_web: String::new(),
            listen_web_tls: None,
            listen_dot: None,
            listen_doq: None,
            tls_configured: false,
            upstreams: Vec::new(),
            block_mode: cfg.block_mode,
            dnssec_enabled: false,
            web_username: String::new(),
        });
    }
    let tls_configured = cfg.tls_cert_path.is_some() && cfg.tls_key_path.is_some();
    Json(SetupStatusResponse {
        setup_required: true,
        listen_dns: cfg.bootstrap.listen_dns.to_string(),
        listen_web: cfg.bootstrap.listen_web.to_string(),
        listen_web_tls: cfg.bootstrap.listen_web_tls.map(|a| a.to_string()),
        listen_dot: cfg.bootstrap.listen_dot.map(|a| a.to_string()),
        listen_doq: cfg.bootstrap.listen_doq.map(|a| a.to_string()),
        tls_configured,
        upstreams: cfg.upstreams.clone(),
        block_mode: cfg.block_mode,
        dnssec_enabled: cfg.dnssec_enabled,
        web_username: cfg.web_username.clone(),
    })
}

async fn apply_setup_auth(
    next: &mut crabdns_core::Config,
    payload: &SetupCompletePayload,
) -> Result<(), (StatusCode, String)> {
    if !payload.enable_auth {
        return Ok(());
    }
    let username = payload
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&next.web_username)
        .to_string();
    if username.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username cannot be empty".to_string(),
        ));
    }
    let Some(password) = payload
        .password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password is required to enable authentication".to_string(),
        ));
    };
    let pw_owned = password.to_string();
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw_owned))
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    next.web_auth_enabled = true;
    next.web_username = username;
    next.web_password_hash = hash;
    Ok(())
}

fn apply_setup_dns(
    state: &RouterState,
    next: &mut crabdns_core::Config,
    payload: SetupCompletePayload,
) -> Result<(), (StatusCode, String)> {
    if let Some(raw_upstreams) = payload.upstreams {
        let cleaned: Vec<String> = raw_upstreams
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if cleaned.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "At least one upstream DNS server is required".to_string(),
            ));
        }
        let next_pool = UpstreamPool::new_with_bootstrap(
            &cleaned,
            next.upstream_timeout_ms,
            next.upstream_strategy,
            &next.bootstrap_dns,
        )
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
        state.app.pipeline.swap_upstream(next_pool);
        next.upstreams = cleaned;
    }
    if let Some(mode) = payload.block_mode {
        next.block_mode = mode;
        state.app.pipeline.set_block_mode(mode);
    }
    if let Some(dnssec) = payload.dnssec_enabled {
        next.dnssec_enabled = dnssec;
        state.app.pipeline.set_dnssec_enabled(dnssec);
    }
    Ok(())
}

pub async fn complete_setup(
    State(state): State<RouterState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(payload): Json<SetupCompletePayload>,
) -> Response {
    let _config_guard = state.app.storage.config_lock().lock().await;
    let current = state.app.config.load_full();
    if current.setup_completed || current.web_auth_enabled {
        return err_response(
            StatusCode::CONFLICT,
            "Initial setup has already been completed",
        );
    }

    let mut next = (*current).clone();
    next.setup_completed = true;

    if !payload.skip {
        if let Err((status, msg)) = apply_setup_auth(&mut next, &payload).await {
            return err_response(status, &msg);
        }
        if let Err((status, msg)) = apply_setup_dns(&state, &mut next, payload) {
            return err_response(status, &msg);
        }
    }

    let storage = Arc::clone(&state.app.storage);
    let to_save = next.clone();
    match tokio::task::spawn_blocking(move || storage.save_config(&to_save.runtime)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        Err(err) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }

    let auth_enabled = next.web_auth_enabled;
    let username = next.web_username.clone();
    let secure_cookie = is_https_request(&next.trusted_proxies, connect_info.as_ref(), &headers);
    state.app.config.store(Arc::new(next));

    let mut resp = Json(SetupCompleteResponse {
        status: "ok".to_string(),
        auth_enabled,
        authenticated: true,
        username: username.clone(),
    })
    .into_response();

    if auth_enabled && let Some(token) = state.sessions.create_session(&username) {
        let cookie = session_cookie_header(&token, secure_cookie);
        if let Ok(val) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, val);
        }
    }

    resp
}

#[derive(Clone, Copy)]
enum TransportKind {
    Tcp,
    Udp,
    Both,
}

fn map_bind_error(err: &std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::AddrInUse => "in_use".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission_denied".to_string(),
        _ => "other".to_string(),
    }
}

fn probe_single_port(
    key: &str,
    raw_addr: &str,
    transport: TransportKind,
    current_bound: Option<SocketAddr>,
) -> PortCheckItem {
    let trimmed = raw_addr.trim();
    let parsed: SocketAddr = match trimmed.parse() {
        Ok(addr) => addr,
        Err(err) => {
            return PortCheckItem {
                key: key.to_string(),
                addr: trimmed.to_string(),
                available: false,
                in_use_by_self: false,
                reason: Some("invalid_addr".to_string()),
                error: Some(err.to_string()),
            };
        }
    };

    if current_bound == Some(parsed) {
        return PortCheckItem {
            key: key.to_string(),
            addr: parsed.to_string(),
            available: true,
            in_use_by_self: true,
            reason: Some("self".to_string()),
            error: None,
        };
    }

    if matches!(transport, TransportKind::Udp | TransportKind::Both)
        && let Err(err) = std::net::UdpSocket::bind(parsed)
    {
        return PortCheckItem {
            key: key.to_string(),
            addr: parsed.to_string(),
            available: false,
            in_use_by_self: false,
            reason: Some(map_bind_error(&err)),
            error: Some(err.to_string()),
        };
    }

    if matches!(transport, TransportKind::Tcp | TransportKind::Both)
        && let Err(err) = std::net::TcpListener::bind(parsed)
    {
        return PortCheckItem {
            key: key.to_string(),
            addr: parsed.to_string(),
            available: false,
            in_use_by_self: false,
            reason: Some(map_bind_error(&err)),
            error: Some(err.to_string()),
        };
    }

    PortCheckItem {
        key: key.to_string(),
        addr: parsed.to_string(),
        available: true,
        in_use_by_self: false,
        reason: None,
        error: None,
    }
}

pub async fn check_ports(
    State(state): State<RouterState>,
    Json(payload): Json<PortCheckRequest>,
) -> Json<PortCheckResponse> {
    let cfg = state.app.config.load();
    let candidates = [
        (
            "dns",
            payload.dns_addr,
            TransportKind::Both,
            Some(cfg.bootstrap.listen_dns),
        ),
        (
            "web",
            payload.web_addr,
            TransportKind::Tcp,
            Some(cfg.bootstrap.listen_web),
        ),
        (
            "web_tls",
            payload.web_tls_addr,
            TransportKind::Tcp,
            cfg.bootstrap.listen_web_tls,
        ),
        (
            "dot",
            payload.dot_addr,
            TransportKind::Tcp,
            cfg.bootstrap.listen_dot,
        ),
        (
            "doq",
            payload.doq_addr,
            TransportKind::Udp,
            cfg.bootstrap.listen_doq,
        ),
    ];

    let mut results = Vec::new();
    for (key, maybe_addr, transport, current_bound) in candidates {
        if let Some(addr) = maybe_addr
            && !addr.trim().is_empty()
        {
            results.push(probe_single_port(key, &addr, transport, current_bound));
        }
    }

    Json(PortCheckResponse { results })
}

#[derive(Debug, Deserialize)]
pub struct MobileconfigQuery {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub profile_name: Option<String>,
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn strip_host_port(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((v6, _)) = rest.split_once(']')
    {
        return v6;
    }
    if let Some((host, port)) = trimmed.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
        && !host.contains(':')
    {
        return host;
    }
    trimmed
}

fn make_uuid(seed: u64) -> String {
    let nanos = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .cast_unsigned();
    let a = nanos ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let b = a.rotate_left(17) ^ 0xBF58_476D_1CE4_E5B9;
    let p1 = (a >> 32) as u32;
    let p2 = (a >> 16) as u16;
    let p3 = ((a as u16) & 0x0FFF) | 0x4000;
    let p4 = (((b >> 48) as u16) & 0x3FFF) | 0x8000;
    let p5 = b & 0xFFFF_FFFF_FFFF;
    format!("{p1:08X}-{p2:04X}-{p3:04X}-{p4:04X}-{p5:012X}")
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

pub async fn download_mobileconfig(
    State(state): State<RouterState>,
    headers: HeaderMap,
    Query(query): Query<MobileconfigQuery>,
) -> Response {
    let cfg = state.app.config.load();
    let proto = query
        .protocol
        .as_deref()
        .unwrap_or("doh")
        .trim()
        .to_ascii_lowercase();
    if proto != "doh" && proto != "dot" {
        return err_response(StatusCode::BAD_REQUEST, "protocol must be 'doh' or 'dot'");
    }

    let raw_host = query
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            cfg.ddr_hostname
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(strip_host_port)
                .filter(|s| !s.is_empty())
        });

    let Some(host) = raw_host else {
        return err_response(
            StatusCode::BAD_REQUEST,
            "hostname is required (set ddr_hostname or pass ?hostname=...)",
        );
    };
    if host.chars().any(char::is_whitespace) {
        return err_response(
            StatusCode::BAD_REQUEST,
            "hostname must not contain whitespace",
        );
    }

    let client_id = match query
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_cid) => match validate_client_id(raw_cid) {
            Ok(cid) => Some(cid),
            Err(err) => return err_response(StatusCode::BAD_REQUEST, &err.to_string()),
        },
        None => None,
    };

    let display_name = query
        .profile_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(
            || match &client_id {
                Some(cid) => format!("CrabDNS ({cid})"),
                None => "CrabDNS".to_string(),
            },
            ToString::to_string,
        );

    let plist = build_mobileconfig_plist(&proto, host, client_id.as_deref(), &display_name);
    let filename = match &client_id {
        Some(cid) => format!("crabdns-{cid}-{proto}.mobileconfig"),
        None => format!("crabdns-{proto}.mobileconfig"),
    };
    let disposition = format!("attachment; filename=\"{filename}\"");

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/x-apple-aspen-config; charset=utf-8",
            ),
            (header::CONTENT_DISPOSITION, disposition.as_str()),
        ],
        plist,
    )
        .into_response()
}

pub fn build_mobileconfig_plist(
    proto: &str,
    host: &str,
    client_id: Option<&str>,
    display_name: &str,
) -> String {
    let esc_name = xml_escape(display_name);
    let esc_host = xml_escape(host);
    let id_suffix = client_id.map_or_else(|| "default".to_string(), xml_escape);
    let payload_uuid = make_uuid(1);
    let root_uuid = make_uuid(2);

    let dns_settings_block = if proto == "dot" {
        let server_name = match client_id {
            Some(cid) => format!("{}.{esc_host}", xml_escape(cid)),
            None => esc_host,
        };
        format!(
            "            <key>DNSProtocol</key>\n            \
             <string>TLS</string>\n            \
             <key>ServerName</key>\n            \
             <string>{server_name}</string>"
        )
    } else {
        let server_url = match client_id {
            Some(cid) => format!("https://{esc_host}/dns-query/{}", xml_escape(cid)),
            None => format!("https://{esc_host}/dns-query"),
        };
        format!(
            "            <key>DNSProtocol</key>\n            \
             <string>HTTPS</string>\n            \
             <key>ServerURL</key>\n            \
             <string>{server_url}</string>"
        )
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
{dns_settings_block}
            </dict>
            <key>PayloadDescription</key>
            <string>Configures encrypted DNS via CrabDNS</string>
            <key>PayloadDisplayName</key>
            <string>{esc_name}</string>
            <key>PayloadIdentifier</key>
            <string>org.crabdns.dns-settings.{id_suffix}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Encrypted DNS configuration profile generated by CrabDNS</string>
    <key>PayloadDisplayName</key>
    <string>{esc_name}</string>
    <key>PayloadIdentifier</key>
    <string>org.crabdns.profile.{id_suffix}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{root_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mobileconfig_doh_and_dot() {
        let doh = build_mobileconfig_plist("doh", "dns.example.com", Some("iphone"), "CrabDNS");
        assert!(doh.contains("<string>HTTPS</string>"));
        assert!(doh.contains("<string>https://dns.example.com/dns-query/iphone</string>"));
        assert!(doh.contains("<string>com.apple.dnsSettings.managed</string>"));

        let dot = build_mobileconfig_plist("dot", "dns.example.com", Some("mac"), "CrabDNS");
        assert!(dot.contains("<string>TLS</string>"));
        assert!(dot.contains("<string>mac.dns.example.com</string>"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a&b<c>\"'"), "a&amp;b&lt;c&gt;&quot;&apos;");
    }
}
