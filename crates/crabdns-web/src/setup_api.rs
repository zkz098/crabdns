use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use crabdns_core::validate_client_id;
use serde::Deserialize;

use crate::RouterState;

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
