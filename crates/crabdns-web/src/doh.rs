use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use crabdns_core::{QueryContext, QueryProtocol, validate_client_id};
use serde::Deserialize;

use crate::RouterState;
use crate::proxy::extract_client_ip;

const DNS_MESSAGE_MIME: &str = "application/dns-message";
pub(crate) const MAX_DOH_PACKET_BYTES: usize = 65_535;
const DOH_QUERY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
pub struct DohQuery {
    pub dns: Option<String>,
}

pub async fn doh_get(
    State(state): State<RouterState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(query): Query<DohQuery>,
) -> Response {
    doh_get_inner(&state, connect_info, &headers, &query, None).await
}

pub async fn doh_get_client(
    State(state): State<RouterState>,
    Path(raw_client_id): Path<String>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(query): Query<DohQuery>,
) -> Response {
    let Ok(client_id) = validate_client_id(&raw_client_id) else {
        return (StatusCode::BAD_REQUEST, "invalid client_id").into_response();
    };
    doh_get_inner(&state, connect_info, &headers, &query, Some(client_id)).await
}

async fn doh_get_inner(
    state: &RouterState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
    query: &DohQuery,
    client_id: Option<String>,
) -> Response {
    if !state.app.config.load().doh_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(encoded) = query.dns.as_deref() else {
        return (StatusCode::BAD_REQUEST, "missing 'dns' query parameter").into_response();
    };
    let Some(packet) = decode_base64url(encoded) else {
        return (StatusCode::BAD_REQUEST, "invalid base64url 'dns' parameter").into_response();
    };
    let client = client_addr(state, connect_info, headers);
    handle_doh_packet(state, &packet, client, client_id).await
}

pub async fn doh_post(
    State(state): State<RouterState>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    doh_post_inner(&state, connect_info, &headers, &body, None).await
}

pub async fn doh_post_client(
    State(state): State<RouterState>,
    Path(raw_client_id): Path<String>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(client_id) = validate_client_id(&raw_client_id) else {
        return (StatusCode::BAD_REQUEST, "invalid client_id").into_response();
    };
    doh_post_inner(&state, connect_info, &headers, &body, Some(client_id)).await
}

async fn doh_post_inner(
    state: &RouterState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
    body: &Bytes,
    client_id: Option<String>,
) -> Response {
    if !state.app.config.load().doh_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ct) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        let media_type = ct.split(';').next().unwrap_or("").trim();
        if !media_type.eq_ignore_ascii_case(DNS_MESSAGE_MIME) {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "expected application/dns-message",
            )
                .into_response();
        }
    }
    let client = client_addr(state, connect_info, headers);
    handle_doh_packet(state, body, client, client_id).await
}

async fn handle_doh_packet(
    state: &RouterState,
    packet: &[u8],
    client: SocketAddr,
    client_id: Option<String>,
) -> Response {
    if packet.is_empty() || packet.len() > MAX_DOH_PACKET_BYTES {
        return (StatusCode::BAD_REQUEST, "invalid DNS message size").into_response();
    }
    let Ok(_permit) = Arc::clone(&state.doh_limiter).try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "DoH inflight capacity reached",
        )
            .into_response();
    };
    let ctx = QueryContext {
        client_addr: client,
        protocol: QueryProtocol::Doh,
        client_id,
    };
    match tokio::time::timeout(
        DOH_QUERY_TIMEOUT,
        state.app.pipeline.handle_packet_with_context(packet, ctx),
    )
    .await
    {
        Ok(Ok(resp)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, DNS_MESSAGE_MIME),
                (header::CACHE_CONTROL, "no-store"),
            ],
            resp,
        )
            .into_response(),
        Ok(Err(err)) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "DNS query timed out").into_response(),
    }
}

fn client_addr(
    state: &RouterState,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
) -> SocketAddr {
    let trusted = &state.app.config.load().trusted_proxies;
    SocketAddr::new(extract_client_ip(connect_info, headers, trusted), 0)
}

pub fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for byte in trimmed.bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64url() {
        assert_eq!(decode_base64url("SGVsbG8").unwrap(), b"Hello");
        assert_eq!(decode_base64url("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(decode_base64url("_-8").unwrap(), &[0xff, 0xef]);
        assert!(decode_base64url("bad!char").is_none());
    }
}
