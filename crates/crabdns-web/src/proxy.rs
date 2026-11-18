use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, Extension};
use axum::http::HeaderMap;
use crabdns_core::acl::parse_cidr_list;

/// Extracts the client IP address, honoring `X-Forwarded-For` and `X-Real-IP`
/// only when the direct TCP peer belongs to `trusted_proxies`.
pub fn extract_client_ip(
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: &HeaderMap,
    trusted_proxies: &[String],
) -> IpAddr {
    let direct_ip = connect_info.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |Extension(ci)| ci.0.ip());
    if trusted_proxies.is_empty() {
        return direct_ip;
    }
    let Ok(nets) = parse_cidr_list(trusted_proxies) else {
        return direct_ip;
    };
    let is_trusted = |ip: IpAddr| nets.iter().any(|net| net.contains(ip));
    if !is_trusted(direct_ip) {
        return direct_ip;
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let mut parsed: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|part| part.trim().parse::<IpAddr>().ok())
            .collect();
        if !parsed.is_empty() {
            // Walk from right to left and return the first untrusted hop.
            while let Some(ip) = parsed.pop() {
                if !is_trusted(ip) || parsed.is_empty() {
                    return ip;
                }
            }
        }
    }

    if let Some(real_ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return real_ip;
    }

    direct_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_client_ip_untrusted_ignores_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        let ci = Some(Extension(ConnectInfo(SocketAddr::new(
            "198.51.100.9".parse().unwrap(),
            1234,
        ))));
        assert_eq!(
            extract_client_ip(ci, &headers, &[]),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            extract_client_ip(ci, &headers, &["127.0.0.1/32".to_string()]),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_extract_client_ip_trusted_proxy_xff_and_real_ip() {
        let trusted = vec!["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()];
        let ci = Some(Extension(ConnectInfo(SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            1234,
        ))));

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.2"),
        );
        assert_eq!(
            extract_client_ip(ci, &headers, &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );

        let mut real_headers = HeaderMap::new();
        real_headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.44"));
        assert_eq!(
            extract_client_ip(ci, &real_headers, &trusted),
            "198.51.100.44".parse::<IpAddr>().unwrap()
        );
    }
}
