use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::error::{CoreError, Result};
use crate::upstream_transport::{
    ConnPool, UpstreamEndpoint, split_host_port, tcp_roundtrip, try_exchange_dot_pooled,
    tx_id_matches,
};

const MAX_DOH_RESPONSE_BYTES: usize = 65_535;
const MAX_HTTP_HEADER_BYTES: usize = 16_384;
const MAX_POOLED_RETRIES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedProxy {
    Http {
        host: String,
        port: u16,
        basic_auth: Option<String>,
    },
    Socks5 {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
        resolve_remote: bool,
    },
}

impl ParsedProxy {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| CoreError::Config(format!("invalid proxy URL '{trimmed}'")))?;
        let scheme_lower = scheme.to_ascii_lowercase();
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return Err(CoreError::Config(format!(
                "missing proxy host in '{trimmed}'"
            )));
        }
        let (creds, hostport) = match authority.rsplit_once('@') {
            Some((c, hp)) => (Some(c), hp),
            None => (None, authority),
        };
        if hostport.is_empty() {
            return Err(CoreError::Config(format!(
                "missing proxy host in '{trimmed}'"
            )));
        }

        let default_port = match scheme_lower.as_str() {
            "http" => 8080,
            "socks5" | "socks5h" => 1080,
            other => {
                return Err(CoreError::Config(format!(
                    "unsupported proxy scheme '{other}' (expected http://, socks5://, or socks5h://)"
                )));
            }
        };
        let (host_raw, port) = split_host_port(hostport, default_port);
        let host = host_raw.trim_matches(['[', ']']).to_string();
        if host.is_empty() || port == 0 {
            return Err(CoreError::Config(format!(
                "invalid proxy host/port in '{trimmed}'"
            )));
        }

        let parsed_creds = creds.and_then(|c| {
            let (u, p) = c.split_once(':').unwrap_or((c, ""));
            (!u.is_empty()).then(|| (u.to_string(), p.to_string()))
        });

        match scheme_lower.as_str() {
            "http" => {
                let basic_auth = parsed_creds.map(|(u, p)| {
                    format!("Basic {}", base64_encode(format!("{u}:{p}").as_bytes()))
                });
                Ok(Self::Http {
                    host,
                    port,
                    basic_auth,
                })
            }
            "socks5" => Ok(Self::Socks5 {
                host,
                port,
                auth: parsed_creds,
                resolve_remote: false,
            }),
            "socks5h" => Ok(Self::Socks5 {
                host,
                port,
                auth: parsed_creds,
                resolve_remote: true,
            }),
            _ => unreachable!(),
        }
    }

    pub(crate) fn proxy_host_port(&self) -> (&str, u16) {
        match self {
            Self::Http { host, port, .. } | Self::Socks5 { host, port, .. } => (host, *port),
        }
    }
}

pub(crate) async fn connect_tcp_via_proxy(
    proxy: &ParsedProxy,
    proxy_addrs: &[SocketAddr],
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addrs).await?;
    let _ = stream.set_nodelay(true);
    match proxy {
        ParsedProxy::Http { basic_auth, .. } => {
            http_connect_handshake(&mut stream, target_host, target_port, basic_auth.as_deref())
                .await?;
        }
        ParsedProxy::Socks5 { auth, .. } => {
            socks5_handshake(&mut stream, target_host, target_port, auth.as_ref()).await?;
        }
    }
    Ok(stream)
}

async fn http_connect_handshake(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    basic_auth: Option<&str>,
) -> Result<()> {
    let authority = format_host_port(target_host, target_port);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = basic_auth {
        use std::fmt::Write;
        let _ = write!(&mut req, "Proxy-Authorization: {auth}\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut header_buf = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while header_buf.len() < MAX_HTTP_HEADER_BYTES {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(CoreError::Upstream(
                "HTTP proxy closed connection during CONNECT".to_string(),
            ));
        }
        header_buf.push(byte[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header_buf.ends_with(b"\r\n\r\n") {
        return Err(CoreError::Upstream(
            "HTTP proxy CONNECT response headers too large".to_string(),
        ));
    }
    let header_str = String::from_utf8_lossy(&header_buf);
    let status_line = header_str.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        return Err(CoreError::Upstream(format!(
            "HTTP proxy CONNECT failed with status {status_line}"
        )));
    }
    Ok(())
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    auth: Option<&(String, String)>,
) -> Result<()> {
    if auth.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut greeting_resp = [0_u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 {
        return Err(CoreError::Upstream(
            "invalid SOCKS5 greeting version".to_string(),
        ));
    }
    match greeting_resp[1] {
        0x00 => {}
        0x02 => {
            let Some((user, pass)) = auth else {
                return Err(CoreError::Upstream(
                    "SOCKS5 proxy requested username/password auth".to_string(),
                ));
            };
            socks5_password_auth(stream, user, pass).await?;
        }
        0xFF => {
            return Err(CoreError::Upstream(
                "SOCKS5 proxy rejected authentication methods".to_string(),
            ));
        }
        other => {
            return Err(CoreError::Upstream(format!(
                "unsupported SOCKS5 auth method: {other}"
            )));
        }
    }

    let clean_host = target_host.trim_matches(['[', ']']);
    let mut req = Vec::with_capacity(7 + clean_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host_bytes = clean_host.as_bytes();
        let host_len = u8::try_from(host_bytes.len())
            .map_err(|_| CoreError::Upstream("SOCKS5 target hostname exceeds 255 bytes".into()))?;
        req.push(0x03);
        req.push(host_len);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut hdr = [0_u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(CoreError::Upstream(format!(
            "SOCKS5 CONNECT failed with reply code {}",
            hdr[1]
        )));
    }
    let addr_len = match hdr[3] {
        0x01 => 4_usize,
        0x04 => 16_usize,
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        other => {
            return Err(CoreError::Upstream(format!(
                "invalid SOCKS5 reply ATYP: {other}"
            )));
        }
    };
    let mut discard = vec![0_u8; addr_len + 2];
    stream.read_exact(&mut discard).await?;
    Ok(())
}

async fn socks5_password_auth(stream: &mut TcpStream, user: &str, pass: &str) -> Result<()> {
    let ulen = u8::try_from(user.len())
        .map_err(|_| CoreError::Config("SOCKS5 username exceeds 255 bytes".to_string()))?;
    let plen = u8::try_from(pass.len())
        .map_err(|_| CoreError::Config("SOCKS5 password exceeds 255 bytes".to_string()))?;
    let mut buf = Vec::with_capacity(3 + user.len() + pass.len());
    buf.push(0x01);
    buf.push(ulen);
    buf.extend_from_slice(user.as_bytes());
    buf.push(plen);
    buf.extend_from_slice(pass.as_bytes());
    stream.write_all(&buf).await?;
    let mut resp = [0_u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        return Err(CoreError::Upstream(
            "SOCKS5 username/password authentication failed".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn exchange_tcp_via_proxy_pooled(
    proxy: &ParsedProxy,
    proxy_addrs: &[SocketAddr],
    pool: &ConnPool<TcpStream>,
    target_host: &str,
    target_port: u16,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    for _ in 0..MAX_POOLED_RETRIES {
        let Some(mut stream) = pool.pop_fresh() else {
            break;
        };
        if let Ok(resp) = tcp_roundtrip(&mut stream, query_wire).await
            && tx_id_matches(query_wire, &resp)
        {
            pool.put(stream);
            return Ok(resp);
        }
    }

    let mut stream = connect_tcp_via_proxy(proxy, proxy_addrs, target_host, target_port).await?;
    let resp = tcp_roundtrip(&mut stream, query_wire).await?;
    if !tx_id_matches(query_wire, &resp) {
        return Err(CoreError::Upstream(
            "TCP DNS response transaction ID mismatch".to_string(),
        ));
    }
    pool.put(stream);
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_dot_via_proxy(
    proxy: &ParsedProxy,
    proxy_addrs: &[SocketAddr],
    connector: &TlsConnector,
    pool: &ConnPool<tokio_rustls::client::TlsStream<TcpStream>>,
    target_host: &str,
    target_port: u16,
    server_name: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let stream = connect_tcp_via_proxy(proxy, proxy_addrs, target_host, target_port).await?;
    let clean_sni = server_name.trim_matches(['[', ']']);
    let name = ServerName::try_from(clean_sni.to_string())
        .map_err(|e| CoreError::Upstream(format!("invalid TLS server name: {e}")))?;
    let mut tls_stream = connector
        .connect(name, stream)
        .await
        .map_err(|e| CoreError::Upstream(format!("proxied TLS handshake failed: {e}")))?;
    let resp = tcp_roundtrip(&mut tls_stream, query_wire).await?;
    if !tx_id_matches(query_wire, &resp) {
        return Err(CoreError::Upstream(
            "DoT DNS response transaction ID mismatch".to_string(),
        ));
    }
    pool.put(tls_stream);
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_endpoint_via_proxy(
    proxy: &ParsedProxy,
    proxy_addrs: &[SocketAddr],
    tls_connector: &TlsConnector,
    tcp_pool: &ConnPool<TcpStream>,
    dot_pool: &ConnPool<tokio_rustls::client::TlsStream<TcpStream>>,
    endpoint: &UpstreamEndpoint,
    resolved_dot_ip: Option<String>,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    match endpoint {
        UpstreamEndpoint::Tcp(addr) => {
            exchange_tcp_via_proxy_pooled(
                proxy,
                proxy_addrs,
                tcp_pool,
                &addr.ip().to_string(),
                addr.port(),
                query_wire,
            )
            .await
        }
        UpstreamEndpoint::Dot { addr, server_name } => {
            if let Some(resp) = try_exchange_dot_pooled(dot_pool, query_wire).await {
                return Ok(resp);
            }
            let (host, port) = split_host_port(addr, 853);
            let target_host = resolved_dot_ip.unwrap_or(host);
            exchange_dot_via_proxy(
                proxy,
                proxy_addrs,
                tls_connector,
                dot_pool,
                &target_host,
                port,
                server_name,
                query_wire,
            )
            .await
        }
        UpstreamEndpoint::Doh { url } => {
            exchange_doh_via_proxy(proxy, proxy_addrs, tls_connector, url, query_wire).await
        }
        UpstreamEndpoint::Udp(_) | UpstreamEndpoint::Doq { .. } | UpstreamEndpoint::Doh3 { .. } => {
            Err(CoreError::Config(
                "proxy_url only supports tcp://, tls://, and https:// upstreams".to_string(),
            ))
        }
    }
}

pub(crate) async fn exchange_doh_via_proxy(
    proxy: &ParsedProxy,
    proxy_addrs: &[SocketAddr],
    connector: &TlsConnector,
    url: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| CoreError::Upstream(format!("invalid DoH URL '{url}': {e}")))?;
    let is_https = uri
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let authority = uri
        .authority()
        .ok_or_else(|| CoreError::Upstream(format!("missing host in DoH URL '{url}'")))?;
    let (host_raw, port) = split_host_port(authority.as_str(), if is_https { 443 } else { 80 });
    let host = host_raw.trim_matches(['[', ']']).to_string();
    let path = uri
        .path_and_query()
        .map_or("/dns-query", http::uri::PathAndQuery::as_str);

    let tcp = connect_tcp_via_proxy(proxy, proxy_addrs, &host, port).await?;
    if is_https {
        let name = ServerName::try_from(host.clone())
            .map_err(|e| CoreError::Upstream(format!("invalid DoH TLS server name: {e}")))?;
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| CoreError::Upstream(format!("proxied DoH TLS handshake failed: {e}")))?;
        http1_doh_roundtrip(tls, &format_host_port(&host, port), path, query_wire).await
    } else {
        http1_doh_roundtrip(tcp, &format_host_port(&host, port), path, query_wire).await
    }
}

async fn http1_doh_roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host_header: &str,
    path: &str,
    query_wire: &[u8],
) -> Result<Vec<u8>> {
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        query_wire.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(query_wire).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(CoreError::Upstream(format!("DoH HTTP status {status}")));
    }

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut header_bytes = 0_usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        header_bytes = header_bytes.saturating_add(n);
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if header_bytes > MAX_HTTP_HEADER_BYTES {
            return Err(CoreError::Upstream(
                "DoH HTTP response headers too large".to_string(),
            ));
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    if chunked {
        read_chunked_body(&mut reader).await
    } else if let Some(len) = content_length {
        if len > MAX_DOH_RESPONSE_BYTES {
            return Err(CoreError::Upstream(format!(
                "DoH response exceeds {MAX_DOH_RESPONSE_BYTES} bytes limit"
            )));
        }
        let mut body = vec![0_u8; len];
        reader.read_exact(&mut body).await?;
        Ok(body)
    } else {
        let mut body = Vec::new();
        let mut limited =
            reader.take(u64::try_from(MAX_DOH_RESPONSE_BYTES + 1).unwrap_or(u64::MAX));
        limited.read_to_end(&mut body).await?;
        if body.len() > MAX_DOH_RESPONSE_BYTES {
            return Err(CoreError::Upstream(format!(
                "DoH response exceeds {MAX_DOH_RESPONSE_BYTES} bytes limit"
            )));
        }
        Ok(body)
    }
}

async fn read_chunked_body<R: AsyncBufReadExt + AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = reader.read_line(&mut size_line).await?;
        if n == 0 {
            break;
        }
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex, 16)
            .map_err(|_| CoreError::Upstream("invalid DoH chunked size".to_string()))?;
        if chunk_len == 0 {
            break;
        }
        if out.len().saturating_add(chunk_len) > MAX_DOH_RESPONSE_BYTES {
            return Err(CoreError::Upstream(format!(
                "DoH response exceeds {MAX_DOH_RESPONSE_BYTES} bytes limit"
            )));
        }
        let prev_len = out.len();
        out.resize(prev_len + chunk_len, 0);
        reader.read_exact(&mut out[prev_len..]).await?;
        let mut crlf = [0_u8; 2];
        reader.read_exact(&mut crlf).await?;
    }
    Ok(out)
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(TABLE[((triple >> 18) & 0x3F) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3F) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3F) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3F) as usize])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn test_parse_proxy_urls() {
        assert_eq!(
            ParsedProxy::parse("http://user:pass@127.0.0.1:7890").unwrap(),
            ParsedProxy::Http {
                host: "127.0.0.1".to_string(),
                port: 7890,
                basic_auth: Some("Basic dXNlcjpwYXNz".to_string()),
            }
        );
        assert_eq!(
            ParsedProxy::parse("socks5h://proxy.local:1081").unwrap(),
            ParsedProxy::Socks5 {
                host: "proxy.local".to_string(),
                port: 1081,
                auth: None,
                resolve_remote: true,
            }
        );
        assert!(ParsedProxy::parse("ftp://127.0.0.1:21").is_err());
    }

    #[tokio::test]
    async fn test_http_connect_proxy_tcp_dns() {
        let dns_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = dns_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = dns_listener.accept().await {
                let mut len_buf = [0_u8; 2];
                s.read_exact(&mut len_buf).await.unwrap();
                let len = usize::from(u16::from_be_bytes(len_buf));
                let mut q = vec![0_u8; len];
                s.read_exact(&mut q).await.unwrap();
                q[2] |= 0x80;
                s.write_all(&len_buf).await.unwrap();
                s.write_all(&q).await.unwrap();
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();
            let mut buf = [0_u8; 512];
            let n = client.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("CONNECT"));
            assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut target = TcpStream::connect(dns_addr).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        });

        let proxy = ParsedProxy::parse(&format!("http://user:pass@{proxy_addr}")).unwrap();
        let pool = ConnPool::default();
        let query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x00];
        let resp = exchange_tcp_via_proxy_pooled(
            &proxy,
            &[proxy_addr],
            &pool,
            &dns_addr.ip().to_string(),
            dns_addr.port(),
            &query,
        )
        .await
        .unwrap();
        assert_eq!(&resp[..2], &[0x12, 0x34]);
        assert_eq!(resp[2] & 0x80, 0x80);
    }

    #[tokio::test]
    async fn test_socks5_proxy_doh_http() {
        let doh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doh_addr = doh_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = doh_listener.accept().await {
                let mut buf = [0_u8; 1024];
                let _ = s.read(&mut buf).await.unwrap();
                let body = [0xAB_u8, 0xCD, 0x81, 0x80];
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                s.write_all(resp.as_bytes()).await.unwrap();
                s.write_all(&body).await.unwrap();
            }
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = socks_listener.accept().await.unwrap();
            let mut greet = [0_u8; 4];
            client.read_exact(&mut greet).await.unwrap();
            assert_eq!(&greet, &[0x05, 0x02, 0x00, 0x02]);
            client.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth_hdr = [0_u8; 2];
            client.read_exact(&mut auth_hdr).await.unwrap();
            let ulen = usize::from(auth_hdr[1]);
            let mut u = vec![0_u8; ulen];
            client.read_exact(&mut u).await.unwrap();
            let mut plen_b = [0_u8; 1];
            client.read_exact(&mut plen_b).await.unwrap();
            let mut p = vec![0_u8; usize::from(plen_b[0])];
            client.read_exact(&mut p).await.unwrap();
            assert_eq!(u, b"u1");
            assert_eq!(p, b"p1");
            client.write_all(&[0x01, 0x00]).await.unwrap();

            let mut req_hdr = [0_u8; 4];
            client.read_exact(&mut req_hdr).await.unwrap();
            assert_eq!(req_hdr[3], 0x01); // IPv4
            let mut ip_port = [0_u8; 6];
            client.read_exact(&mut ip_port).await.unwrap();
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();

            let mut target = TcpStream::connect(doh_addr).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        });

        let proxy = ParsedProxy::parse(&format!("socks5://u1:p1@{socks_addr}")).unwrap();
        let tls_cfg = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(tls_cfg));
        let resp = exchange_doh_via_proxy(
            &proxy,
            &[socks_addr],
            &connector,
            &format!("http://{doh_addr}/dns-query"),
            &[0xAB, 0xCD, 0x01, 0x00],
        )
        .await
        .unwrap();
        assert_eq!(resp, vec![0xAB, 0xCD, 0x81, 0x80]);
    }
}
