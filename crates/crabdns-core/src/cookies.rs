use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

use crate::error::{CoreError, Result};
use crate::wire::base_response;

pub const EDNS_OPTION_COOKIE: u16 = 10;
const SERVER_COOKIE_MAX_AGE_SECS: u32 = 3600;
const SERVER_COOKIE_MAX_FUTURE_SECS: u32 = 300;
const RFC9018_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieCheck {
    None,
    Valid { client_cookie: [u8; 8] },
    NeedsServerCookie { client_cookie: [u8; 8] },
    Malformed,
}

pub struct DnsCookieEngine {
    key: hmac::Key,
    enabled: AtomicBool,
    require_valid: AtomicBool,
}

impl Default for DnsCookieEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCookieEngine {
    pub fn new() -> Self {
        let mut secret = [0_u8; 32];
        let rng = SystemRandom::new();
        let _ = rng.fill(&mut secret);
        Self::with_secret(&secret)
    }

    pub fn with_secret(secret: &[u8; 32]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            enabled: AtomicBool::new(false),
            require_valid: AtomicBool::new(false),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn require_valid(&self) -> bool {
        self.require_valid.load(Ordering::Relaxed)
    }

    pub fn set_require_valid(&self, require_valid: bool) {
        self.require_valid.store(require_valid, Ordering::Relaxed);
    }

    pub fn check_request(&self, request: &Message, client_ip: IpAddr) -> CookieCheck {
        if !self.is_enabled() {
            return CookieCheck::None;
        }
        let Some(opt_bytes) = extract_cookie_option(request) else {
            return CookieCheck::None;
        };
        if opt_bytes.len() == 8 {
            let mut client_cookie = [0_u8; 8];
            client_cookie.copy_from_slice(opt_bytes);
            return CookieCheck::NeedsServerCookie { client_cookie };
        }
        if !(16..=40).contains(&opt_bytes.len()) {
            return CookieCheck::Malformed;
        }
        let mut client_cookie = [0_u8; 8];
        client_cookie.copy_from_slice(&opt_bytes[..8]);
        let server_cookie = &opt_bytes[8..];
        let now_secs = current_unix_secs();
        if self.verify_server_cookie(client_cookie, server_cookie, client_ip, now_secs) {
            CookieCheck::Valid { client_cookie }
        } else {
            CookieCheck::NeedsServerCookie { client_cookie }
        }
    }

    pub fn mint_cookie_bytes(&self, client_cookie: [u8; 8], client_ip: IpAddr) -> Vec<u8> {
        self.mint_cookie_bytes_at(client_cookie, client_ip, current_unix_secs())
    }

    pub fn mint_cookie_bytes_at(
        &self,
        client_cookie: [u8; 8],
        client_ip: IpAddr,
        now_secs: u32,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&client_cookie);
        out.push(RFC9018_VERSION);
        out.extend_from_slice(&[0_u8; 3]);
        out.extend_from_slice(&now_secs.to_be_bytes());
        let tag = self.compute_hash(client_cookie, &out[8..16], client_ip);
        out.extend_from_slice(&tag);
        out
    }

    fn verify_server_cookie(
        &self,
        client_cookie: [u8; 8],
        server_cookie: &[u8],
        client_ip: IpAddr,
        now_secs: u32,
    ) -> bool {
        if server_cookie.len() != 16 || server_cookie[0] != RFC9018_VERSION {
            return false;
        }
        if server_cookie[1..4] != [0_u8; 3] {
            return false;
        }
        let ts = u32::from_be_bytes([
            server_cookie[4],
            server_cookie[5],
            server_cookie[6],
            server_cookie[7],
        ]);
        let age = now_secs.wrapping_sub(ts);
        let future = ts.wrapping_sub(now_secs);
        if age > SERVER_COOKIE_MAX_AGE_SECS && future > SERVER_COOKIE_MAX_FUTURE_SECS {
            return false;
        }
        let expected = self.compute_hash(client_cookie, &server_cookie[..8], client_ip);
        constant_time_eq_8(expected, &server_cookie[8..16])
    }

    fn compute_hash(&self, client_cookie: [u8; 8], header_8: &[u8], client_ip: IpAddr) -> [u8; 8] {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(&client_cookie);
        ctx.update(header_8);
        match client_ip {
            IpAddr::V4(v4) => ctx.update(&v4.octets()),
            IpAddr::V6(v6) => ctx.update(&v6.octets()),
        }
        let tag = ctx.sign();
        let mut out = [0_u8; 8];
        out.copy_from_slice(&tag.as_ref()[..8]);
        out
    }

    pub fn attach_cookie_to_wire(
        &self,
        resp_bytes: Vec<u8>,
        client_cookie: [u8; 8],
        client_ip: IpAddr,
    ) -> Vec<u8> {
        let Ok(mut msg) = Message::from_vec(&resp_bytes) else {
            return resp_bytes;
        };
        let cookie_data = self.mint_cookie_bytes(client_cookie, client_ip);
        let edns = msg.edns.get_or_insert_with(Edns::new);
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDNS_OPTION_COOKIE, cookie_data));
        msg.to_vec().unwrap_or(resp_bytes)
    }

    pub fn build_badcookie_response(
        &self,
        request: &Message,
        client_cookie: [u8; 8],
        client_ip: IpAddr,
    ) -> Result<Vec<u8>> {
        let mut msg = base_response(request, ResponseCode::BADCOOKIE);
        let cookie_data = self.mint_cookie_bytes(client_cookie, client_ip);
        let edns = msg.edns.get_or_insert_with(Edns::new);
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDNS_OPTION_COOKIE, cookie_data));
        msg.to_vec()
            .map_err(|e| CoreError::Protocol(format!("failed to encode BADCOOKIE response: {e}")))
    }
}

fn extract_cookie_option(request: &Message) -> Option<&[u8]> {
    let edns = request.edns.as_ref()?;
    for (code, opt) in edns.options().as_ref() {
        match (code, opt) {
            (EdnsCode::Cookie, EdnsOption::Unknown(_, data))
            | (_, EdnsOption::Unknown(EDNS_OPTION_COOKIE, data)) => return Some(data.as_slice()),
            _ => {}
        }
    }
    None
}

fn current_unix_secs() -> u32 {
    let raw = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (raw & 0xFFFF_FFFF) as u32
}

fn constant_time_eq_8(a: [u8; 8], b: &[u8]) -> bool {
    if b.len() != 8 {
        return false;
    }
    let mut diff = 0_u8;
    for i in 0..8 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[test]
    fn test_server_cookie_mint_and_verify() {
        let engine = DnsCookieEngine::with_secret(&[7_u8; 32]);
        engine.set_enabled(true);
        let client_cookie = [1, 2, 3, 4, 5, 6, 7, 8];
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        let full = engine.mint_cookie_bytes_at(client_cookie, ip, 1_700_000_000);
        assert_eq!(full.len(), 24);
        assert_eq!(&full[..8], &client_cookie);
        assert!(engine.verify_server_cookie(client_cookie, &full[8..], ip, 1_700_000_100));

        // Wrong IP must fail verification.
        let other_ip: IpAddr = "192.0.2.11".parse().unwrap();
        assert!(!engine.verify_server_cookie(client_cookie, &full[8..], other_ip, 1_700_000_100));

        // Expired server cookie (> 1h) must fail.
        assert!(!engine.verify_server_cookie(client_cookie, &full[8..], ip, 1_700_004_000));
    }

    #[test]
    fn test_cookie_check_malformed_and_valid() {
        let engine = DnsCookieEngine::with_secret(&[9_u8; 32]);
        engine.set_enabled(true);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        let mut req = Message::new(1, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDNS_OPTION_COOKIE, vec![1, 2, 3]));
        req.edns = Some(edns);
        assert_eq!(engine.check_request(&req, ip), CookieCheck::Malformed);

        let client_cookie = [10, 20, 30, 40, 50, 60, 70, 80];
        let mut edns2 = Edns::new();
        edns2.options_mut().insert(EdnsOption::Unknown(
            EDNS_OPTION_COOKIE,
            client_cookie.to_vec(),
        ));
        req.edns = Some(edns2);
        assert_eq!(
            engine.check_request(&req, ip),
            CookieCheck::NeedsServerCookie { client_cookie }
        );
    }
}
