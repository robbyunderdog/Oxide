//! Abuse protection for the login and register endpoints.
//!
//! Two separate problems:
//! 1. **Password guessing.** Without a limit, anyone can try thousands of
//!    passwords against an account. `RateLimiter` caps attempts per IP address.
//! 2. **Overload.** Every login runs Argon2, which deliberately burns CPU and
//!    memory. A flood of logins could exhaust the server. A semaphore (see
//!    `AppState::hash_slots`) caps how many hashes run at once; the rest wait.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
};

use crate::{AppState, error::AppError};

/// "At most `max_hits` requests per `window`, per IP": a fixed-window counter.
/// Simple and memory-cheap; precise enough for slowing down guessing.
pub struct RateLimiter {
    max_hits: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, Window>>,
}

struct Window {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    pub fn new(max_hits: u32, window: Duration) -> Self {
        Self { max_hits, window, hits: Mutex::new(HashMap::new()) }
    }

    /// Counts one attempt from `ip`; errors once the limit is exceeded.
    pub fn check(&self, ip: IpAddr) -> Result<(), AppError> {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();

        // Forget expired entries now and then, so the map can't grow forever.
        if hits.len() > 10_000 {
            hits.retain(|_, w| now.duration_since(w.started) < self.window);
        }

        let w = hits.entry(bucket(ip)).or_insert(Window { started: now, count: 0 });
        if now.duration_since(w.started) >= self.window {
            *w = Window { started: now, count: 0 };
        }
        w.count += 1;
        if w.count > self.max_hits {
            Err(AppError::TooManyRequests("too many attempts, please wait a few minutes and try again"))
        } else {
            Ok(())
        }
    }
}

/// IPv6 users typically get a whole /64 block (18 quintillion addresses), so
/// limiting single IPv6 addresses would be pointless: count the block instead.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut seg = v6.segments();
            seg[4..].fill(0);
            IpAddr::V6(Ipv6Addr::from(seg))
        }
        v4 => v4,
    }
}

/// The caller's IP address, as an extractor (like `AuthUser`).
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        // Behind a cloud load balancer, every connection comes *from the
        // proxy*, so the real client is in X-Forwarded-For. Only trust that
        // header when we know a proxy is in front (TRUST_PROXY=1); otherwise
        // a client could write any IP there and dodge the limit. The proxy
        // appends the address it saw to the *end*, so take the last entry.
        if state.trust_proxy {
            let forwarded = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|s| s.trim().parse().ok());
            if let Some(ip) = forwarded {
                return Ok(ClientIp(ip));
            }
        }
        // Filled in by `into_make_service_with_connect_info` in main.rs.
        let ConnectInfo(addr) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("server not started with connect info")))?;
        Ok(ClientIp(addr.ip()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_limit_and_tracks_ips_separately() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.check(a).is_ok());
        }
        assert!(limiter.check(a).is_err(), "4th attempt is blocked");
        assert!(limiter.check(b).is_ok(), "a different IP is unaffected");
    }

    #[test]
    fn ipv6_addresses_in_one_block_share_a_limit() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("2001:db8::1".parse().unwrap()).is_ok());
        assert!(limiter.check("2001:db8::ffff".parse().unwrap()).is_err());
    }

    #[test]
    fn window_resets() {
        let limiter = RateLimiter::new(1, Duration::from_millis(20));
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_err());
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.check(ip).is_ok());
    }
}
