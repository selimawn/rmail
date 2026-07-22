//! Per-IP connection limiting, shared by the SMTP and IMAP listeners.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedSemaphorePermit};

#[derive(Clone, Default)]
pub struct PerIpLimiter {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

pub struct Permit {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    _global: OwnedSemaphorePermit,
}

impl PerIpLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to register a connection from `ip`. Returns `None` when the
    /// per-IP limit is reached. The returned permit releases both the
    /// per-IP slot and the global semaphore slot on drop.
    pub async fn acquire(
        &self,
        ip: IpAddr,
        max_per_ip: usize,
        global: OwnedSemaphorePermit,
    ) -> Option<Permit> {
        let mut counts = self.counts.lock().await;
        let count = counts.entry(ip).or_default();
        if *count >= max_per_ip {
            return None;
        }
        *count += 1;
        drop(counts);
        Some(Permit {
            ip,
            counts: Arc::clone(&self.counts),
            _global: global,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let ip = self.ip;
        let counts = Arc::clone(&self.counts);
        tokio::spawn(async move {
            let mut counts = counts.lock().await;
            if let Some(count) = counts.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&ip);
                }
            }
        });
    }
}
