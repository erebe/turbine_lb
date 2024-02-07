use crate::config::types::LoadBalancingStrategyConfig;
use nonempty::NonEmpty;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Default)]
pub enum LoadBalancingStrategy {
    RoundRobin {
        ix: AtomicUsize,
    },
    #[default]
    Random,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub addr: SocketAddr,
}

impl Backend {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl LoadBalancingStrategy {
    #[inline]
    pub fn pick_backend<'a>(&'_ self, backends: &'a NonEmpty<Backend>) -> &'a Backend {
        match self {
            LoadBalancingStrategy::RoundRobin { ix } => {
                let ix = ix.fetch_add(1, Ordering::Relaxed);
                &backends[ix % backends.len()]
            }
            LoadBalancingStrategy::Random => {
                let random = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos() as usize;
                &backends[random % backends.len()]
            }
        }
    }
}

impl From<&LoadBalancingStrategyConfig> for LoadBalancingStrategy {
    fn from(value: &LoadBalancingStrategyConfig) -> Self {
        match value {
            LoadBalancingStrategyConfig::RoundRobin => LoadBalancingStrategy::RoundRobin {
                ix: AtomicUsize::new(0),
            },
            LoadBalancingStrategyConfig::Random => LoadBalancingStrategy::Random,
        }
    }
}
