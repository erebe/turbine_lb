use duration_str::deserialize_duration;
use nonempty::NonEmpty;
use regex::Regex;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Protocol {
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub protocol: Protocol,
    pub listen_addr: NonEmpty<SocketAddr>,
    pub upstreams: NonEmpty<UpstreamConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum LoadBalancingStrategyConfig {
    RoundRobin,
    Random,
}

#[derive(Debug, Clone, Deserialize)]
pub enum BackendDiscovery {
    Static(NonEmpty<BackendConfig>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub enum MatchConfig {
    Any,
    None,
    Sni(String),
    #[serde(with = "serde_regex")]
    SniRegex(Regex),
    Alpn(String),
    DestinationPort(u16),
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub backends: BackendDiscovery,
    pub load_balancing: LoadBalancingStrategyConfig,
    pub proxy_protocol: bool,
    pub r#match: MatchConfig,
    #[serde(deserialize_with = "deserialize_duration")]
    pub cnx_max_duration: Duration,
    #[serde(default = "default_connect_timeout")]
    #[serde(deserialize_with = "deserialize_duration")]
    pub connect_timeout: Duration,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    #[serde(default)]
    pub alpns: Vec<String>,
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}
