use crate::config::types::MatchConfig;
use crate::Upstream;
use nonempty::NonEmpty;
use rustls::internal::msgs::handshake::{ConvertProtocolNameList, ProtocolName};
use rustls::server::DnsName;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct MatchContext {
    sni: Option<DnsName>,
    alpns: Option<Vec<ProtocolName>>,
    destination: SocketAddr,
}

impl MatchContext {
    pub fn new(stream: &TcpStream, sni: Option<DnsName>, alpn: Option<Vec<ProtocolName>>) -> Self {
        Self {
            sni,
            alpns: alpn,
            destination: stream
                .local_addr()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
        }
    }

    #[inline]
    pub fn find_matching_upstream<'a>(
        &'_ self,
        upstreams: &'a NonEmpty<Upstream>,
    ) -> Option<&'a Upstream> {
        upstreams
            .iter()
            .find(|upstream| match &upstream.cfg.r#match {
                MatchConfig::Any => true,
                MatchConfig::None => false,
                MatchConfig::Sni(sni) => self
                    .sni
                    .as_ref()
                    .map(|cnx_sni| cnx_sni.as_ref() == sni.as_str())
                    .unwrap_or(false),
                MatchConfig::SniRegex(sni) => self
                    .sni
                    .as_ref()
                    .map(|cnx_sni| sni.is_match(cnx_sni.as_ref()))
                    .unwrap_or(false),
                MatchConfig::SniRegexNot(sni) => self
                    .sni
                    .as_ref()
                    .map(|cnx_sni| !sni.is_match(cnx_sni.as_ref()))
                    .unwrap_or(false),
                MatchConfig::DestinationPort(dport) => self.destination.port() == *dport,
                MatchConfig::Alpn(alpn) => {
                    let Some(cnx_alpn) = &self.alpns else {
                        return false;
                    };
                    cnx_alpn
                        .to_slices()
                        .iter()
                        .any(|cnx_alpn| *cnx_alpn == alpn.as_bytes())
                }
            })
    }
}
