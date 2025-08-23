use anyhow::{anyhow, Context};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::debug;
use tracing::log::warn;

pub type ProtocolName = Vec<u8>;

pub fn load_certificates_from_pem(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    debug!("Loading tls certificate from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader);

    Ok(certs
        .into_iter()
        .filter_map(|cert| match cert {
            Ok(cert) => Some(cert),
            Err(err) => {
                warn!("Error while parsing tls certificate: {:?}", err);
                None
            }
        })
        .collect())
}

pub fn load_private_key_from_file(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    debug!("Loading tls private key from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let Some(private_key) = rustls_pemfile::private_key(&mut reader)? else {
        return Err(anyhow!("No private key found in {path:?}"));
    };

    Ok(private_key)
}

pub fn tls_acceptor(
    certificate: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    alpn_protocols: Option<Vec<Vec<u8>>>,
) -> anyhow::Result<TlsAcceptor> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate, private_key)
        .with_context(|| "invalid tls certificate or private key")?;

    if let Some(alpn_protocols) = alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    config.enable_secret_extraction = true;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
