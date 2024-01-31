use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use anyhow::{anyhow, Context};
use rustls::{Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tracing::info;
use tracing::log::warn;

pub fn load_certificates_from_pem(path: &Path) -> anyhow::Result<Vec<Certificate>> {
    info!("Loading tls certificate from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader);

    Ok(certs
        .into_iter()
        .filter_map(|cert| match cert {
            Ok(cert) => Some(Certificate(cert.to_vec())),
            Err(err) => {
                warn!("Error while parsing tls certificate: {:?}", err);
                None
            }
        })
        .collect())
}

pub fn load_private_key_from_file(path: &Path) -> anyhow::Result<PrivateKey> {
    info!("Loading tls private key from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let Some(private_key) = rustls_pemfile::private_key(&mut reader)? else {
        return Err(anyhow!("No private key found in {path:?}"));
    };

    Ok(PrivateKey(private_key.secret_der().to_vec()))
}

pub fn tls_acceptor(certificate: Vec<Certificate>, private_key: PrivateKey, alpn_protocols: Option<Vec<Vec<u8>>>) -> anyhow::Result<TlsAcceptor> {
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificate, private_key)
        .with_context(|| "invalid tls certificate or private key")?;

    if let Some(alpn_protocols) = alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    config.enable_secret_extraction = true;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
