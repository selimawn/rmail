//! TLS helpers: build server configs, perform STARTTLS upgrades.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{self, ServerConfig},
    server::TlsStream,
    TlsAcceptor,
};
use tracing::debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no certificates found in {0}")]
    NoCerts(String),
    #[error("no private key found in {0}")]
    NoKey(String),
}

/// Build a `TlsAcceptor` from PEM cert + key files.
/// Call once at startup; store the Arc<TlsAcceptor> in shared state.
pub fn build_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsError> {
    let certs = {
        let mut r = BufReader::new(File::open(cert_path)?);
        rustls_pemfile::certs(&mut r)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
    };
    if certs.is_empty() {
        return Err(TlsError::NoCerts(cert_path.display().to_string()));
    }

    let key = {
        let mut r = BufReader::new(File::open(key_path)?);
        rustls_pemfile::private_key(&mut r)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| TlsError::NoKey(key_path.display().to_string()))?
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    debug!(
        cert = %cert_path.display(),
        key  = %key_path.display(),
        "TLS acceptor built"
    );

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Perform a STARTTLS upgrade on a plain TCP stream.
/// Call after sending `220 Ready to start TLS` to the client.
pub async fn upgrade(acceptor: &TlsAcceptor, stream: TcpStream) -> Result<TlsStream<TcpStream>, TlsError> {
    Ok(acceptor.accept(stream).await?)
}
