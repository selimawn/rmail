//! TLS helpers for rmail.
//!
//! Provides:
//! - `TlsAcceptor` for inbound connections (SMTP STARTTLS / SMTPS / IMAPS)
//! - `TlsConnector` for outbound delivery (SMTP client STARTTLS)
//!
//! Both are thin wrappers around `tokio-rustls` + `rustls`.
//! Certificate and private key are loaded from disk at startup
//! and cached for the lifetime of the process.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig, ClientConfig, RootCertStore,
    },
    TlsAcceptor as TokioAcceptor,
    TlsConnector as TokioConnector,
    server::TlsStream as ServerTlsStream,
    client::TlsStream as ClientTlsStream,
};
use rustls_pemfile::{certs, private_key};
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error loading TLS material: {0}")]
    Io(#[from] std::io::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),
    #[error("no certificate found in {0}")]
    NoCert(String),
    #[error("no private key found in {0}")]
    NoKey(String),
}

// ─── Inbound TLS ──────────────────────────────────────────────────────────────

/// Wraps a rustls `ServerConfig` for use with inbound SMTP / IMAP connections.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: TokioAcceptor,
}

impl TlsAcceptor {
    /// Load cert + key from PEM files and build the acceptor.
    /// Call once at startup; clone freely (Arc inside).
    pub fn from_pem(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_file = std::fs::File::open(cert_path)?;
        let key_file  = std::fs::File::open(key_path)?;

        let certs: Vec<CertificateDer> = certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(TlsError::NoCert(cert_path.display().to_string()));
        }

        let key: PrivateKeyDer = private_key(&mut BufReader::new(key_file))?
            .ok_or_else(|| TlsError::NoKey(key_path.display().to_string()))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        debug!(cert = %cert_path.display(), "TLS acceptor ready");
        Ok(Self { inner: TokioAcceptor::from(Arc::new(config)) })
    }

    /// Perform the TLS handshake on an already-accepted TCP stream.
    pub async fn accept(&self, stream: TcpStream) -> Result<ServerTlsStream<TcpStream>, TlsError> {
        self.inner.accept(stream).await.map_err(TlsError::Io)
    }
}

// ─── Outbound TLS ─────────────────────────────────────────────────────────────

/// Wraps a rustls `ClientConfig` for use in the SMTP outbound delivery client.
#[derive(Clone)]
pub struct TlsConnector {
    inner: TokioConnector,
}

impl TlsConnector {
    /// Build a connector that trusts the OS/WebPKI root certificates.
    pub fn new() -> Result<Self, TlsError> {
        let roots = webpki_roots_store();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self { inner: TokioConnector::from(Arc::new(config)) })
    }

    /// Upgrade a plaintext TCP stream to TLS (STARTTLS).
    pub async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> Result<ClientTlsStream<TcpStream>, TlsError> {
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(domain.to_owned())
            .map_err(|e| TlsError::Rustls(tokio_rustls::rustls::Error::General(e.to_string())))?;
        self.inner.connect(server_name, stream).await.map_err(TlsError::Io)
    }
}

impl Default for TlsConnector {
    fn default() -> Self { Self::new().expect("TlsConnector::new should not fail") }
}

// ─── WebPKI roots ─────────────────────────────────────────────────────────────

fn webpki_roots_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    // webpki-roots provides Mozilla's root program as DER-encoded certs.
    // Include them via the rustls built-in.
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}
