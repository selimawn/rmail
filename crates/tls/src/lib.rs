//! TLS helpers for rmail (production-ready baseline).
//!
//! Features:
//! - Inbound TLS (SMTP/IMAP)
//! - Outbound TLS with opportunistic mode
//! - Handshake timeout
//! - Better error handling
//! - TLS policy support (Opportunistic / Required)

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use tokio_rustls::{
    client::TlsStream as ClientTlsStream,
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    },
    server::TlsStream as ServerTlsStream,
    TlsAcceptor as TokioAcceptor, TlsConnector as TokioConnector,
};

use rustls_pemfile::{certs, private_key};
use thiserror::Error;
use tracing::{debug, warn};

const TLS_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    #[error("timeout during TLS handshake")]
    Timeout,

    #[error("no certificate found in {0}")]
    NoCert(String),

    #[error("no private key found in {0}")]
    NoKey(String),
}

/// TLS policy for outbound connections.
#[derive(Debug, Clone, Copy)]
pub enum TlsMode {
    /// Try TLS, fallback to plaintext on failure (SMTP default)
    Opportunistic,
    /// TLS is required (MTA-STS / strict mode)
    Required,
}

// ─── Inbound ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TlsAcceptor {
    inner: TokioAcceptor,
}

impl TlsAcceptor {
    pub fn from_pem(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_file = std::fs::File::open(cert_path)?;
        let key_file = std::fs::File::open(key_path)?;

        let certs: Vec<CertificateDer> =
            certs(&mut BufReader::new(cert_file)).collect::<Result<_, _>>()?;

        if certs.is_empty() {
            return Err(TlsError::NoCert(cert_path.display().to_string()));
        }

        let key: PrivateKeyDer = private_key(&mut BufReader::new(key_file))?
            .ok_or_else(|| TlsError::NoKey(key_path.display().to_string()))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        Ok(Self {
            inner: TokioAcceptor::from(Arc::new(config)),
        })
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<ServerTlsStream<TcpStream>, TlsError> {
        timeout(TLS_TIMEOUT, self.inner.accept(stream))
            .await
            .map_err(|_| TlsError::Timeout)?
            .map_err(|e| TlsError::Handshake(e.to_string()))
    }
}

// ─── Outbound ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TlsConnector {
    inner: TokioConnector,
}

impl TlsConnector {
    /// Strict connector: verifies the server certificate against the WebPKI
    /// roots. Use for MTA-STS enforce / require_starttls deliveries.
    pub fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Self {
            inner: TokioConnector::from(Arc::new(config)),
        }
    }

    /// Permissive connector for opportunistic STARTTLS: encrypts without
    /// authenticating the peer. This matches Postfix's `smtp_tls_security_level
    /// = may` — many MTAs serve self-signed certificates, and rejecting them
    /// would make legitimate mail undeliverable. Use `TlsConnector::new()`
    /// whenever a policy (MTA-STS, require_starttls) demands authentication.
    pub fn permissive() -> Self {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        Self {
            inner: TokioConnector::from(Arc::new(config)),
        }
    }

    /// Try to upgrade to TLS based on policy.
    pub async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
        mode: TlsMode,
    ) -> Result<Option<ClientTlsStream<TcpStream>>, TlsError> {
        let server_name = ServerName::try_from(domain.to_string())
            .map_err(|_| TlsError::InvalidDnsName(domain.to_string()))?;

        let result = timeout(TLS_TIMEOUT, self.inner.connect(server_name, stream)).await;

        match result {
            Ok(Ok(tls)) => {
                debug!(%domain, "TLS established");
                Ok(Some(tls))
            }

            Ok(Err(e)) => {
                warn!(%domain, "TLS handshake failed: {}", e);
                match mode {
                    TlsMode::Opportunistic => Ok(None),
                    TlsMode::Required => Err(TlsError::Handshake(e.to_string())),
                }
            }

            Err(_) => {
                warn!(%domain, "TLS handshake timeout");
                match mode {
                    TlsMode::Opportunistic => Ok(None),
                    TlsMode::Required => Err(TlsError::Timeout),
                }
            }
        }
    }
}

impl Default for TlsConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Opportunistic certificate verifier ─────────────────────────────────────

/// Accepts any server certificate. Only used by `TlsConnector::permissive()`
/// for opportunistic MTA-to-MTA STARTTLS, where encryption is better than
/// no delivery at all.
#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
