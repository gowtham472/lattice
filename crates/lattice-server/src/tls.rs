//! TLS for the API and cockpit: TLS 1.3 only, hybrid post-quantum key exchange first.
//!
//! A tool that tells an estate to move to X25519MLKEM768 serves itself with it: the key-exchange
//! groups are rustls's post-quantum preference (X25519MLKEM768, then X25519 and the NIST curves
//! for clients that lack it), over TLS 1.3 alone. With a client CA the server requires a client
//! certificate chaining to it (mutual TLS), and the certificate's SHA-256 fingerprint identifies
//! the user (see [`crate::access`]).
//!
//! Connections are served by a small accept loop instead of `axum::serve`, so each request can
//! carry the peer address and the client certificate that authenticated the connection.

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// How long a client may take to complete the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// SHA-256 of the client certificate that authenticated the connection, in lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate(pub String);

/// What `/api/health` says about transport security.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub protocol: &'static str,
    /// Key-exchange groups in the server's order of preference.
    pub key_exchange: Vec<String>,
    pub client_certificates: bool,
}

/// A server configuration and what it offers.
#[derive(Clone)]
pub struct Tls {
    pub config: Arc<rustls::ServerConfig>,
    pub info: TlsInfo,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").field("info", &self.info).finish()
    }
}

/// Lowercase hex SHA-256 of a DER certificate: how users files pin client certificates.
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// The DER of the first certificate in a PEM file.
pub fn first_certificate(pem: &[u8]) -> Result<Vec<u8>, String> {
    CertificateDer::pem_slice_iter(pem)
        .next()
        .ok_or_else(|| "no PEM certificate found".to_owned())?
        .map(|der| der.to_vec())
        .map_err(|e| e.to_string())
}

/// Builds the TLS configuration from PEM: the server's certificate chain and private key, and
/// optionally the CA that client certificates must chain to.
pub fn configure(
    certificate_pem: &[u8],
    key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> Result<Tls, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("server certificate: {e}"))?;
    if chain.is_empty() {
        return Err("server certificate: no PEM certificate found".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("server key: {e}"))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key_exchange = provider
        .kx_groups
        .iter()
        .map(|group| format!("{:?}", group.name()))
        .collect();
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS: {e}"))?;
    let builder = match client_ca_pem {
        Some(pem) => {
            let mut roots = rustls::RootCertStore::empty();
            let mut count = 0;
            for certificate in CertificateDer::pem_slice_iter(pem) {
                let certificate = certificate.map_err(|e| format!("client CA: {e}"))?;
                roots
                    .add(certificate)
                    .map_err(|e| format!("client CA: {e}"))?;
                count += 1;
            }
            if count == 0 {
                return Err("client CA: no PEM certificate found".into());
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| format!("client CA: {e}"))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|e| format!("server certificate and key: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls {
        config: Arc::new(config),
        info: TlsInfo {
            protocol: "TLSv1.3",
            key_exchange,
            client_certificates: client_ca_pem.is_some(),
        },
    })
}

/// Accepts TLS connections until `shutdown` resolves, serving each on its own task.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    tls: &Tls,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.config.clone());
    tokio::pin!(shutdown);
    loop {
        let (tcp, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "accept failed");
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|der| ClientCertificate(fingerprint(der)));
            let service =
                router.map_request(move |mut request: hyper::Request<hyper::body::Incoming>| {
                    request
                        .extensions_mut()
                        .insert(ConnectInfo::<SocketAddr>(peer));
                    if let Some(certificate) = &certificate {
                        request.extensions_mut().insert(certificate.clone());
                    }
                    request
                });
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
            if let Err(error) = connection.await {
                tracing::debug!(%peer, %error, "connection ended with an error");
            }
        });
    }
}
