//! A TLS 1.3 handshake over loopback with rustls on ring, once per cipher suite, after a pause so
//! a recording can start first. Arguments: certificate PEM, key PEM, pause in milliseconds.

use rustls::crypto::ring::{cipher_suite, default_provider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let certificate = CertificateDer::from_pem_file(&args[1]).expect("certificate");
    let key = PrivateKeyDer::from_pem_file(&args[2]).expect("key");
    let pause = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(0);
    std::thread::sleep(std::time::Duration::from_millis(pause));

    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();

    for suite in [
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![suite],
            ..default_provider()
        };
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_no_client_auth(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_config = server_config.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            stream.write_all(&byte).unwrap();
            stream.flush().unwrap();
        });
        let connection = rustls::ClientConnection::new(
            client_config,
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut stream = rustls::StreamOwned::new(connection, TcpStream::connect(address).unwrap());
        stream.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).unwrap();
        println!("tls {:?}", stream.conn.negotiated_cipher_suite().unwrap().suite());
        server.join().unwrap();
    }
}
