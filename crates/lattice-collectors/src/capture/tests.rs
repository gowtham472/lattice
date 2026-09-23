use super::*;
use lattice_core::Finding;

const CERT_PEM: &str = include_str!("../../tests/fixtures/rsa2048-sha256.pem");

fn cert_der() -> Vec<u8> {
    use base64::Engine;
    let body: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

// ---- packet construction ---------------------------------------------------------------------

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

struct Packet {
    frame: Vec<u8>,
}

fn tcp(src: ([u8; 4], u16), dst: ([u8; 4], u16), seq: u32, flags: u8, payload: &[u8]) -> Packet {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src.1.to_be_bytes());
    tcp.extend_from_slice(&dst.1.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src.0);
    ip.extend_from_slice(&dst.0);
    ip.extend_from_slice(&tcp);
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&ip);
    // Ethernet minimum-frame padding must not be mistaken for payload
    frame.resize(frame.len().max(60), 0);
    Packet { frame }
}

fn tcp6(src: ([u8; 16], u16), dst: ([u8; 16], u16), seq: u32, flags: u8, payload: &[u8]) -> Packet {
    let v4 = tcp(([0; 4], src.1), ([0; 4], dst.1), seq, flags, payload);
    let tcp_segment = &v4.frame[14 + 20..14 + 20 + 20 + payload.len()];
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[6, 64]);
    ip.extend_from_slice(&src.0);
    ip.extend_from_slice(&dst.0);
    ip.extend_from_slice(tcp_segment);
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(&ip);
    Packet { frame }
}

fn pcap_file(packets: &[Packet]) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for packet in packets {
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(packet.frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&packet.frame);
    }
    out
}

fn pcapng_file(packets: &[Packet]) -> Vec<u8> {
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut padded = body.to_vec();
        padded.resize(body.len().div_ceil(4) * 4, 0);
        let length = (12 + padded.len()) as u32;
        let mut out = kind.to_le_bytes().to_vec();
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&padded);
        out.extend_from_slice(&length.to_le_bytes());
        out
    }
    let mut out = block(
        0x0a0d_0d0a,
        &[
            0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    );
    out.extend(block(1, &[1, 0, 0, 0, 0xff, 0xff, 0, 0]));
    for packet in packets {
        let mut body = vec![0; 12];
        body.extend_from_slice(&(packet.frame.len() as u32).to_le_bytes());
        body.extend_from_slice(&(packet.frame.len() as u32).to_le_bytes());
        body.extend_from_slice(&packet.frame);
        out.extend(block(6, &body));
    }
    out
}

// ---- TLS and SSH messages --------------------------------------------------------------------

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn records(kind: u8, data: &[u8], chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for part in data.chunks(chunk) {
        out.extend_from_slice(&[kind, 0x03, 0x03]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn client_hello(server_name: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    sni.extend_from_slice(server_name.as_bytes());
    let extensions = extension(0, &sni);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 4, 0x13, 0x02, 0xc0, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    handshake(1, &body)
}

fn server_hello(suite: u16, extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[9; 32]);
    body.push(0);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    handshake(2, &body)
}

fn certificate(der: &[u8]) -> Vec<u8> {
    let mut list = (der.len() as u32).to_be_bytes()[1..].to_vec();
    list.extend_from_slice(der);
    let mut body = (list.len() as u32).to_be_bytes()[1..].to_vec();
    body.extend_from_slice(&list);
    handshake(11, &body)
}

fn ssh_stream(banner: &str, lists: [&str; 6]) -> Vec<u8> {
    let mut payload = vec![20];
    payload.extend_from_slice(&[3; 16]);
    for list in lists.iter().chain(["", "", "", ""].iter()) {
        payload.extend_from_slice(&(list.len() as u32).to_be_bytes());
        payload.extend_from_slice(list.as_bytes());
    }
    payload.extend_from_slice(&[0, 0, 0, 0, 0]);
    let padding = 8 - (payload.len() + 5) % 8 + 4;
    let mut out = format!("{banner}\r\n").into_bytes();
    out.extend_from_slice(&((payload.len() + padding + 1) as u32).to_be_bytes());
    out.push(padding as u8);
    out.extend_from_slice(&payload);
    out.extend(std::iter::repeat_n(0, padding));
    out
}

const CLIENT: [u8; 4] = [10, 0, 0, 7];

/// TLS 1.2 to the gateway: split records, out-of-order and retransmitted segments.
fn tls12() -> Vec<Packet> {
    let server = ([10, 0, 0, 5], 443);
    let client = (CLIENT, 50000);
    let hello = records(22, &client_hello("pay.example.gov.in"), 4096);
    let mut flight = server_hello(0xc02f, &[]);
    flight.extend(certificate(&cert_der()));
    flight.extend(handshake(12, &[3, 0, 29, 32]));
    flight.extend(handshake(14, &[]));
    let flight = records(22, &flight, 300); // handshake messages span records
    let (first, second) = flight.split_at(flight.len() / 2);
    vec![
        tcp(client, server, 1000, SYN, &[]),
        tcp(server, client, 5000, SYN | ACK, &[]),
        tcp(client, server, 1001, PSH_ACK, &hello),
        tcp(server, client, 5001 + first.len() as u32, PSH_ACK, second), // arrives first
        tcp(server, client, 5001, PSH_ACK, first),
        tcp(server, client, 5001, PSH_ACK, first), // retransmission
    ]
}

/// TLS 1.3 with the hybrid ML-KEM group, over IPv6.
fn tls13_hybrid() -> Vec<Packet> {
    let server = (
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        443,
    );
    let client = (
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
        50001,
    );
    let mut extensions = extension(43, &[0x03, 0x04]);
    extensions.extend(extension(51, &[0x11, 0xec, 0, 2, 1, 2]));
    let mut flight = records(22, &server_hello(0x1302, &extensions), 4096);
    flight.extend(records(20, &[1], 16));
    flight.extend(records(23, &[0xaa; 64], 64)); // encrypted from here on
    vec![
        tcp6(client, server, 7000, SYN, &[]),
        tcp6(
            client,
            server,
            7001,
            PSH_ACK,
            &records(22, &client_hello("ledger.example.gov.in"), 4096),
        ),
        tcp6(server, client, 9000, PSH_ACK, &flight),
    ]
}

fn ssh() -> Vec<Packet> {
    let server = ([10, 0, 0, 6], 22);
    let client = (CLIENT, 50100);
    let client_stream = ssh_stream(
        "SSH-2.0-OpenSSH_9.9",
        [
            "mlkem768x25519-sha256,curve25519-sha256",
            "ssh-ed25519,rsa-sha2-512",
            "aes256-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-256",
        ],
    );
    let server_stream = ssh_stream(
        "SSH-2.0-OpenSSH_8.9",
        [
            "curve25519-sha256,mlkem768x25519-sha256",
            "rsa-sha2-512",
            "aes128-ctr,aes256-gcm@openssh.com",
            "aes128-ctr,aes256-gcm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-256",
        ],
    );
    vec![
        tcp(client, server, 100, SYN, &[]),
        tcp(server, client, 900, SYN | ACK, &[]),
        tcp(server, client, 901, PSH_ACK, &server_stream),
        tcp(client, server, 101, PSH_ACK, &client_stream),
    ]
}

fn analyse_file(bytes: &[u8]) -> Findings {
    let connections =
        read_capture(bytes, &Deadline::after(std::time::Duration::from_secs(5))).unwrap();
    analyse(
        &connections,
        "captures/gateway.pcap",
        ".",
        &ScanOptions::default(),
    )
    .0
}

fn protocols(findings: &Findings) -> Vec<&ProtocolFinding> {
    findings
        .observations
        .iter()
        .filter_map(|o| match &o.finding {
            Finding::Protocol(p) => Some(p),
            _ => None,
        })
        .collect()
}

fn algorithm_ids(findings: &Findings) -> BTreeSet<String> {
    findings
        .observations
        .iter()
        .filter_map(|o| match &o.finding {
            Finding::Algorithm(f) => Some(f.algorithm.id.clone()),
            _ => None,
        })
        .collect()
}

// ---- tests -----------------------------------------------------------------------------------

#[test]
fn tls12_handshakes_reassembled_from_disordered_segments() {
    let findings = analyse_file(&pcap_file(&tls12()));
    let tls = protocols(&findings);
    assert_eq!(tls.len(), 1);
    assert_eq!(tls[0].version.as_deref(), Some("1.2"));
    assert_eq!(
        tls[0].cipher_suites,
        vec!["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned()]
    );
    assert_eq!(
        tls[0].groups,
        vec!["x25519".to_owned()],
        "the ECDHE group comes from ServerKeyExchange"
    );
    let ids = algorithm_ids(&findings);
    for id in ["aes", "rsa", "x25519"] {
        assert!(ids.contains(id), "{id} in {ids:?}");
    }
    for observation in &findings.observations {
        assert_eq!(observation.surface, Surface::Runtime);
        assert_eq!(observation.evidence.kind, EvidenceKind::Handshake);
        assert_eq!(
            observation.evidence.matched_token, "pay.example.gov.in",
            "attributed by server name"
        );
        assert_eq!(observation.location.path, "captures/gateway.pcap");
        assert!(observation.location.byte_offset.is_some());
    }
    let certificate = findings
        .observations
        .iter()
        .find(|o| matches!(o.finding, Finding::Certificate(_)))
        .expect("the certificate crossed the wire in clear");
    assert_eq!(certificate.evidence.rule_id, "capture.tls.certificate");
}

#[test]
fn tls13_hybrid_group_over_ipv6_in_pcapng() {
    let findings = analyse_file(&pcapng_file(&tls13_hybrid()));
    let tls = protocols(&findings);
    assert_eq!(tls[0].version.as_deref(), Some("1.3"));
    assert_eq!(tls[0].groups, vec!["X25519MLKEM768".to_owned()]);
    assert_eq!(
        tls[0].cipher_suites,
        vec!["TLS_AES_256_GCM_SHA384".to_owned()]
    );
    assert!(algorithm_ids(&findings).contains("x25519-mlkem768"));
    assert!(
        !findings
            .observations
            .iter()
            .any(|o| matches!(o.finding, Finding::Certificate(_))),
        "TLS 1.3 certificates are encrypted"
    );
    assert_eq!(
        findings.observations[0].evidence.matched_token,
        "ledger.example.gov.in"
    );
}

#[test]
fn ssh_negotiation_follows_the_client_preference() {
    let findings = analyse_file(&pcap_file(&ssh()));
    let ssh = protocols(&findings);
    assert_eq!(ssh.len(), 1);
    assert_eq!(ssh[0].protocol, ProtocolKind::Ssh);
    assert_eq!(
        ssh[0].cipher_suites,
        vec![
            "mlkem768x25519-sha256".to_owned(),
            "rsa-sha2-512".to_owned(),
            "aes256-gcm@openssh.com".to_owned()
        ],
        "client order wins; an AEAD cipher makes the MAC irrelevant"
    );
    assert_eq!(
        findings.observations[0].evidence.matched_token,
        "10.0.0.6:22"
    );
    let ids = algorithm_ids(&findings);
    assert!(
        ids.contains("x25519-mlkem768") && ids.contains("rsa") && ids.contains("aes"),
        "{ids:?}"
    );
}

#[test]
fn repeated_handshakes_are_one_finding_and_mixed_captures_work() {
    let mut packets = tls12();
    // a second connection from another client port, same negotiation
    let mut again = tls12();
    for packet in &mut again {
        // rewrite the client port 50000 → 50002 wherever it appears in the TCP header
        let tcp_start = 14 + 20;
        for at in [tcp_start, tcp_start + 2] {
            if packet.frame[at..at + 2] == 50000u16.to_be_bytes() {
                packet.frame[at..at + 2].copy_from_slice(&50002u16.to_be_bytes());
            }
        }
    }
    packets.extend(again);
    packets.extend(ssh());
    let findings = analyse_file(&pcap_file(&packets));
    assert_eq!(
        protocols(&findings).len(),
        2,
        "one TLS configuration, one SSH"
    );
}

#[test]
fn hostile_captures_fail_cleanly() {
    let deadline = Deadline::after(std::time::Duration::from_secs(5));
    assert!(read_capture(&b"not a capture"[..], &deadline).is_err());
    // a record header claiming a gigantic packet
    let mut corrupt = pcap_file(&[]);
    corrupt.extend_from_slice(&[0; 8]);
    corrupt.extend_from_slice(&u32::MAX.to_le_bytes());
    corrupt.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        read_capture(&corrupt[..], &deadline)
            .err()
            .unwrap()
            .contains("corrupt")
    );
    // truncation mid-packet keeps what was read
    let mut truncated = pcap_file(&tls12());
    truncated.truncate(truncated.len() - 10);
    assert!(read_capture(&truncated[..], &deadline).is_ok());
    // random bytes after a valid header never panic
    let mut noise = pcap_file(&[]);
    noise.extend((0..20_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    let _ = read_capture(&noise[..], &deadline);
    // handshake parsers on garbage
    let _ = handshake_messages(&[0x16, 3, 3, 0xff, 0xff, 1, 2, 3]);
    let _ = parse_server(&[(2, vec![3, 3])]);
    let _ = parse_client_hello(&[0; 10]);
    let _ = ssh_kexinit(b"SSH-2.0-x\r\n\xff\xff\xff\xff\x05");
}

#[test]
fn capture_names_route_to_this_scanner() {
    assert!(is_capture("edge/gateway.pcapng"));
    assert!(is_capture("TRACE.PCAP"));
    assert!(!is_capture("capture.py"));
}
