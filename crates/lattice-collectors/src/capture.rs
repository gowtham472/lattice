//! Runtime evidence from packet captures (pcap and pcapng).
//!
//! Source and configuration say what a system *can* negotiate; a capture shows what it *does*.
//! This collector reassembles the start of each TCP connection and reads the unencrypted
//! handshake: for TLS the ClientHello (server name), ServerHello (version, cipher suite, TLS 1.3
//! key-exchange group), ServerKeyExchange (TLS 1.2 ECDHE group) and, before TLS 1.3, the server's
//! certificate chain; for SSH both KEXINIT messages, from which the negotiated algorithms follow.
//! Everything reported is marked [`Surface::Runtime`], which normalisation turns into
//! `Confirmed` liveness.
//!
//! Only handshake metadata is read. Application data, client addresses and anything encrypted
//! are never decoded or stored. Captures are streamed, and packets, flows, bytes per flow and
//! wall time are all bounded.

use crate::sandbox::Deadline;
use crate::{Artifact, CollectionFailure, Collector, Findings, ScanOptions, ScanStats, pki};
use lattice_core::names;
use lattice_core::{
    Evidence, EvidenceKind, Finding, Location, Observation, ProtocolFinding, ProtocolKind,
    Registry, Surface,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::IpAddr;
use std::path::Path;

const COLLECTOR: &str = "capture";
const RULE_VERSION: &str = "2026.09.1";
const MAX_PACKETS: u64 = 20_000_000;
const MAX_PACKET_BYTES: usize = 262_144;
const MAX_BLOCK_BYTES: usize = 16 << 20;
const MAX_FLOWS: usize = 200_000;
/// Enough of each direction for a full handshake including a long certificate chain.
const MAX_STREAM_BYTES: usize = 96 * 1024;
const MAX_SEGMENTS: usize = 512;

pub fn is_capture(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".pcap", ".pcapng", ".cap"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// Scans one capture file. Never panics and never runs past its time budget.
pub fn scan_capture(
    path: &Path,
    report: &str,
    component: &str,
    options: &ScanOptions,
) -> (Findings, Vec<CollectionFailure>, ScanStats) {
    let result = crate::sandbox::isolate(options.archive_timeout, |deadline| {
        let file = File::open(path).map_err(|e| format!("could not open: {}", e.kind()))?;
        let connections = read_capture(BufReader::new(file), deadline)?;
        Ok(analyse(&connections, report, component, options))
    });
    match result {
        Ok((findings, stats)) => (findings, Vec::new(), stats),
        Err(reason) => (
            Findings::default(),
            vec![CollectionFailure {
                path: report.to_owned(),
                collector: COLLECTOR.into(),
                reason,
            }],
            ScanStats::default(),
        ),
    }
}

// ---- capture formats -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
struct Endpoint {
    ip: IpAddr,
    port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

/// One direction of a TCP connection: segments by absolute sequence number.
#[derive(Default)]
struct Direction {
    syn: Option<u32>,
    segments: Vec<(u32, Vec<u8>)>,
    stored: usize,
    /// File offset of the first packet carrying data, for evidence.
    first_offset: Option<u64>,
}

impl Direction {
    /// The contiguous bytes from the start of the stream (retransmissions and overlaps
    /// resolved, stopping at the first gap).
    fn assemble(&self) -> Vec<u8> {
        let Some(base) = self
            .syn
            .map(|s| s.wrapping_add(1))
            .or_else(|| self.segments.iter().map(|(s, _)| *s).min())
        else {
            return Vec::new();
        };
        let mut ordered: Vec<(u32, &Vec<u8>)> = self
            .segments
            .iter()
            .map(|(s, d)| (s.wrapping_sub(base), d))
            .collect();
        ordered.sort_by_key(|(offset, _)| *offset);
        let mut out: Vec<u8> = Vec::new();
        for (offset, data) in ordered {
            let offset = offset as usize;
            if offset > out.len() || offset > MAX_STREAM_BYTES {
                break;
            }
            let skip = out.len() - offset;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out.truncate(MAX_STREAM_BYTES);
        out
    }
}

#[derive(Default)]
struct Connection {
    /// Directions keyed by sender.
    directions: HashMap<Endpoint, Direction>,
    /// The endpoint that sent the initial SYN, when seen.
    initiator: Option<Endpoint>,
}

type Connections = BTreeMap<(Endpoint, Endpoint), Connection>;

/// Reads and analyses an in-memory capture without isolation, for the fuzz targets.
#[cfg(feature = "fuzzing")]
pub(crate) fn analyse_bytes(bytes: &[u8], deadline: &Deadline) -> Result<(), String> {
    let connections = read_capture(std::io::Cursor::new(bytes), deadline)?;
    analyse(&connections, "fuzz.pcap", "fuzz", &ScanOptions::default());
    Ok(())
}

fn read_capture<R: Read>(mut reader: R, deadline: &Deadline) -> Result<Connections, String> {
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "file too short to be a capture")?;
    let mut connections = Connections::new();
    let mut sink = |linktype: u32, frame: &[u8], offset: u64| {
        if let Some(packet) = parse_frame(linktype, frame) {
            record(&mut connections, packet, offset);
        }
    };
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => {
            pcap(reader, false, deadline, &mut sink)?
        }
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => {
            pcap(reader, true, deadline, &mut sink)?
        }
        [0x0a, 0x0d, 0x0d, 0x0a] => pcapng(reader, deadline, &mut sink)?,
        _ => return Err("not a pcap or pcapng capture".into()),
    }
    Ok(connections)
}

fn u16_at(bytes: &[u8], at: usize, big: bool) -> Option<u16> {
    let b: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(if big {
        u16::from_be_bytes(b)
    } else {
        u16::from_le_bytes(b)
    })
}

fn u32_at(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let b: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    })
}

fn pcap<R: Read>(
    mut reader: R,
    big: bool,
    deadline: &Deadline,
    sink: &mut impl FnMut(u32, &[u8], u64),
) -> Result<(), String> {
    let mut header = [0u8; 20];
    reader
        .read_exact(&mut header)
        .map_err(|_| "truncated pcap header")?;
    let linktype = u32_at(&header, 16, big).unwrap_or(1) & 0x0fff_ffff;
    let mut offset = 24u64;
    let mut record = [0u8; 16];
    let mut frame = Vec::new();
    for count in 0..MAX_PACKETS {
        if count % 4096 == 0 {
            deadline.check()?;
        }
        match reader.read_exact(&mut record) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
        let length = u32_at(&record, 8, big).unwrap_or(0) as usize;
        if length > MAX_PACKET_BYTES {
            return Err(format!(
                "packet at offset {offset} claims {length} bytes; capture is corrupt"
            ));
        }
        frame.resize(length, 0);
        if reader.read_exact(&mut frame).is_err() {
            return Ok(()); // truncated final packet
        }
        sink(linktype, &frame, offset);
        offset += 16 + length as u64;
    }
    Ok(())
}

fn pcapng<R: Read>(
    mut reader: R,
    deadline: &Deadline,
    sink: &mut impl FnMut(u32, &[u8], u64),
) -> Result<(), String> {
    // The section header's type was consumed as the magic; its length follows.
    let mut big = false;
    let mut interfaces: Vec<u32> = Vec::new();
    let mut offset = 0u64;
    let mut block_type = [0x0a, 0x0d, 0x0d, 0x0a];
    let mut body = Vec::new();
    for count in 0..MAX_PACKETS {
        if count % 4096 == 0 {
            deadline.check()?;
        }
        let mut length_bytes = [0u8; 4];
        if count > 0 {
            match reader.read_exact(&mut block_type) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.to_string()),
            }
        }
        if reader.read_exact(&mut length_bytes).is_err() {
            return Ok(());
        }
        let section = block_type == [0x0a, 0x0d, 0x0d, 0x0a];
        if section {
            // byte order comes from the section header's magic, read before the length is trusted
            let mut bom = [0u8; 4];
            reader
                .read_exact(&mut bom)
                .map_err(|_| "truncated section header")?;
            big = match bom {
                [0x1a, 0x2b, 0x3c, 0x4d] => true,
                [0x4d, 0x3c, 0x2b, 0x1a] => false,
                _ => return Err("pcapng section header has an invalid byte-order magic".into()),
            };
            interfaces.clear();
        }
        let length = u32_at(&length_bytes, 0, big).unwrap_or(0) as usize;
        let consumed = if section { 12 } else { 8 };
        if length < consumed + 4 || length > MAX_BLOCK_BYTES || !length.is_multiple_of(4) {
            return Err(format!(
                "pcapng block at offset {offset} has invalid length {length}"
            ));
        }
        body.resize(length - consumed, 0);
        if reader.read_exact(&mut body).is_err() {
            return Ok(());
        }
        let body = &body[..body.len() - 4]; // trailing length copy
        let kind = u32_at(&block_type, 0, big).unwrap_or(0);
        match kind {
            // interface description: the link type for later packets
            1 => interfaces.push(u32::from(u16_at(body, 0, big).unwrap_or(1))),
            // enhanced packet
            6 => {
                let interface = u32_at(body, 0, big).unwrap_or(0) as usize;
                let captured = u32_at(body, 12, big).unwrap_or(0) as usize;
                if let (Some(&linktype), Some(frame)) =
                    (interfaces.get(interface), body.get(20..20 + captured))
                {
                    sink(linktype, frame, offset);
                }
            }
            // simple packet: always interface 0
            3 => {
                if let (Some(&linktype), Some(frame)) = (interfaces.first(), body.get(4..)) {
                    let original = u32_at(body, 0, big).unwrap_or(0) as usize;
                    sink(linktype, &frame[..frame.len().min(original)], offset);
                }
            }
            // obsolete packet block
            2 => {
                let interface = u16_at(body, 0, big).unwrap_or(0) as usize;
                let captured = u32_at(body, 12, big).unwrap_or(0) as usize;
                if let (Some(&linktype), Some(frame)) =
                    (interfaces.get(interface), body.get(20..20 + captured))
                {
                    sink(linktype, frame, offset);
                }
            }
            _ => {}
        }
        offset += length as u64;
    }
    Ok(())
}

// ---- link, network and transport layers ----------------------------------------------------

struct Segment<'a> {
    source: Endpoint,
    destination: Endpoint,
    seq: u32,
    syn: bool,
    ack: bool,
    payload: &'a [u8],
}

fn parse_frame(linktype: u32, frame: &[u8]) -> Option<Segment<'_>> {
    let ip = match linktype {
        // Ethernet, with up to two VLAN tags
        1 => {
            let mut at = 12;
            let mut ethertype = u16_at(frame, at, true)?;
            while matches!(ethertype, 0x8100 | 0x88a8) {
                at += 4;
                ethertype = u16_at(frame, at, true)?;
            }
            matches!(ethertype, 0x0800 | 0x86dd).then(|| frame.get(at + 2..))??
        }
        // raw IP
        12 | 14 | 101 | 228 | 229 => frame,
        // Linux cooked capture v1 and v2
        113 => frame.get(16..)?,
        276 => frame.get(20..)?,
        // BSD loopback (host order) and OpenBSD loopback (network order)
        0 | 108 => frame.get(4..)?,
        _ => return None,
    };
    let (source_ip, destination_ip, protocol, transport) = match ip.first()? >> 4 {
        4 => {
            let header = usize::from(ip.first()? & 0x0f) * 4;
            let total = usize::from(u16_at(ip, 2, true)?).min(ip.len());
            let fragment = u16_at(ip, 6, true)?;
            if fragment & 0x3fff != 0 {
                return None; // fragments carry no complete TCP header we can trust
            }
            let source: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            (
                IpAddr::from(source),
                IpAddr::from(destination),
                *ip.get(9)?,
                ip.get(header..total)?,
            )
        }
        6 => {
            let payload_length = usize::from(u16_at(ip, 4, true)?);
            let source: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            let mut next = *ip.get(6)?;
            let mut at = 40;
            let end = (40 + payload_length).min(ip.len());
            // hop-by-hop, routing and destination options; a fragment header ends the search
            while matches!(next, 0 | 43 | 60) {
                next = *ip.get(at)?;
                at += (usize::from(*ip.get(at + 1)?) + 1) * 8;
            }
            (
                IpAddr::from(source),
                IpAddr::from(destination),
                next,
                ip.get(at..end)?,
            )
        }
        _ => return None,
    };
    if protocol != 6 {
        return None;
    }
    let tcp = transport;
    let data_offset = usize::from(tcp.get(12)? >> 4) * 4;
    let flags = *tcp.get(13)?;
    Some(Segment {
        source: Endpoint {
            ip: source_ip,
            port: u16_at(tcp, 0, true)?,
        },
        destination: Endpoint {
            ip: destination_ip,
            port: u16_at(tcp, 2, true)?,
        },
        seq: u32_at(tcp, 4, true)?,
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        payload: tcp.get(data_offset..)?,
    })
}

fn record(connections: &mut Connections, segment: Segment<'_>, offset: u64) {
    let key = if segment.source <= segment.destination {
        (segment.source, segment.destination)
    } else {
        (segment.destination, segment.source)
    };
    if !connections.contains_key(&key) && connections.len() >= MAX_FLOWS {
        return;
    }
    let connection = connections.entry(key).or_default();
    if segment.syn && !segment.ack {
        connection.initiator = Some(segment.source);
    }
    let direction = connection.directions.entry(segment.source).or_default();
    if segment.syn {
        direction.syn = Some(segment.seq);
    }
    if segment.payload.is_empty()
        || direction.stored >= MAX_STREAM_BYTES
        || direction.segments.len() >= MAX_SEGMENTS
    {
        return;
    }
    direction.first_offset.get_or_insert(offset);
    let keep = segment
        .payload
        .len()
        .min(MAX_STREAM_BYTES - direction.stored);
    direction.stored += keep;
    direction
        .segments
        .push((segment.seq, segment.payload[..keep].to_vec()));
}

// ---- TLS -----------------------------------------------------------------------------------

#[derive(Default, Debug)]
struct ClientHello {
    server_name: Option<String>,
}

#[derive(Default, Debug)]
struct ServerHandshake {
    version: Option<u16>,
    cipher_suite: Option<u16>,
    group: Option<u16>,
    certificates: Vec<Vec<u8>>,
}

fn looks_like_tls(stream: &[u8]) -> bool {
    matches!(stream, [0x16, 0x03, 0x00..=0x04, ..])
}

/// Handshake messages from the start of a stream, reassembled across records, up to the first
/// non-handshake record (after which everything is encrypted).
fn handshake_messages(stream: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut joined: Vec<u8> = Vec::new();
    let mut at = 0;
    while let (Some(&kind), Some(length)) = (stream.get(at), u16_at(stream, at + 3, true)) {
        if kind != 0x16 {
            break;
        }
        let Some(fragment) = stream.get(at + 5..at + 5 + usize::from(length)) else {
            break;
        };
        joined.extend_from_slice(fragment);
        at += 5 + usize::from(length);
    }
    let mut messages = Vec::new();
    let mut cursor = 0;
    while let (Some(&kind), Some(length)) = (joined.get(cursor), joined.get(cursor + 1..cursor + 4))
    {
        let length =
            (usize::from(length[0]) << 16) | (usize::from(length[1]) << 8) | usize::from(length[2]);
        let Some(body) = joined.get(cursor + 4..cursor + 4 + length) else {
            break;
        };
        messages.push((kind, body.to_vec()));
        cursor += 4 + length;
    }
    messages
}

/// Extensions of a hello message: (type, data).
fn extensions(body: &[u8], at: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let Some(total) = u16_at(body, at, true) else {
        return out;
    };
    let end = (at + 2 + usize::from(total)).min(body.len());
    let mut cursor = at + 2;
    while cursor + 4 <= end {
        let (Some(kind), Some(length)) =
            (u16_at(body, cursor, true), u16_at(body, cursor + 2, true))
        else {
            break;
        };
        let Some(data) = body.get(cursor + 4..cursor + 4 + usize::from(length)) else {
            break;
        };
        out.push((kind, data));
        cursor += 4 + usize::from(length);
    }
    out
}

fn parse_client_hello(body: &[u8]) -> ClientHello {
    let mut hello = ClientHello::default();
    // version(2) random(32) session_id
    let Some(&session) = body.get(34) else {
        return hello;
    };
    let mut at = 35 + usize::from(session);
    let Some(suites) = u16_at(body, at, true) else {
        return hello;
    };
    at += 2 + usize::from(suites);
    let Some(&compression) = body.get(at) else {
        return hello;
    };
    at += 1 + usize::from(compression);
    for (kind, data) in extensions(body, at) {
        // server_name: list length(2), name type(1) = host_name, length(2), name
        if kind == 0 && data.get(2) == Some(&0) {
            let length = usize::from(u16_at(data, 3, true).unwrap_or(0));
            if let Some(name) = data.get(5..5 + length) {
                let name = String::from_utf8_lossy(name).to_ascii_lowercase();
                if !name.is_empty()
                    && name.len() <= 253
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                {
                    hello.server_name = Some(name);
                }
            }
        }
    }
    hello
}

fn parse_server(messages: &[(u8, Vec<u8>)]) -> Option<ServerHandshake> {
    let mut server = ServerHandshake::default();
    let (_, hello) = messages.iter().find(|(kind, _)| *kind == 2)?;
    server.version = u16_at(hello, 0, true);
    let session = usize::from(*hello.get(34)?);
    let at = 35 + session;
    server.cipher_suite = u16_at(hello, at, true);
    for (kind, data) in extensions(hello, at + 3) {
        match kind {
            43 => server.version = u16_at(data, 0, true), // supported_versions: the selected one
            51 => server.group = u16_at(data, 0, true),   // key_share: the selected group
            _ => {}
        }
    }
    for (kind, body) in messages {
        match *kind {
            // Certificate (visible before TLS 1.3): list length(3), then length(3) + DER each
            11 => {
                let mut at = 3;
                while let Some(length) = body.get(at..at + 3) {
                    let length = (usize::from(length[0]) << 16)
                        | (usize::from(length[1]) << 8)
                        | usize::from(length[2]);
                    let Some(der) = body.get(at + 3..at + 3 + length) else {
                        break;
                    };
                    if server.certificates.len() < 8 {
                        server.certificates.push(der.to_vec());
                    }
                    at += 3 + length;
                }
            }
            // ServerKeyExchange for ECDHE: curve_type 3 (named_curve), then the group
            12 if server.group.is_none() && body.first() == Some(&3) => {
                server.group = u16_at(body, 1, true)
            }
            _ => {}
        }
    }
    Some(server)
}

fn version_name(version: u16) -> Option<&'static str> {
    Some(match version {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1.0",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => return None,
    })
}

fn group_name(group: u16) -> Option<&'static str> {
    Some(match group {
        23 => "secp256r1",
        24 => "secp384r1",
        25 => "secp521r1",
        29 => "x25519",
        30 => "x448",
        256 => "ffdhe2048",
        257 => "ffdhe3072",
        258 => "ffdhe4096",
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        0x11eb => "SecP256r1MLKEM768",
        0x11ec => "X25519MLKEM768",
        0x11ed => "SecP384r1MLKEM1024",
        0x6399 => "X25519Kyber768Draft00",
        _ => return None,
    })
}

/// IANA names of the cipher suites worth recognising on the wire.
fn suite_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc011 => "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006b => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x0016 => "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        _ => return None,
    })
}

// ---- SSH -----------------------------------------------------------------------------------

/// The KEXINIT name-lists: kex, host key, cipher c→s, cipher s→c, MAC c→s, MAC s→c.
fn ssh_kexinit(stream: &[u8]) -> Option<Vec<Vec<String>>> {
    if !stream.starts_with(b"SSH-") {
        return None;
    }
    let banner_end = stream
        .windows(2)
        .position(|w| w == b"\r\n")
        .or_else(|| stream.iter().position(|&b| b == b'\n'))?;
    let mut at = banner_end
        + if stream.get(banner_end) == Some(&b'\r') {
            2
        } else {
            1
        };
    let packet_length = u32_at(stream, at, true)? as usize;
    let padding = usize::from(*stream.get(at + 4)?);
    let payload = stream.get(at + 5..at + 4 + packet_length.checked_sub(padding)?)?;
    if payload.first() != Some(&20) {
        return None;
    }
    at = 17; // message type + 16-byte cookie
    let mut lists = Vec::new();
    for _ in 0..6 {
        let length = u32_at(payload, at, true)? as usize;
        let text = std::str::from_utf8(payload.get(at + 4..at + 4 + length)?).ok()?;
        lists.push(
            text.split(',')
                .filter(|s| !s.is_empty())
                .take(64)
                .map(str::to_owned)
                .collect(),
        );
        at += 4 + length;
    }
    Some(lists)
}

/// RFC 4253 §7.1: the first client algorithm the server also supports.
fn negotiate(client: &[String], server: &[String]) -> Option<String> {
    client.iter().find(|name| server.contains(name)).cloned()
}

// ---- analysis ------------------------------------------------------------------------------

/// A negotiated configuration, deduplicated across connections.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Negotiated {
    server: String,
    protocol: ProtocolKind,
    version: String,
    suites: Vec<String>,
    groups: Vec<String>,
    algorithms: Vec<lattice_core::AlgorithmRef>,
}

fn analyse(
    connections: &Connections,
    report: &str,
    component: &str,
    options: &ScanOptions,
) -> (Findings, ScanStats) {
    let mut findings = Findings::default();
    let mut seen: BTreeMap<Negotiated, (u64, usize)> = BTreeMap::new();
    let mut certificates: BTreeMap<Vec<u8>, (String, u64)> = BTreeMap::new();
    let registry = Registry::active();

    for ((a, b), connection) in connections {
        let streams: Vec<(Endpoint, Vec<u8>, u64)> = [a, b]
            .iter()
            .filter_map(|endpoint| {
                let direction = connection.directions.get(endpoint)?;
                Some((
                    **endpoint,
                    direction.assemble(),
                    direction.first_offset.unwrap_or(0),
                ))
            })
            .collect();
        if streams.len() != 2 {
            continue;
        }

        // TLS: the server is the side whose handshake holds a ServerHello
        if streams.iter().all(|(_, s, _)| looks_like_tls(s)) {
            let parsed: Vec<_> = streams
                .iter()
                .map(|(e, s, o)| (*e, handshake_messages(s), *o))
                .collect();
            let Some((server, handshake, offset)) = parsed
                .iter()
                .find_map(|(e, m, o)| parse_server(m).map(|h| (*e, h, *o)))
            else {
                continue;
            };
            let client_hello = parsed
                .iter()
                .find(|(e, _, _)| *e != server)
                .and_then(|(_, m, _)| {
                    m.iter()
                        .find(|(k, _)| *k == 1)
                        .map(|(_, body)| parse_client_hello(body))
                })
                .unwrap_or_default();
            let Some(version) = handshake.version.and_then(version_name) else {
                continue;
            };
            let (_, protocol_version) = names::parse_protocol_version(version)
                .unwrap_or((ProtocolKind::Tls, version.to_owned()));
            let mut suites = Vec::new();
            let mut algorithms = Vec::new();
            if let Some(suite) = handshake
                .cipher_suite
                .and_then(suite_name)
                .and_then(names::parse_cipher_suite)
            {
                algorithms.extend(suite.algorithms().cloned());
                suites.push(suite.name);
            }
            let mut groups = Vec::new();
            if let Some(group) = handshake.group.and_then(group_name) {
                if let Some(algorithm) = names::resolve_group(group) {
                    algorithms.push(algorithm);
                }
                groups.push(group.to_owned());
            }
            for algorithm in &mut algorithms {
                if let Some(curve) = algorithm.params.curve.take() {
                    algorithm.params.curve = Some(registry.canonical_curve(&curve));
                }
            }
            algorithms.sort();
            algorithms.dedup();
            let name = client_hello
                .server_name
                .unwrap_or_else(|| server.to_string());
            for der in handshake.certificates {
                certificates
                    .entry(der)
                    .or_insert_with(|| (name.clone(), offset));
            }
            let entry = seen
                .entry(Negotiated {
                    server: name,
                    protocol: ProtocolKind::Tls,
                    version: protocol_version,
                    suites,
                    groups,
                    algorithms,
                })
                .or_insert((offset, 0));
            entry.1 += 1;
            continue;
        }

        // SSH: KEXINIT from both sides; the initiator (or the higher port) is the client
        let kex: Vec<_> = streams
            .iter()
            .filter_map(|(e, s, o)| ssh_kexinit(s).map(|lists| (*e, lists, *o)))
            .collect();
        if kex.len() == 2 {
            let client_index = match connection.initiator {
                Some(initiator) => usize::from(kex[1].0 == initiator),
                None => usize::from(kex[1].0.port > kex[0].0.port),
            };
            let (client, server) = (&kex[client_index], &kex[1 - client_index]);
            let chosen: Vec<String> = [0, 1, 2, 4]
                .iter()
                .filter_map(|&i| negotiate(&client.1[i], &server.1[i]))
                .filter(|name| {
                    !(name.starts_with("hmac") && is_aead_ssh(&client.1[2], &server.1[2]))
                })
                .collect();
            let algorithms: BTreeSet<_> = chosen.iter().filter_map(|n| names::resolve(n)).collect();
            let entry = seen
                .entry(Negotiated {
                    server: server.0.to_string(),
                    protocol: ProtocolKind::Ssh,
                    version: "2.0".into(),
                    suites: chosen,
                    groups: Vec::new(),
                    algorithms: algorithms.into_iter().collect(),
                })
                .or_insert((server.2, 0));
            entry.1 += 1;
        }
    }

    let evidence = |rule: &str, token: &str| Evidence {
        collector: COLLECTOR.into(),
        rule_id: rule.into(),
        rule_version: RULE_VERSION.into(),
        kind: EvidenceKind::Handshake,
        matched_token: token.chars().take(96).collect(),
    };
    let observe = |finding: Finding, offset: u64, rule: &str, token: &str| Observation {
        surface: Surface::Runtime,
        component: component.to_owned(),
        location: Location::at_offset(report, offset),
        finding,
        evidence: evidence(rule, token),
        usage: None,
    };
    for (negotiated, (offset, _connections)) in &seen {
        let rule = match negotiated.protocol {
            ProtocolKind::Ssh => "capture.ssh.kexinit",
            _ => "capture.tls.handshake",
        };
        findings.observations.push(observe(
            Finding::Protocol(ProtocolFinding {
                protocol: negotiated.protocol,
                version: Some(negotiated.version.clone()),
                cipher_suites: negotiated.suites.clone(),
                groups: negotiated.groups.clone(),
            }),
            *offset,
            rule,
            &negotiated.server,
        ));
        for algorithm in &negotiated.algorithms {
            findings.observations.push(observe(
                Finding::algorithm(algorithm.clone()),
                *offset,
                rule,
                &negotiated.server,
            ));
        }
    }

    // certificates the servers presented, through the PKI collector
    let collector = pki::PkiCollector::new();
    let deadline = Deadline::after(options.parse_timeout);
    for (index, (der, (server, offset))) in certificates.iter().enumerate() {
        let path = format!("{report}!/tls/{index}.der");
        let artifact = Artifact {
            path: &path,
            component,
            bytes: der,
        };
        let mut local = Findings::default();
        if collector.collect(&artifact, &deadline, &mut local).is_ok() {
            for mut observation in local.observations {
                observation.surface = Surface::Runtime;
                observation.location = Location::at_offset(report, *offset);
                observation.evidence = evidence("capture.tls.certificate", server);
                findings.observations.push(observation);
            }
        }
    }

    let stats = ScanStats {
        files_seen: 1,
        files_scanned: 1,
        bytes_scanned: connections
            .values()
            .flat_map(|c| c.directions.values())
            .map(|d| d.stored as u64)
            .sum(),
        skipped_too_large: 0,
        by_collector: BTreeMap::from([(COLLECTOR.to_owned(), 1)]),
        cache_hits: 0,
    };
    (findings, stats)
}

fn is_aead_ssh(client: &[String], server: &[String]) -> bool {
    negotiate(client, server)
        .is_some_and(|cipher| cipher.contains("gcm") || cipher.contains("poly1305"))
}

#[cfg(test)]
mod tests;
