#!/usr/bin/env python3
"""Builds the runtime and container artefacts of the demo estate.

* ``captures/edge-traffic.pcap``: real TLS handshakes between OpenSSL ``s_client`` and
  ``s_server`` (whatever OpenSSL is installed; 3.5+ is needed for the X25519MLKEM768 session),
  relayed through a local recorder. The TLS bytes are exactly what OpenSSL sent; only the
  Ethernet/IP/TCP framing is synthesised, with documentation addresses (RFC 5737), because the
  recorder sits at the socket layer rather than on a network interface.
* ``images/payments-api-4.2.0.tar``: a ``docker save``-format archive of the payments service:
  a Debian-style base layer with its dpkg database and CA bundle, the application layer, and a
  final layer that deletes a debug key with an OCI whiteout.

Usage: python3 scripts/make-demo-artefacts.py   (from the repository root, on Linux or WSL)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ESTATE = ROOT / "examples" / "demo-estate"
MTIME = 1_790_035_200  # 2026-09-22T00:00:00Z: fixed so the archive is reproducible


# ---- recording real TLS sessions -------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def openssl(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], check=True, capture_output=True, **kw)


def make_cert(directory: Path, name: str, key_args: list[str]) -> tuple[Path, Path]:
    key, cert = directory / f"{name}.key", directory / f"{name}.crt"
    openssl("req", "-x509", "-new", "-nodes", *key_args, "-sha256", "-days", "397",
            "-subj", f"/CN={name}/O=Demo Estate", "-addext", f"subjectAltName=DNS:{name}",
            "-keyout", str(key), "-out", str(cert))
    return cert, key


def record_session(cert: Path, key: Path, server_args: list[str], client_args: list[str], sni: str) -> list[tuple[bool, bytes]]:
    """Runs one handshake through a relay and returns the chunks (True = client to server)."""
    server_port, relay_port = free_port(), free_port()
    server = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(server_port), "-cert", str(cert), "-key", str(key),
         "-naccept", "1", "-quiet", *server_args],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.4)
    if server.poll() is not None:
        raise SystemExit(f"s_server {server_args} did not start: {server.stderr.read().decode()[:400]}")
    chunks: list[tuple[bool, bytes]] = []
    lock = threading.Lock()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", relay_port))
    listener.listen(1)

    def relay():
        client, _ = listener.accept()
        upstream = socket.create_connection(("127.0.0.1", server_port))

        def pump(source, sink, outbound):
            while True:
                try:
                    data = source.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    try:
                        sink.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                with lock:
                    chunks.append((outbound, data))
                sink.sendall(data)

        threads = [threading.Thread(target=pump, args=(client, upstream, True), daemon=True),
                   threading.Thread(target=pump, args=(upstream, client, False), daemon=True)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        client.close()
        upstream.close()

    thread = threading.Thread(target=relay, daemon=True)
    thread.start()
    subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{relay_port}", "-servername", sni,
                    "-brief", *client_args], input=b"", capture_output=True, timeout=20)
    thread.join(timeout=15)
    listener.close()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
    if not any(not outbound for outbound, _ in chunks):
        raise SystemExit(f"handshake for {sni} {client_args} failed: {server.stderr.read().decode()[:400]}")
    return chunks


# ---- pcap framing ----------------------------------------------------------------------------

class Pcap:
    def __init__(self):
        self.out = io.BytesIO()
        self.out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.clock = MTIME + 3600

    def packet(self, src, dst, seq, ack, flags, payload=b""):
        sport, dport = src[1], dst[1]
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                         socket.inet_aton(src[0]), socket.inet_aton(dst[0])) + tcp
        frame = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip
        self.clock += 0.001
        seconds = int(self.clock)
        self.out.write(struct.pack("<IIII", seconds, int((self.clock - seconds) * 1e6), len(frame), len(frame)))
        self.out.write(frame)

    def session(self, client, server, chunks):
        seq = {True: 1_000_000 + client[1], False: 7_000_000 + server[1]}
        self.packet(client, server, seq[True], 0, 0x02)
        self.packet(server, client, seq[False], seq[True] + 1, 0x12)
        seq[True] += 1
        seq[False] += 1
        self.packet(client, server, seq[True], seq[False], 0x10)
        for outbound, data in chunks:
            src, dst = (client, server) if outbound else (server, client)
            for start in range(0, len(data), 1448):
                segment = data[start:start + 1448]
                self.packet(src, dst, seq[outbound], seq[not outbound], 0x18, segment)
                seq[outbound] += len(segment)
        self.packet(client, server, seq[True], seq[False], 0x11)
        self.packet(server, client, seq[False], seq[True] + 1, 0x11)


def build_capture() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pay_cert, pay_key = make_cert(tmp, "pay.example.gov.in", ["-newkey", "rsa:2048"])
        ledger_cert, ledger_key = make_cert(tmp, "ledger.example.gov.in", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"])
        # static RSA key transport, CBC, HMAC-SHA1: no forward secrecy (3DES is compiled out of
        # current OpenSSL builds, so the legacy terminal uses the weakest suite still available)
        legacy = ["-cipher", "AES128-SHA:@SECLEVEL=0"]
        sessions = [
            # a point-of-sale terminal still speaking TLS 1.0 to the payment gateway
            (("198.51.100.23", 49152), ("192.0.2.10", 443),
             record_session(pay_cert, pay_key, ["-tls1", *legacy], ["-tls1", *legacy], "pay.example.gov.in")),
            # a browser: TLS 1.2 ECDHE-RSA; the certificate crosses the wire in clear
            (("198.51.100.77", 50811), ("192.0.2.10", 443),
             record_session(pay_cert, pay_key, ["-tls1_2"], ["-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-groups", "x25519"], "pay.example.gov.in")),
            # the ledger: TLS 1.3 with the hybrid post-quantum group
            (("198.51.100.8", 51200), ("192.0.2.30", 8443),
             record_session(ledger_cert, ledger_key, ["-tls1_3", "-groups", "X25519MLKEM768"], ["-tls1_3", "-groups", "X25519MLKEM768"], "ledger.example.gov.in")),
        ]
        pcap = Pcap()
        for client, server, chunks in sessions:
            pcap.session(client, server, chunks)
        target = ESTATE / "captures" / "edge-traffic.pcap"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(pcap.out.getvalue())
        print(f"wrote {target.relative_to(ROOT)} ({target.stat().st_size} bytes, {len(sessions)} sessions)")


# ---- docker save archive ---------------------------------------------------------------------

def tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), MTIME, 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


DPKG_STATUS = """Package: libc6
Status: install ok installed
Version: 2.39-0ubuntu8.4

Package: openssl
Status: install ok installed
Version: 3.0.13-0ubuntu3.5

Package: libssl3t64
Status: install ok installed
Version: 3.0.13-0ubuntu3.5

Package: python3.12
Status: install ok installed
Version: 3.12.3-1ubuntu0.8

Package: ca-certificates
Status: install ok installed
Version: 20240203
"""

OPENSSL_CNF = """openssl_conf = default_conf

[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=2
Groups = x25519:secp256r1
"""


def build_image() -> None:
    app = {f"srv/payments/app/{p.name}": p.read_bytes() for p in sorted((ESTATE / "payments-api" / "app").glob("*.py"))}
    ca = (ROOT / "crates" / "lattice-collectors" / "tests" / "fixtures" / "rsa2048-sha256.pem").read_bytes()
    debug_key = (ROOT / "crates" / "lattice-collectors" / "tests" / "fixtures" / "rsa1024-key.pem").read_bytes()
    layers = [
        tar_bytes({"var/lib/dpkg/status": DPKG_STATUS.encode(), "etc/ssl/openssl.cnf": OPENSSL_CNF.encode(),
                   "usr/local/share/ca-certificates/internal-ca.crt": ca}),
        tar_bytes({**app, "srv/payments/debug/signing.key": debug_key}),
        tar_bytes({"srv/payments/debug/.wh.signing.key": b""}),  # removed before release
    ]
    names = [f"{hashlib.sha256(layer).hexdigest()}/layer.tar" for layer in layers]
    config = json.dumps({
        "architecture": "amd64", "os": "linux",
        "config": {"Env": ["PATH=/usr/local/bin:/usr/bin", "PYTHONUNBUFFERED=1", "TLS_MIN_VERSION=TLSv1.2"],
                   "ExposedPorts": {"8000/tcp": {}}},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{hashlib.sha256(l).hexdigest()}" for l in layers]},
    }, sort_keys=True).encode()
    config_name = f"{hashlib.sha256(config).hexdigest()}.json"
    manifest = json.dumps([{"Config": config_name, "RepoTags": ["registry.example.gov.in/payments-api:4.2.0"], "Layers": names}]).encode()
    archive = tar_bytes({**dict(zip(names, layers)), config_name: config, "manifest.json": manifest})
    target = ESTATE / "images" / "payments-api-4.2.0.tar"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(archive)
    print(f"wrote {target.relative_to(ROOT)} ({len(archive)} bytes, {len(layers)} layers)")


if __name__ == "__main__":
    os.chdir(ROOT)
    build_capture()
    build_image()
