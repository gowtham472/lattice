# Demo estate

A small, realistic estate used to demonstrate and test LATTICE. Every cryptographic choice here is
deliberate, and most are wrong in the ways real estates are wrong. Keys are throwaway test keys.

| Service | Stack | What it shows |
|---|---|---|
| `payments-api` | Python, Flask | RSA-OAEP over card data behind an HTTP route (harvest-now risk), HMAC webhooks, MD5 checksums |
| `identity-service` | Java, Spring | RSA signatures on citizen tokens (forgery risk), AES-ECB over Aadhaar numbers, ECDSA P-256 |
| `gateway` | nginx | TLS 1.0 still enabled, 3DES suites, an RSA-1024 private key stored unencrypted |
| `ledger` | Go | TLS 1.3 with the X25519MLKEM768 hybrid group: already post-quantum |
| `notifications` | Node.js | AES-256-GCM (quantum-safe), HS256 JWTs |
| `infra` | Terraform | KMS keys: RSA-2048 signing, ECDSA P-256 |
| `images/payments-api-4.2.0.tar` | `docker save` archive | The payments service as shipped: OpenSSL 3.0.13 from dpkg, a TLS policy in `openssl.cnf`, and a debug key deleted by a later layer (not reported) |
| `captures/edge-traffic.pcap` | Packet capture | Real OpenSSL handshakes: a terminal on TLS 1.0 with static RSA and a browser on TLS 1.2 to the gateway, and the ledger on TLS 1.3 with X25519MLKEM768 |

The image and the capture are regenerated with `python3 scripts/make-demo-artefacts.py`. The TLS
bytes are exactly what OpenSSL sent; the IP/TCP framing uses documentation addresses.

```bash
lattice scan examples/demo-estate -o demo.cbom.json --report demo.report.json
lattice serve --root demo=examples/demo-estate
```
