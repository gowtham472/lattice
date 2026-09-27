// Everything the page states as fact, in one place. Values come from LATTICE 1.0.1 runs on the
// demo estate (examples/demo-estate), the OpenSSL 3.5.5 golden scan, the risk policy
// (knowledge/policy.toml) and the recorded tracer and sandbox outputs.

export const REPO = "https://github.com/gowtham472/lattice";

export const stats = [
  { to: 0.18, suffix: " s", label: "to scan the demo estate: 19 files, 49 assets" },
  { to: 1033, label: "assets found in OpenSSL 3.5.5 source in 2.9 s" },
  { to: 9, label: "kinds of evidence, from source to live processes" },
  { to: 234, label: "tests, run on Linux, Windows and macOS" },
];

// Mosca's inputs, as the engine uses them (knowledge/policy.toml)
export const policy = {
  assessmentYear: 2026,
  qDayEarliest: 2030,
  qDayLatest: 2035,
  baseYears: 0.25,
  yearsPerPoint: 0.04,
};

export const dataClasses = [
  { id: "identity", name: "Identity", example: "Aadhaar, passport, biometrics", years: 25 },
  { id: "health", name: "Health", example: "patient records, ABHA", years: 20 },
  { id: "financial", name: "Financial", example: "card numbers, UPI, ledgers", years: 10 },
  { id: "personal", name: "Personal", example: "email, phone, address", years: 10 },
  { id: "credential", name: "Credential", example: "tokens, passwords, OTPs", years: 5 },
  { id: "public", name: "Public", example: "checksums, caches", years: 0 },
] as const;

export type Surface = {
  id: string;
  name: string;
  what: string;
  path: string;
  rule: string;
  token: string;
  finding: string;
  verdict: string;
  tone: "late" | "urgent" | "safe" | "info";
  liveness: "Capable" | "Configured" | "Confirmed";
  reason: string;
  grade?: string;
};

export const surfaces: Surface[] = [
  {
    id: "source", name: "Source code", what: "Python, Java, Go, C, C++, JavaScript, TypeScript, Rust and C#, parsed into syntax trees.",
    path: "identity-service/src/main/java/in/gov/identity/AadhaarVault.java:10", rule: "java.jca.secret-key-spec", token: "SecretKeySpec",
    finding: "AES-ECB (PKCS5) protecting Aadhaar data", verdict: "High priority, wave 1: replace with AES-256-GCM", tone: "urgent", liveness: "Configured", reason: "selected in code by SecretKeySpec", grade: "C",
  },
  {
    id: "binary", name: "Binaries and libraries", what: "ELF, PE and Mach-O symbols, constant tables, algorithm OIDs and library versions.",
    path: "lattice 1.0.1, its own release binary", rule: "binary symbols and constant tables", token: "self-CBOM",
    finding: "ML-KEM and ML-DSA-65 compiled in", verdict: "Post-quantum: retain. Every release ships this scan of itself.", tone: "safe", liveness: "Capable", reason: "compiled into the binary",
  },
  {
    id: "pki", name: "Certificates and keys", what: "X.509, PKCS#1 and #8, SEC1 and OpenSSH. Keys are kept as fingerprints, never copied.",
    path: "gateway/tls/legacy.key", rule: "pki.pem.pkcs1", token: "unencrypted private key",
    finding: "RSA-1024 private key, unencrypted on disk", verdict: "Critical: rotate into an HSM or cloud KMS", tone: "late", liveness: "Confirmed", reason: "reachable from the gateway listener, listen 443 ssl", grade: "C",
  },
  {
    id: "config", name: "Server configuration", what: "nginx, Apache, HAProxy, OpenSSL, sshd and Postfix: protocols, suites and listeners.",
    path: "gateway/nginx.conf:8", rule: "config.directive.ssl_ciphers", token: "ssl_ciphers",
    finding: "3DES-CBC offered by the TLS gateway", verdict: "Critical, wave 1: a one-line change to AES-256-GCM", tone: "urgent", liveness: "Confirmed", reason: "reachable from the gateway listener, listen 443 ssl", grade: "C",
  },
  {
    id: "iac", name: "Infrastructure as code", what: "Cloud key specs from Terraform and CloudFormation.",
    path: "infra/kms.tf:1", rule: "config.custody.aws_kms_key", token: "aws_kms_key.statement_signing",
    finding: "RSA-2048 signing key held in AWS KMS", verdict: "Wave 4: generate an ML-DSA-65 key inside the KMS", tone: "info", liveness: "Configured", reason: "selected by infrastructure as code at infra/kms.tf:1", grade: "C",
  },
  {
    id: "container", name: "Container images", what: "docker save and OCI archives, layer by layer, with deleted files removed.",
    path: "images/payments-api-4.2.0.tar!/var/lib/dpkg/status", rule: "installed package records", token: "OpenSSL 3.0.13",
    finding: "OpenSSL 3.0.13 inside the payments image", verdict: "Not post-quantum capable. OpenSSL 3.5.0 ships ML-KEM and ML-DSA.", tone: "urgent", liveness: "Capable", reason: "the library can do it; nothing yet shows it in use",
  },
  {
    id: "capture", name: "Packet captures", what: "TLS and SSH handshakes: version, suite, group and certificates. Payloads are never read.",
    path: "captures/edge-traffic.pcap", rule: "capture.tls.handshake", token: "pay.example.gov.in",
    finding: "TLS 1.0 negotiated on the wire", verdict: "Confirmed, matched to the nginx listener by server name", tone: "late", liveness: "Confirmed", reason: "observed in live traffic at edge-traffic.pcap", grade: "B",
  },
  {
    id: "trace", name: "Running processes", what: "Kernel uprobes on OpenSSL, BoringSSL, AWS-LC, ring and Go. Java through its Flight Recorder.",
    path: "lattice-srv, rustls on AWS-LC, 12 s", rule: "trace.algorithm", token: "EVP_PKEY_kem_new_raw_public_key",
    finding: "ML-KEM-768 called by the running server", verdict: "Confirmed: hybrid X25519MLKEM768 is really in use", tone: "safe", liveness: "Confirmed", reason: "called by a running process",
  },
  {
    id: "custody", name: "Key custody", what: "PKCS#11 tokens, TPMs, Vault seals and cloud HSM or KMS keys.",
    path: "infra/kms.tf:7", rule: "config.custody.google_kms_crypto_key", token: "google_kms_crypto_key.device_attestation",
    finding: "ECDSA P-256 key held in Google Cloud KMS", verdict: "Recorded in the CBOM as secured by the KMS", tone: "info", liveness: "Configured", reason: "selected by infrastructure as code at infra/kms.tf:7", grade: "C",
  },
];

// What `lattice trace` recorded inside LATTICE's own server (rustls on AWS-LC) while curl connected
export const trace = [
  { fn: "X25519_keypair", alg: "X25519", kind: "v", calls: 3 },
  { fn: "EVP_PKEY_kem_new_raw_public_key", alg: "ML-KEM-768", kind: "q", calls: 2 },
  { fn: "EVP_aead_aes_256_gcm_tls13", alg: "AES-256-GCM", kind: "s", calls: 12 },
  { fn: "EVP_aead_chacha20_poly1305", alg: "ChaCha20-Poly1305", kind: "s", calls: 4 },
  { fn: "ECDSA_sign", alg: "ECDSA", kind: "v", calls: 4 },
  { fn: "aes_hw_set_encrypt_key", alg: "AES-256", kind: "s", calls: 97 },
] as const;

export type Wave = { n: number; name: string; due: string; weeks: number; count: number; items: { name: string; where: string; action: string; weeks: number }[] };

export const waves: Wave[] = [
  {
    n: 1, name: "Urgent quick wins", due: "2027", weeks: 9.9, count: 3, items: [
      { name: "3DES-CBC", where: "gateway", action: "replace with AES-256-GCM", weeks: 1.4 },
      { name: "TLS 1.0", where: "gateway", action: "upgrade to TLS 1.3 with the X25519MLKEM768 group", weeks: 0.8 },
      { name: "AES-ECB (PKCS5)", where: "identity-service", action: "replace with AES-256-GCM", weeks: 7.7 },
    ],
  },
  {
    n: 2, name: "Urgent re-engineering", due: "2028", weeks: 58.6, count: 7, items: [
      { name: "MD5", where: "payments-api", action: "replace with SHA-384", weeks: 8.1 },
      { name: "RSA-1024", where: "gateway", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 5.4 },
      { name: "RSA-1024 private key", where: "gateway", action: "rotate into an HSM or cloud KMS", weeks: 1.4 },
      { name: "RSA-2048", where: "payments-api", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 12.6 },
      { name: "RSA-2048", where: "payments-api image", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 17.6 },
      { name: "X.509 certificate", where: "gateway", action: "replace with an ML-DSA-65 certificate", weeks: 5.4 },
      { name: "MD5", where: "payments-api image", action: "replace with SHA-384", weeks: 8.1 },
    ],
  },
  {
    n: 3, name: "Planned migration", due: "2029", weeks: 65.6, count: 14, items: [
      { name: "X25519", where: "ledger", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 7.2 },
      { name: "ECDSA P-256", where: "ledger", action: "replace with ML-DSA-65", weeks: 12.2 },
      { name: "ECDH P-256", where: "payments-api image", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 2.2 },
      { name: "TLS 1.2", where: "payments-api image", action: "enable the X25519MLKEM768 group", weeks: 0.8 },
      { name: "RSA (SHA-256)", where: "payments-api image", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 8.1 },
      { name: "and 9 more", where: "", action: "", weeks: 35.1 },
    ],
  },
  {
    n: 4, name: "Opportunistic hygiene", due: "no deadline", weeks: 33.4, count: 10, items: [
      { name: "AES-128-GCM", where: "gateway", action: "replace with AES-256-GCM", weeks: 1.6 },
      { name: "HMAC (SHA-1)", where: "gateway", action: "upgrade to HMAC-SHA-256", weeks: 0.8 },
      { name: "RSA-2048", where: "infra", action: "replace with hybrid X25519 + ML-KEM-768", weeks: 2.4 },
      { name: "ECDSA P-256 key", where: "infra", action: "generate an ML-DSA-65 key inside the KMS", weeks: 1.9 },
      { name: "and 6 more", where: "", action: "", weeks: 26.7 },
    ],
  },
];

// the six probes `lattice sandbox-check` runs, with their recorded results
export const probes = [
  { id: "net", label: "Open a network connection", layer: "system call", expected: "denied" },
  { id: "exec", label: "Run another program", layer: "system call", expected: "denied" },
  { id: "outside", label: "Read a file outside the targets", layer: "filesystem", expected: "denied" },
  { id: "modify", label: "Modify a scan target", layer: "filesystem", expected: "denied" },
  { id: "read", label: "Read inside a scan target", layer: "filesystem", expected: "allowed" },
  { id: "write", label: "Write to the output folder", layer: "filesystem", expected: "allowed" },
] as const;

export type Runtime = {
  id: string;
  name: string;
  how: string;
  detail: string;
  listens: string[];
  reads: string;
  note: string;
};

// The runtimes `lattice trace` listens inside, and how (crates/lattice-tracer)
export const runtimes: Runtime[] = [
  {
    id: "openssl", name: "OpenSSL", how: "Kernel uprobes",
    detail: "Probes on libcrypto and libssl, in every running program that loads them.",
    listens: ["EVP_CIPHER_fetch", "EVP_SIGNATURE_fetch", "EVP_KEM_fetch", "RSA_generate_key_ex", "SSL_CTX_set1_groups_list"],
    reads: "the algorithm name, key size or cipher list the program asks for",
    note: "Setup is not use: every call inside OPENSSL_init_crypto and SSL_CTX_new_ex is ignored.",
  },
  {
    id: "boringssl", name: "BoringSSL", how: "Kernel uprobes",
    detail: "Its own entry points, where the function is the algorithm.",
    listens: ["X25519_keypair", "MLKEM768_encap", "EVP_aead_aes_256_gcm_tls13", "ECDSA_sign", "ED25519_sign"],
    reads: "the call itself: X25519_keypair is X25519",
    note: "Its TLS settings are real functions, so group and cipher lists are read too.",
  },
  {
    id: "awslc", name: "AWS-LC", how: "Kernel uprobes",
    detail: "Amazon's fork of BoringSSL, with ML-KEM and ML-DSA named by NID.",
    listens: ["EVP_PKEY_CTX_kem_set_params", "EVP_PKEY_kem_new_raw_public_key", "EVP_PKEY_CTX_pqdsa_set_params", "aes_hw_set_encrypt_key"],
    reads: "the NID or key size: NID 989 is ML-KEM-768, 256 bits is AES-256",
    note: "Symbols of the FIPS build, prefixed aws_lc_fips_, are read the same way.",
  },
  {
    id: "rustls", name: "rustls", how: "Kernel uprobes",
    detail: "Linked statically on AWS-LC or ring, found inside running Rust programs.",
    listens: ["aws_lc_0_45_0_X25519", "ring_core_0_17_14_aes_hw_set_encrypt_key", "chacha20_poly1305_seal", "x25519_scalar_mult_adx"],
    reads: "the versioned symbol, with its prefix stripped to the real function",
    note: "Recorded live inside LATTICE's own server: hybrid X25519MLKEM768 in use.",
  },
  {
    id: "go", name: "Go", how: "Uprobes, Go ABI",
    detail: "Go compiles crypto/... into every binary. Functions are found in .gopclntab, even when stripped.",
    listens: ["crypto/mlkem.GenerateKey768", "crypto/aes.NewCipher", "crypto/rsa.GenerateKey", "crypto/ecdsa.SignASN1", "crypto/md5.Sum"],
    reads: "Go's register arguments: a 32-byte key to crypto/aes is AES-256",
    note: "TLS key exchanges are read by their CurveID, so X25519MLKEM768 is told from X25519.",
  },
  {
    id: "java", name: "Java", how: "Flight Recorder",
    detail: "The JVM records it itself. A recording starts with jcmd and ends on its own; nothing is injected.",
    listens: ["jdk.SecurityProviderService", "jdk.TLSHandshake", "jdk.X509Certificate"],
    reads: "Cipher AES/GCM/NoPadding from SunJCE, the TLS suite, the certificate key",
    note: "No root for your own JVMs. Lookups from static initialisers count as setup.",
  },
];
