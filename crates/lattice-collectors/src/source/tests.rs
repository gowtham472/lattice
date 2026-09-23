//! Source collector behaviour on real snippets in every supported language.

use super::*;
use crate::sandbox::Deadline;
use lattice_core::{ApiStyle, EntryKind};
use std::time::Duration;

fn scan(path: &str, source: &str) -> Findings {
    let collector = SourceCollector::new().expect("embedded rules load");
    let artifact = Artifact {
        path,
        component: ".",
        bytes: source.as_bytes(),
    };
    let deadline = Deadline::after(Duration::from_secs(10));
    let mut findings = Findings::default();
    collector
        .collect(&artifact, &deadline, &mut findings)
        .expect("scan succeeds");
    findings
}

/// (algorithm id, params) of every algorithm observation.
fn algorithms(findings: &Findings) -> Vec<(String, Params)> {
    findings
        .observations
        .iter()
        .filter_map(|o| match &o.finding {
            Finding::Algorithm(f) => Some((f.algorithm.id.clone(), f.algorithm.params.clone())),
            _ => None,
        })
        .collect()
}

fn find<'f>(findings: &'f Findings, id: &str) -> &'f Observation {
    findings
        .observations
        .iter()
        .find(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.id == id))
        .unwrap_or_else(|| panic!("no `{id}` observation in {:#?}", algorithms(findings)))
}

fn params_of(findings: &Findings, id: &str) -> Params {
    match &find(findings, id).finding {
        Finding::Algorithm(f) => f.algorithm.params.clone(),
        _ => unreachable!(),
    }
}

// ---- Java ------------------------------------------------------------------------------------

#[test]
fn java_jca_with_constants_refinement_and_route_entry() {
    let findings = scan(
        "src/Pay.java",
        r#"
        class Pay {
            static final String ALG = "AES/GCM/NoPadding";
            @PostMapping("/pay")
            public void pay(String cardNumber) throws Exception {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(1024);
                Cipher c = Cipher.getInstance(ALG);
                Cipher legacy = Cipher.getInstance("AES");
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                Signature s = Signature.getInstance("SHA256withECDSA");
                SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            }
        }"#,
    );
    // refinement: initialize(1024) is attributed to the bound KeyPairGenerator
    assert_eq!(params_of(&findings, "rsa").key_bits, Some(1024));

    // constant folding: the algorithm comes from a same-file constant
    let aes: Vec<_> = findings
        .observations
        .iter()
        .filter(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.id == "aes"))
        .collect();
    assert_eq!(aes.len(), 2);
    let from_constant = aes
        .iter()
        .find(|o| o.usage.as_ref().unwrap().algorithm_source == AlgorithmSource::Constant)
        .expect("constant-sourced AES");
    let Finding::Algorithm(gcm) = &from_constant.finding else {
        unreachable!()
    };
    assert_eq!(gcm.algorithm.params.mode.as_deref(), Some("gcm"));

    // the JCA default: bare "AES" is ECB
    assert!(aes.iter().any(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.params.mode.as_deref() == Some("ecb"))));

    assert!(algorithms(&findings).iter().any(|(id, _)| id == "sha-1"));
    assert_eq!(
        params_of(&findings, "ecdsa").digest.as_deref(),
        Some("sha-256")
    );
    assert_eq!(
        params_of(&findings, "pbkdf2").digest.as_deref(),
        Some("sha-256")
    );

    let pay = findings.functions.iter().find(|f| f.name == "pay").unwrap();
    assert_eq!(pay.entry.as_ref().unwrap().kind, EntryKind::HttpRoute);
    assert_eq!(pay.id, ".::src/Pay.java::Pay.pay");
    assert_eq!(pay.parameters, vec!["cardNumber".to_owned()]);

    let usage = find(&findings, "sha-1").usage.as_ref().unwrap();
    assert_eq!(usage.api_style, ApiStyle::Provider);
    assert_eq!(usage.function.as_deref(), Some(".::src/Pay.java::Pay.pay"));
    assert!(
        usage.identifiers.contains(&"md".to_owned()),
        "bound variable is recorded"
    );
}

#[test]
fn java_ec_curve_refinement_through_constructor_argument() {
    let findings = scan(
        "K.java",
        r#"class K { void k() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp384r1"));
        } }"#,
    );
    assert_eq!(
        params_of(&findings, "ecdsa").curve.as_deref(),
        Some("P-384")
    );
}

#[test]
fn java_tls_protocol_and_suites() {
    let findings = scan(
        "T.java",
        r#"class T { void t() throws Exception {
            SSLContext ctx = SSLContext.getInstance("TLSv1.1");
            socket.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
        } }"#,
    );
    let versions: Vec<_> = findings
        .observations
        .iter()
        .filter_map(|o| match &o.finding {
            Finding::Protocol(p) => p.version.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(versions, vec!["1.1".to_owned()]);
    let suites: Vec<_> = findings
        .observations
        .iter()
        .filter_map(|o| match &o.finding {
            Finding::Protocol(p) if !p.cipher_suites.is_empty() => Some(p.cipher_suites.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        suites,
        vec![vec!["TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_owned()]]
    );
    assert!(
        algorithms(&findings).iter().any(|(id, _)| id == "3des"),
        "suite components are inventoried"
    );
}

#[test]
fn comments_and_strings_do_not_produce_findings() {
    let findings = scan(
        "C.java",
        r#"class C {
            // Cipher.getInstance("DES") is forbidden here
            String doc = "call MessageDigest.getInstance(\"MD5\") never";
        }"#,
    );
    assert!(
        algorithms(&findings).is_empty(),
        "{:#?}",
        algorithms(&findings)
    );
}

// ---- Python ----------------------------------------------------------------------------------

#[test]
fn python_cryptography_hashlib_and_flask_route() {
    let findings = scan(
        "app/payments.py",
        r#"
ALG = "sha1"

@app.route("/pay", methods=["POST"])
def pay(card_number):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = ec.generate_private_key(ec.SECP384R1())
    c = Cipher(algorithms.AES(k), modes.GCM(iv))
    digest = hashlib.new(ALG, card_number)
    token = jwt.encode(payload, secret, algorithm="HS256")
    f = Fernet(fkey)
    return hashlib.md5(card_number).hexdigest()
"#,
    );
    assert_eq!(params_of(&findings, "rsa").key_bits, Some(2048));
    assert_eq!(
        params_of(&findings, "ecdsa").curve.as_deref(),
        Some("P-384")
    );
    let aes = params_of(&findings, "aes");
    assert!(aes.mode.as_deref() == Some("gcm") || aes.mode.as_deref() == Some("cbc"));
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "aes" && p.mode.as_deref() == Some("gcm"))
    );
    assert_eq!(
        find(&findings, "sha-1")
            .usage
            .as_ref()
            .unwrap()
            .algorithm_source,
        AlgorithmSource::Constant
    );
    assert_eq!(
        params_of(&findings, "hmac").digest.as_deref(),
        Some("sha-256"),
        "HS256 and Fernet both HMAC-SHA256"
    );
    assert!(
        algorithms(&findings).iter().any(|(id, p)| id == "aes"
            && p.key_bits == Some(128)
            && p.mode.as_deref() == Some("cbc")),
        "Fernet is AES-128-CBC"
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "md5"));

    let pay = findings.functions.iter().find(|f| f.name == "pay").unwrap();
    assert_eq!(pay.entry.as_ref().unwrap().kind, EntryKind::HttpRoute);
    let md5 = find(&findings, "md5").usage.as_ref().unwrap();
    assert!(
        md5.identifiers.contains(&"card_number".to_owned()),
        "argument names reach the classifier"
    );
    assert_eq!(md5.api_style, ApiStyle::Primitive);
}

#[test]
fn python_hmac_digestmod_and_pycryptodome_mode() {
    let findings = scan(
        "x.py",
        "mac = hmac.new(key, msg, hashlib.sha1)\nc = AES.new(key, AES.MODE_ECB)\n",
    );
    assert_eq!(
        params_of(&findings, "hmac").digest.as_deref(),
        Some("sha-1")
    );
    assert_eq!(params_of(&findings, "aes").mode.as_deref(), Some("ecb"));
}

// ---- C / C++ ---------------------------------------------------------------------------------

#[test]
fn c_openssl_with_macro_constants_and_low_level_apis() {
    let findings = scan(
        "src/crypto.c",
        r#"
#include <openssl/md5.h>
#define KEY_BITS 1024
int main(void) {
    RSA_generate_key_ex(rsa, KEY_BITS, e, NULL);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp384r1);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:!aNULL");
    SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:x25519");
    MD5(data, len, out);
    return 0;
}
"#,
    );
    assert_eq!(
        params_of(&findings, "rsa").key_bits,
        Some(1024),
        "macro constant folded"
    );
    assert!(
        algorithms(&findings).iter().any(|(id, p)| id == "aes"
            && p.key_bits == Some(256)
            && p.mode.as_deref() == Some("gcm"))
    );
    let curves: Vec<_> = algorithms(&findings)
        .into_iter()
        .filter(|(id, _)| id == "ecdsa")
        .filter_map(|(_, p)| p.curve)
        .collect();
    assert!(
        curves.contains(&"P-256".to_owned()),
        "curve refined onto the bound pkey ctx: {curves:?}"
    );
    assert!(curves.contains(&"P-384".to_owned()));
    assert!(
        algorithms(&findings).iter().any(|(id, _)| id == "3des"),
        "cipher string suites decoded"
    );
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, _)| id == "x25519-mlkem768"),
        "hybrid group decoded"
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "md5"));
    assert!(
        findings
            .observations
            .iter()
            .any(|o| o.evidence.kind == EvidenceKind::Import)
    );
    let main = findings
        .functions
        .iter()
        .find(|f| f.name == "main")
        .unwrap();
    assert_eq!(main.entry.as_ref().unwrap().kind, EntryKind::Main);
}

#[test]
fn cpp_openssl3_fetch_and_qualified_methods() {
    let findings = scan(
        "svc.cpp",
        "void Svc::run() { auto c = EVP_CIPHER_fetch(nullptr, \"AES-128-CBC\", nullptr); auto m = EVP_MD_fetch(nullptr, \"SHA256\", nullptr); }\n",
    );
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "aes" && p.key_bits == Some(128))
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "sha-256"));
    assert!(
        findings
            .functions
            .iter()
            .any(|f| f.id.ends_with("::Svc.run"))
    );
}

// ---- Go --------------------------------------------------------------------------------------

#[test]
fn go_crypto_bindings_tls_config_and_route_binding() {
    let findings = scan(
        "cmd/server/main.go",
        r#"package main
const Bits = 2048
func main() { http.HandleFunc("/pay", pay) }
func pay(w http.ResponseWriter, r *http.Request) {
    k, _ := rsa.GenerateKey(rand.Reader, Bits)
    b, _ := aes.NewCipher(key)
    g, _ := cipher.NewGCM(b)
    h := hmac.New(sha256.New, key)
    d := sha1.Sum(data)
    p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    dk, _ := mlkem.GenerateKey768()
    cfg := &tls.Config{MinVersion: tls.VersionTLS10, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}}
}
"#,
    );
    assert_eq!(params_of(&findings, "rsa").key_bits, Some(2048));
    assert_eq!(
        params_of(&findings, "aes").mode.as_deref(),
        Some("gcm"),
        "NewGCM refines the bound block cipher"
    );
    assert_eq!(
        params_of(&findings, "hmac").digest.as_deref(),
        Some("sha-256")
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "sha-1"));
    assert_eq!(
        params_of(&findings, "ecdsa").curve.as_deref(),
        Some("P-256")
    );
    assert_eq!(
        params_of(&findings, "ml-kem").parameter_set.as_deref(),
        Some("768")
    );
    assert!(findings.observations.iter().any(
        |o| matches!(&o.finding, Finding::Protocol(p) if p.version.as_deref() == Some("1.0"))
    ));
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, _)| id == "x25519-mlkem768")
    );

    let binding = findings
        .bindings
        .iter()
        .find(|b| b.handler == "pay")
        .expect("route binding");
    assert_eq!(binding.entry.kind, EntryKind::HttpRoute);
    assert!(findings.calls.iter().any(|c| c.callee == "HandleFunc"));
}

// ---- JavaScript / TypeScript -----------------------------------------------------------------

#[test]
fn javascript_node_crypto_jwt_and_inline_route_handler() {
    let findings = scan(
        "server.js",
        r#"
const ALG = 'md5';
app.post('/pay', (req, res) => {
  crypto.createHash(ALG);
  crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  crypto.createCipheriv('aes-128-cbc', key, iv);
  jwt.sign(payload, secret, { algorithm: 'RS256' });
  tls.createServer({ minVersion: 'TLSv1', ciphers: 'ECDHE-RSA-AES256-GCM-SHA384' });
});
"#,
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "md5"));
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "rsa" && p.key_bits == Some(1024))
    );
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "rsa" && p.digest.as_deref() == Some("sha-256"))
    );
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "aes" && p.mode.as_deref() == Some("cbc"))
    );
    assert!(findings.observations.iter().any(
        |o| matches!(&o.finding, Finding::Protocol(p) if p.version.as_deref() == Some("1.0"))
    ));

    let handler = findings
        .functions
        .iter()
        .find(|f| f.entry.is_some())
        .expect("inline handler is an entry");
    assert_eq!(handler.entry.as_ref().unwrap().kind, EntryKind::HttpRoute);
    assert!(
        find(&findings, "md5")
            .usage
            .as_ref()
            .unwrap()
            .function
            .as_deref()
            == Some(handler.id.as_str())
    );
}

#[test]
fn typescript_webcrypto_object_arguments() {
    let findings = scan(
        "seal.ts",
        "export async function seal(data: string): Promise<void> { await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' }, true, ['encrypt']); await crypto.subtle.digest('SHA-1', data); }\n",
    );
    let rsa = params_of(&findings, "rsa");
    assert_eq!(rsa.key_bits, Some(2048));
    assert_eq!(rsa.padding.as_deref(), Some("oaep"));
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "sha-1"));
}

// ---- Rust ------------------------------------------------------------------------------------

#[test]
fn rust_rustcrypto_openssl_and_axum_routes() {
    let findings = scan(
        "src/main.rs",
        r#"
const BITS: usize = 2048;
async fn pay() {
    let k = RsaPrivateKey::new(&mut rng, BITS);
    let c = Aes256Gcm::new(&key);
    let d = Sha1::digest(b"x");
    let s = openssl::symm::Cipher::aes_128_cbc();
    let kem = MlKem768::generate(&mut rng);
}
fn main() { let app = Router::new().route("/pay", post(pay)); }
"#,
    );
    assert_eq!(params_of(&findings, "rsa").key_bits, Some(2048));
    assert!(
        algorithms(&findings).iter().any(|(id, p)| id == "aes"
            && p.key_bits == Some(256)
            && p.mode.as_deref() == Some("gcm"))
    );
    assert!(
        algorithms(&findings).iter().any(|(id, p)| id == "aes"
            && p.key_bits == Some(128)
            && p.mode.as_deref() == Some("cbc"))
    );
    assert!(algorithms(&findings).iter().any(|(id, _)| id == "sha-1"));
    assert_eq!(
        params_of(&findings, "ml-kem").parameter_set.as_deref(),
        Some("768")
    );
    assert!(
        findings.bindings.iter().any(|b| b.handler == "pay"),
        "axum route binds through post(pay)"
    );
    assert!(
        findings
            .functions
            .iter()
            .any(|f| f.name == "main" && f.entry.is_some())
    );
}

// ---- C# --------------------------------------------------------------------------------------

#[test]
fn csharp_create_constructors_and_mode_assignment() {
    let findings = scan(
        "Pay.cs",
        r#"class C {
            const int Bits = 1024;
            [HttpPost("pay")]
            public void Pay(string cardNumber) {
                var r = RSA.Create(Bits);
                var a = Aes.Create();
                a.Mode = CipherMode.ECB;
                var h = new HMACSHA1(k);
                var d = new Rfc2898DeriveBytes(p, s, 1000);
                var e = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            }
        }"#,
    );
    assert_eq!(params_of(&findings, "rsa").key_bits, Some(1024));
    assert_eq!(
        params_of(&findings, "aes").mode.as_deref(),
        Some("ecb"),
        "property assignment refines Aes.Create()"
    );
    assert!(
        algorithms(&findings)
            .iter()
            .any(|(id, p)| id == "hmac" && p.digest.as_deref() == Some("sha-1"))
    );
    assert_eq!(
        params_of(&findings, "pbkdf2").digest.as_deref(),
        Some("sha-1"),
        "Rfc2898 defaults to SHA-1"
    );
    assert_eq!(
        params_of(&findings, "ecdsa").curve.as_deref(),
        Some("P-256")
    );
    let pay = findings.functions.iter().find(|f| f.name == "Pay").unwrap();
    assert_eq!(pay.entry.as_ref().unwrap().kind, EntryKind::HttpRoute);
}

// ---- robustness ------------------------------------------------------------------------------

#[test]
fn malformed_source_is_reported_as_heuristic_not_dropped() {
    let findings = scan("broken.py", "def f(:\n    hashlib.sha1(x\n");
    for observation in &findings.observations {
        assert!(matches!(
            observation.evidence.kind,
            EvidenceKind::Heuristic | EvidenceKind::ApiCall
        ));
    }
}

#[test]
fn identifiers_named_like_algorithms_are_not_algorithms() {
    let findings = scan(
        "v.py",
        "aes = load()\nsha1 = 3\nprint(aes, sha1)\nresult = process(md5_hex)\n",
    );
    assert!(
        algorithms(&findings).is_empty(),
        "{:#?}",
        algorithms(&findings)
    );
}

#[test]
fn deadline_expiry_aborts_cleanly() {
    let collector = SourceCollector::new().unwrap();
    let source = "x = 1\n".repeat(50_000);
    let artifact = Artifact {
        path: "big.py",
        component: ".",
        bytes: source.as_bytes(),
    };
    let expired = Deadline::after(Duration::from_millis(0));
    let mut findings = Findings::default();
    assert!(
        collector
            .collect(&artifact, &expired, &mut findings)
            .is_err()
    );
}

#[test]
fn dotted_normalises_every_path_syntax() {
    assert_eq!(
        dotted("javax.crypto.Cipher.getInstance"),
        "javax.crypto.Cipher.getInstance"
    );
    assert_eq!(
        dotted("openssl::symm::Cipher::aes_128_cbc"),
        "openssl.symm.Cipher.aes_128_cbc"
    );
    assert_eq!(dotted("Router::new().route"), "Router.new.route");
    assert_eq!(dotted("ctx->method"), "ctx.method");
    assert_eq!(dotted("SigningKey::<Sha256>::new"), "SigningKey.new");
    assert_eq!(dotted("obj?.prop"), "obj.prop");
}

#[test]
fn keyword_names_and_nested_callees_are_not_data_identifiers() {
    let python = scan(
        "pay.py",
        "def seal(card_number):\n    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n    return key.public_key().encrypt(card_number, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))\n",
    );
    for observation in &python.observations {
        let usage = observation.usage.as_ref().unwrap();
        for vocabulary in [
            "public_exponent",
            "key_size",
            "OAEP",
            "MGF1",
            "SHA256",
            "mgf",
            "label",
        ] {
            assert!(
                !usage.identifiers.iter().any(|i| i == vocabulary),
                "{vocabulary} in {:?}",
                usage.identifiers
            );
        }
    }
    assert!(
        find(&python, "rsa")
            .usage
            .as_ref()
            .unwrap()
            .identifiers
            .contains(&"key".to_owned()),
        "the bound variable is kept"
    );
    let seal = python.functions.iter().find(|f| f.name == "seal").unwrap();
    assert_eq!(
        seal.parameters,
        vec!["card_number".to_owned()],
        "data reaches classification through parameters"
    );

    let js = scan(
        "keys.js",
        "const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });\n",
    );
    let usage = find(&js, "rsa").usage.as_ref().unwrap();
    assert!(
        !usage
            .identifiers
            .iter()
            .any(|i| i == "modulusLength" || i == "publicExponent"),
        "{:?}",
        usage.identifiers
    );
    assert!(
        usage.identifiers.iter().any(|i| i == "pair"),
        "the bound variable is kept"
    );
}

#[test]
fn functions_using_module_level_keys_are_linked_to_them() {
    let findings = scan(
        "pay.py",
        "_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def tokenize(card_number):
    return _key.public_key().encrypt(card_number, None)


def rotate():
    _key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return _key.public_key()
",
    );
    let rsa: Vec<&Observation> = findings
        .observations
        .iter()
        .filter(|o| matches!(&o.finding, Finding::Algorithm(f) if f.algorithm.id == "rsa" && f.algorithm.params.key_bits == Some(2048)))
        .collect();
    assert_eq!(rsa.len(), 2, "the definition plus one linked use");
    let linked = rsa
        .iter()
        .find(|o| o.evidence.rule_id.ends_with("+use"))
        .unwrap();
    assert_eq!(linked.location.line, Some(5));
    assert!(
        linked
            .usage
            .as_ref()
            .unwrap()
            .function
            .as_deref()
            .unwrap()
            .ends_with("tokenize")
    );
    assert_eq!(linked.evidence.matched_token, "_key");
    // `rotate` binds its own `_key`: the local shadows the module binding, nothing is linked
    assert!(!rsa.iter().any(|o| {
        o.usage
            .as_ref()
            .unwrap()
            .function
            .as_deref()
            .is_some_and(|f| f.ends_with("rotate"))
    }));
}
