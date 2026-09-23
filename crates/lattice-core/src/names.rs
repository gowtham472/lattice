//! Turns the many spellings of an algorithm found in code and configuration into catalogue
//! references.
//!
//! Supported grammars:
//! * generic names and aliases with trailing parameters: `aes-256-gcm`, `AES256GCM`,
//!   `ML-KEM-768`, `HmacSHA256`, `des-ede3-cbc`, `EVP_aes_128_cbc` (after prefix stripping)
//! * JCA cipher transformations: `AES/GCM/NoPadding`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`
//! * JCA signature and KDF names: `SHA256withRSA`, `SHA256withRSA/PSS`, `PBKDF2WithHmacSHA256`
//! * JOSE (RFC 7518) identifiers: `RS256`, `ES384`, `A256GCM`, `RSA-OAEP-256`
//! * SSH algorithm names: `ssh-rsa`, `rsa-sha2-256`, `diffie-hellman-group14-sha256`
//! * TLS cipher suites, IANA and OpenSSL naming: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
//!   `ECDHE-RSA-AES128-GCM-SHA256`, `TLS_AES_256_GCM_SHA384`
//!
//! Parsing is deliberately strict: a name is only resolved when every token is explained.
//! `AESUtil` or `rsa_key_path` resolve to nothing rather than to a guessed algorithm, because a
//! false positive in a CBOM costs an analyst's time and erodes trust in every other finding.

use crate::knowledge::{
    AlgorithmRef, AlgorithmSpec, Params, Primitive, Registry, SecurityModel, normalize_token,
};
use serde::{Deserialize, Serialize};

const MAX_NAME_LENGTH: usize = 160;

/// Resolves one algorithm name in any supported single-algorithm grammar.
pub fn resolve(text: &str) -> Option<AlgorithmRef> {
    let text = clean(text)?;
    jose(text)
        .or_else(|| jca_signature(text))
        .or_else(|| jca_kdf(text))
        .or_else(|| jca_transformation(text))
        .or_else(|| ssh(text))
        .or_else(|| generic(text))
}

/// Resolves a curve or TLS/SSH group name to a key-agreement algorithm, e.g. `secp384r1` →
/// ECDH over P-384, `x25519` → X25519, `X25519MLKEM768` → the hybrid KEM, `ffdhe3072` → DH-3072.
pub fn resolve_group(text: &str) -> Option<AlgorithmRef> {
    let text = clean(text)?;
    let registry = Registry::embedded();
    let normalized = normalize_token(text);
    if let Some(bits) = normalized
        .strip_prefix("ffdhe")
        .and_then(|rest| rest.parse::<u32>().ok())
    {
        return Some(AlgorithmRef::with_params(
            "dh",
            Params {
                key_bits: Some(bits),
                parameter_set: Some(format!("ffdhe{bits}")),
                ..Params::default()
            },
        ));
    }
    if let Some(curve) = registry.curve(text) {
        let id = match curve.name.as_str() {
            "curve25519" => return Some(AlgorithmRef::new("x25519")),
            "curve448" => return Some(AlgorithmRef::new("x448")),
            _ => "ecdh",
        };
        return Some(AlgorithmRef::with_params(
            id,
            Params {
                curve: Some(curve.name.clone()),
                ..Params::default()
            },
        ));
    }
    resolve(text).filter(|reference| {
        registry.get(&reference.id).is_some_and(|spec| {
            matches!(
                spec.primitive,
                Primitive::KeyAgree | Primitive::Kem | Primitive::Combiner
            )
        })
    })
}

/// Resolves a curve name to its canonical name (`prime256v1` → `P-256`).
pub fn resolve_curve(text: &str) -> Option<String> {
    let text = clean(text)?;
    Registry::embedded()
        .curve(text)
        .map(|curve| curve.name.clone())
}

fn clean(text: &str) -> Option<&str> {
    let text = text.trim().trim_matches(|c| matches!(c, '"' | '\'' | '`'));
    (!text.is_empty() && text.len() <= MAX_NAME_LENGTH && text.is_ascii()).then_some(text)
}

// ---------------------------------------------------------------------------------------------
// Generic grammar: <alias><parameters...>
// ---------------------------------------------------------------------------------------------

fn generic(text: &str) -> Option<AlgorithmRef> {
    let registry = Registry::embedded();
    let normalized = normalize_token(strip_vendor_suffix(text));
    if normalized.is_empty() {
        return None;
    }
    // Longest readings first (`sha256` before `sha`, `desede3` before `des`), but fall back to a
    // shorter one when the longer leaves an unexplained remainder.
    registry
        .prefix_candidates(&normalized)
        .find_map(|(spec, set, consumed)| {
            let mut params = Params::default();
            if let Some(set) = set {
                params.parameter_set = Some(set.name.clone());
            }
            parse_parameters(registry, spec, &normalized[consumed..], &mut params)?;
            Some(AlgorithmRef::with_params(spec.id.clone(), params))
        })
}

/// Consumes the text after an algorithm alias as parameters. Returns `None` when any token
/// cannot be explained, which rejects the whole name.
fn parse_parameters(
    registry: &Registry,
    spec: &AlgorithmSpec,
    mut rest: &str,
    params: &mut Params,
) -> Option<()> {
    let mut guard = 0;
    while !rest.is_empty() {
        guard += 1;
        if guard > 12 {
            return None;
        }
        // numbers: parameter set, key size, or (for digest-parameterised families) nothing
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            let number = &rest[..digits];
            if let Some(set) = spec.parameter_set(number) {
                params.parameter_set = Some(set.name.clone());
            } else if let Ok(bits) = number.parse::<u32>()
                && plausible_key_bits(spec, bits)
            {
                params.key_bits = Some(bits);
            } else {
                return None;
            }
            rest = &rest[digits..];
            continue;
        }
        if let Some(mode) = longest_match(rest, modes_of(spec)) {
            params.mode = Some(mode.to_owned());
            rest = &rest[normalize_token(mode).len()..];
            continue;
        }
        if let Some((padding, length)) = padding_prefix(rest) {
            params.padding = Some(padding.to_owned());
            rest = &rest[length..];
            continue;
        }
        if accepts_digest(spec)
            && let Some((digest, length)) = digest_prefix(registry, rest)
        {
            params.digest = Some(digest);
            rest = &rest[length..];
            continue;
        }
        if spec.security == SecurityModel::Curve
            && let Some((curve, length)) = curve_prefix(registry, rest)
        {
            params.curve = Some(curve);
            rest = &rest[length..];
            continue;
        }
        // connective noise in names such as `PBKDF2WithHmacSHA256` or `SHA256andMGF1`
        if let Some(stripped) = ["with", "and"]
            .iter()
            .find_map(|word| rest.strip_prefix(word))
        {
            rest = stripped;
            continue;
        }
        return None;
    }
    Some(())
}

/// Standard block-cipher modes of operation, used for ciphers whose catalogue entry does not
/// list its own (every block cipher can be run in these).
const BLOCK_MODES: &[&str] = &[
    "ecb", "cbc", "ctr", "gcm", "ccm", "ofb", "cfb", "cfb8", "cfb1", "xts",
];

fn modes_of(spec: &AlgorithmSpec) -> Box<dyn Iterator<Item = &str> + '_> {
    if spec.modes.is_empty() && spec.primitive == Primitive::BlockCipher {
        Box::new(BLOCK_MODES.iter().copied())
    } else {
        Box::new(spec.modes.iter().map(String::as_str))
    }
}

fn plausible_key_bits(spec: &AlgorithmSpec, bits: u32) -> bool {
    match spec.security {
        SecurityModel::IntegerFactoring => (512..=16384).contains(&bits),
        SecurityModel::KeyBits => spec.key_bits.is_empty() || spec.key_bits.contains(&bits),
        _ => !spec.key_bits.is_empty() && spec.key_bits.contains(&bits),
    }
}

fn accepts_digest(spec: &AlgorithmSpec) -> bool {
    spec.security == SecurityModel::Digest
        || matches!(
            spec.primitive,
            Primitive::Signature | Primitive::Pke | Primitive::KeyAgree
        )
}

fn digest_prefix(registry: &Registry, rest: &str) -> Option<(String, usize)> {
    registry
        .digest_prefix(rest)
        .map(|(spec, length)| (spec.id.clone(), length))
}

fn curve_prefix(registry: &Registry, rest: &str) -> Option<(String, usize)> {
    // Curves are looked up whole: they are always the last token of a name.
    registry
        .curve(rest)
        .map(|curve| (curve.name.clone(), rest.len()))
}

fn padding_prefix(rest: &str) -> Option<(&'static str, usize)> {
    const PADDINGS: &[(&str, &str)] = &[
        ("nopadding", "none"),
        ("pkcs5padding", "pkcs5"),
        ("pkcs7padding", "pkcs7"),
        ("pkcs1padding", "pkcs1v15"),
        ("pkcs1v15", "pkcs1v15"),
        ("pkcs1", "pkcs1v15"),
        ("iso10126padding", "iso10126"),
        ("oaep", "oaep"),
        ("pss", "pss"),
    ];
    PADDINGS
        .iter()
        .find(|(prefix, _)| rest.starts_with(prefix))
        .map(|(prefix, canonical)| (*canonical, prefix.len()))
}

fn longest_match<'a>(rest: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    candidates
        .filter(|candidate| rest.starts_with(&normalize_token(candidate)))
        .max_by_key(|candidate| candidate.len())
}

fn strip_vendor_suffix(text: &str) -> &str {
    text.split('@').next().unwrap_or(text)
}

// ---------------------------------------------------------------------------------------------
// JCA
// ---------------------------------------------------------------------------------------------

/// `AES/GCM/NoPadding`, `DESede/CBC/PKCS5Padding`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`,
/// and bare `AES`, which SunJCE silently expands to `AES/ECB/PKCS5Padding`.
fn jca_transformation(text: &str) -> Option<AlgorithmRef> {
    let parts: Vec<&str> = text.split('/').collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let registry = Registry::embedded();
    let mode = normalize_token(parts[1]);
    let known_mode = mode == "none"
        || registry
            .algorithms()
            .iter()
            .any(|spec| spec.modes.iter().any(|m| normalize_token(m) == mode));
    if !known_mode {
        return None;
    }
    let mut algorithm = generic(parts[0])?;
    let spec = registry.get(&algorithm.id)?;
    if matches!(spec.primitive, Primitive::BlockCipher) && mode != "none" {
        algorithm.params.mode = Some(mode);
    }
    if let Some(padding) = parts.get(2) {
        let padding_token = normalize_token(padding);
        if let Some(digest) = padding_token
            .strip_prefix("oaepwith")
            .and_then(|rest| rest.strip_suffix("andmgf1padding"))
        {
            algorithm.params.padding = Some("oaep".into());
            algorithm.params.digest = digest_prefix(registry, digest)
                .filter(|(_, length)| *length == digest.len())
                .map(|(id, _)| id);
        } else if let Some((canonical, length)) = padding_prefix(&padding_token)
            && length == padding_token.len()
        {
            algorithm.params.padding = Some(canonical.to_owned());
        }
    }
    Some(algorithm)
}

/// Resolves a JCA `Cipher.getInstance` argument. A bare block-cipher name defaults to ECB in
/// SunJCE, which is a real vulnerability hidden behind an innocent-looking string, so it is
/// made explicit here rather than left unspecified.
pub fn resolve_jca_cipher(text: &str) -> Option<AlgorithmRef> {
    let text = clean(text)?;
    if text.contains('/') {
        return jca_transformation(text);
    }
    let mut algorithm = generic(text)?;
    let spec = Registry::embedded().get(&algorithm.id)?;
    if spec.primitive == Primitive::BlockCipher && algorithm.params.mode.is_none() {
        algorithm.params.mode = Some("ecb".into());
        algorithm.params.padding = Some("pkcs5".into());
    }
    Some(algorithm)
}

/// `SHA256withRSA`, `SHA384withECDSA`, `SHA256withRSA/PSS`, `SHA3-256withRSA`, `NONEwithRSA`.
fn jca_signature(text: &str) -> Option<AlgorithmRef> {
    let lower = text.to_ascii_lowercase();
    let (digest_part, rest) = lower.split_once("with")?;
    if digest_part.is_empty() || digest_part.starts_with("pbkdf") || digest_part == "oaep" {
        return None;
    }
    let (algorithm_part, variant) = match rest.split_once('/') {
        Some((algorithm, variant)) => (algorithm, Some(variant)),
        None => (rest, None),
    };
    let registry = Registry::embedded();
    let mut algorithm = generic(algorithm_part)?;
    let spec = registry.get(&algorithm.id)?;
    if !matches!(spec.primitive, Primitive::Signature | Primitive::Pke) {
        return None;
    }
    if digest_part != "none" {
        let digest = normalize_token(digest_part);
        let (id, length) = digest_prefix(registry, &digest)?;
        if length != digest.len() {
            return None;
        }
        algorithm.params.digest = Some(id);
    }
    if variant.is_some_and(|variant| variant.contains("pss")) {
        algorithm.params.padding = Some("pss".into());
    }
    Some(algorithm)
}

/// `PBKDF2WithHmacSHA256`, `PBEWithHmacSHA256AndAES_256`.
fn jca_kdf(text: &str) -> Option<AlgorithmRef> {
    let normalized = normalize_token(text);
    let rest = normalized.strip_prefix("pbkdf2withhmac")?;
    let registry = Registry::embedded();
    let (digest, length) = digest_prefix(registry, rest)?;
    (length == rest.len()).then(|| {
        AlgorithmRef::with_params(
            "pbkdf2",
            Params {
                digest: Some(digest),
                ..Params::default()
            },
        )
    })
}

// ---------------------------------------------------------------------------------------------
// JOSE (RFC 7518)
// ---------------------------------------------------------------------------------------------

fn jose(text: &str) -> Option<AlgorithmRef> {
    let with = |id: &str, params: Params| Some(AlgorithmRef::with_params(id, params));
    let digest = |d: &str| Some(d.to_owned());
    match text {
        "RS256" | "RS384" | "RS512" => with(
            "rsa",
            Params {
                digest: digest(sha_for(text)),
                padding: Some("pkcs1v15".into()),
                ..Params::default()
            },
        ),
        "PS256" | "PS384" | "PS512" => with(
            "rsa",
            Params {
                digest: digest(sha_for(text)),
                padding: Some("pss".into()),
                ..Params::default()
            },
        ),
        "ES256" => with(
            "ecdsa",
            Params {
                curve: Some("P-256".into()),
                digest: digest("sha-256"),
                ..Params::default()
            },
        ),
        "ES384" => with(
            "ecdsa",
            Params {
                curve: Some("P-384".into()),
                digest: digest("sha-384"),
                ..Params::default()
            },
        ),
        "ES512" => with(
            "ecdsa",
            Params {
                curve: Some("P-521".into()),
                digest: digest("sha-512"),
                ..Params::default()
            },
        ),
        "ES256K" => with(
            "ecdsa",
            Params {
                curve: Some("secp256k1".into()),
                digest: digest("sha-256"),
                ..Params::default()
            },
        ),
        "EdDSA" | "Ed25519" => with("ed25519", Params::default()),
        "Ed448" => with("ed448", Params::default()),
        "HS256" | "HS384" | "HS512" => with(
            "hmac",
            Params {
                digest: digest(sha_for(text)),
                ..Params::default()
            },
        ),
        "RSA1_5" => with(
            "rsa",
            Params {
                padding: Some("pkcs1v15".into()),
                ..Params::default()
            },
        ),
        "RSA-OAEP" => with(
            "rsa",
            Params {
                padding: Some("oaep".into()),
                digest: digest("sha-1"),
                ..Params::default()
            },
        ),
        "RSA-OAEP-256" => with(
            "rsa",
            Params {
                padding: Some("oaep".into()),
                digest: digest("sha-256"),
                ..Params::default()
            },
        ),
        "A128KW" | "A192KW" | "A256KW" => with(
            "aes",
            Params {
                key_bits: jose_bits(text),
                mode: Some("kw".into()),
                ..Params::default()
            },
        ),
        "A128GCMKW" | "A192GCMKW" | "A256GCMKW" | "A128GCM" | "A192GCM" | "A256GCM" => with(
            "aes",
            Params {
                key_bits: jose_bits(text),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => with(
            "aes",
            Params {
                key_bits: jose_bits(text),
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            with("ecdh", Params::default())
        }
        _ => None,
    }
}

fn sha_for(jose: &str) -> &'static str {
    if jose.ends_with("384") {
        "sha-384"
    } else if jose.ends_with("512") {
        "sha-512"
    } else {
        "sha-256"
    }
}

fn jose_bits(jose: &str) -> Option<u32> {
    jose.get(1..4).and_then(|bits| bits.parse().ok())
}

// ---------------------------------------------------------------------------------------------
// SSH (RFC 4253, 8332, 8731, 9142 and OpenSSH extensions)
// ---------------------------------------------------------------------------------------------

fn ssh(text: &str) -> Option<AlgorithmRef> {
    let name = strip_vendor_suffix(text).to_ascii_lowercase();
    let name = name.strip_suffix("-etm").unwrap_or(&name);
    let digest = |d: &str| Params {
        digest: Some(d.to_owned()),
        ..Params::default()
    };
    match name {
        "ssh-rsa" => return Some(AlgorithmRef::with_params("rsa", digest("sha-1"))),
        "rsa-sha2-256" => return Some(AlgorithmRef::with_params("rsa", digest("sha-256"))),
        "rsa-sha2-512" => return Some(AlgorithmRef::with_params("rsa", digest("sha-512"))),
        "ssh-dss" => {
            return Some(AlgorithmRef::with_params(
                "dsa",
                Params {
                    key_bits: Some(1024),
                    digest: Some("sha-1".into()),
                    ..Params::default()
                },
            ));
        }
        "diffie-hellman-group-exchange-sha1" => {
            return Some(AlgorithmRef::with_params("dh", digest("sha-1")));
        }
        "diffie-hellman-group-exchange-sha256" => {
            return Some(AlgorithmRef::with_params("dh", digest("sha-256")));
        }
        _ => {}
    }
    if let Some(rest) = name.strip_prefix("diffie-hellman-group") {
        let (group, hash) = rest.split_once('-')?;
        // RFC 3526 / RFC 8268 MODP group numbers to modulus sizes
        let bits = match group {
            "1" => 1024,
            "14" => 2048,
            "15" => 3072,
            "16" => 4096,
            "17" => 6144,
            "18" => 8192,
            _ => return None,
        };
        let hash = if hash == "sha1" {
            "sha-1"
        } else {
            ssh_sha2(hash)?
        };
        return Some(AlgorithmRef::with_params(
            "dh",
            Params {
                key_bits: Some(bits),
                digest: Some(hash.to_owned()),
                ..Params::default()
            },
        ));
    }
    if let Some(curve) = name.strip_prefix("ecdh-sha2-") {
        return Some(AlgorithmRef::with_params(
            "ecdh",
            Params {
                curve: resolve_curve(curve),
                ..Params::default()
            },
        ));
    }
    if let Some(curve) = name.strip_prefix("ecdsa-sha2-") {
        return Some(AlgorithmRef::with_params(
            "ecdsa",
            Params {
                curve: resolve_curve(curve),
                ..Params::default()
            },
        ));
    }
    if let Some(hash) = name.strip_prefix("hmac-") {
        let hash = if hash == "sha1" || hash == "sha1-96" {
            "sha-1"
        } else if hash == "md5" || hash == "md5-96" {
            "md5"
        } else {
            ssh_sha2(hash)?
        };
        return Some(AlgorithmRef::with_params("hmac", digest(hash)));
    }
    None
}

fn ssh_sha2(token: &str) -> Option<&'static str> {
    match token {
        "sha2-256" | "sha256" => Some("sha-256"),
        "sha2-384" | "sha384" => Some("sha-384"),
        "sha2-512" | "sha512" => Some("sha-512"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Cloud KMS key specifications and managed TLS policies
// ---------------------------------------------------------------------------------------------

/// Cloud key-management key specifications: AWS KMS (`RSA_2048`, `ECC_NIST_P256`,
/// `SYMMETRIC_DEFAULT`, `HMAC_256`, `ML_DSA_65`), GCP Cloud KMS (`RSA_SIGN_PSS_2048_SHA256`,
/// `EC_SIGN_P256_SHA256`, `GOOGLE_SYMMETRIC_ENCRYPTION`, `PQ_SIGN_ML_DSA_65`), ACM
/// (`EC_prime256v1`), Azure (`RSA-HSM`).
pub fn parse_key_spec(text: &str) -> Option<AlgorithmRef> {
    let text = clean(text)?;
    let upper = text.to_ascii_uppercase().replace('-', "_");
    let tokens: Vec<&str> = upper.split('_').filter(|t| !t.is_empty()).collect();
    let number = |prefix_skip: &[&str]| -> Option<u32> {
        tokens
            .iter()
            .filter(|t| !prefix_skip.contains(t))
            .find_map(|t| t.parse::<u32>().ok())
    };
    let digest = tokens.iter().find_map(|t| match *t {
        "SHA1" => Some("sha-1"),
        "SHA256" => Some("sha-256"),
        "SHA384" => Some("sha-384"),
        "SHA512" => Some("sha-512"),
        _ => None,
    });
    let with = |id: &str, params: Params| Some(AlgorithmRef::with_params(id, params));
    if upper == "SYMMETRIC_DEFAULT"
        || upper == "GOOGLE_SYMMETRIC_ENCRYPTION"
        || upper == "AES_256_GCM"
    {
        return with(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        );
    }
    if let Some(position) = tokens.iter().position(|t| *t == "ML") {
        let kind = tokens.get(position + 1)?;
        let set = tokens.get(position + 2)?.to_string();
        return match *kind {
            "DSA" => with(
                "ml-dsa",
                Params {
                    parameter_set: Some(set),
                    ..Params::default()
                },
            ),
            "KEM" => with(
                "ml-kem",
                Params {
                    parameter_set: Some(set),
                    ..Params::default()
                },
            ),
            _ => None,
        };
    }
    if tokens.contains(&"SLH") {
        let set = tokens
            .iter()
            .skip_while(|t| **t != "DSA")
            .skip(1)
            .map(|t| t.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("-");
        return with(
            "slh-dsa",
            Params {
                parameter_set: (!set.is_empty()).then_some(set),
                ..Params::default()
            },
        );
    }
    if tokens.first() == Some(&"HMAC") {
        let digest = match number(&[]) {
            Some(224) => "sha-224",
            Some(384) => "sha-384",
            Some(512) => "sha-512",
            _ => "sha-256",
        };
        return with(
            "hmac",
            Params {
                digest: Some(digest.into()),
                ..Params::default()
            },
        );
    }
    if tokens.contains(&"RSA") {
        let padding = if tokens.contains(&"PSS") {
            Some("pss")
        } else if tokens.contains(&"OAEP") {
            Some("oaep")
        } else if tokens.contains(&"PKCS1") {
            Some("pkcs1v15")
        } else {
            None
        };
        return with(
            "rsa",
            Params {
                key_bits: number(&[]).filter(|bits| *bits >= 512),
                digest: digest.map(str::to_owned),
                padding: padding.map(str::to_owned),
                ..Params::default()
            },
        );
    }
    if tokens.contains(&"ED25519") {
        return Some(AlgorithmRef::new("ed25519"));
    }
    if tokens
        .first()
        .is_some_and(|t| matches!(*t, "EC" | "ECC" | "ECDSA"))
        || tokens.contains(&"SECP256K1")
    {
        let curve = tokens.iter().rev().find_map(|token| resolve_curve(token))?;
        return with(
            "ecdsa",
            Params {
                curve: Some(curve),
                digest: digest.map(str::to_owned),
                ..Params::default()
            },
        );
    }
    if upper == "SM2" {
        return Some(AlgorithmRef::new("sm2"));
    }
    None
}

/// A cloud provider's managed TLS policy: the minimum protocol version it permits and whether it
/// offers hybrid post-quantum key exchange. Covers AWS ELB/ALB/NLB (`ELBSecurityPolicy-...`),
/// CloudFront (`TLSv1.2_2021`) and API Gateway (`TLS_1_2`) naming.
pub fn parse_tls_policy(text: &str) -> Option<(String, bool)> {
    let text = clean(text)?;
    let upper = text.to_ascii_uppercase();
    let post_quantum = upper.contains("-PQ-") || upper.ends_with("-PQ");
    // Legacy default policies that still allow TLS 1.0
    if matches!(
        upper.as_str(),
        "ELBSECURITYPOLICY-2016-08" | "ELBSECURITYPOLICY-2015-05" | "ELBSECURITYPOLICY-FS-2018-06"
    ) {
        return Some(("1.0".into(), false));
    }
    // AWS `TLS13-1-x`: TLS 1.3 offered, minimum 1.x
    if let Some(index) = upper.find("TLS13-") {
        let minimum = &upper[index + 6..];
        for (prefix, version) in [
            ("1-0", "1.0"),
            ("1-1", "1.1"),
            ("1-2", "1.2"),
            ("1-3", "1.3"),
        ] {
            if minimum.starts_with(prefix) {
                return Some((version.into(), post_quantum));
            }
        }
    }
    // `TLS-1-2`, `TLSv1.2_2021`, `TLS_1_2`, `FS-1-2`, `TLSv1_2016` (= 1.0: the 2016 is a year)
    for marker in ["TLS", "FS"] {
        for (index, _) in upper.match_indices(marker) {
            let rest = upper[index + marker.len()..].trim_start_matches(['V', '-', '_', ' ']);
            let Some(after_major) = rest.strip_prefix('1') else {
                continue;
            };
            if after_major.starts_with('3')
                && !after_major[1..].starts_with(|c: char| c.is_ascii_digit())
            {
                return Some(("1.3".into(), post_quantum));
            }
            let minor = after_major.trim_start_matches(['.', '-', '_']);
            let mut digits = minor.chars();
            let version = match (digits.next(), digits.next()) {
                (Some(digit @ '0'..='3'), next) if !next.is_some_and(|c| c.is_ascii_digit()) => {
                    format!("1.{digit}")
                }
                _ => "1.0".to_owned(),
            };
            return Some((version, post_quantum));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Protocol versions
// ---------------------------------------------------------------------------------------------

/// Parses the many spellings of an SSL/TLS/DTLS version found in code and configuration:
/// `TLSv1.2`, `TLS1_2_VERSION`, `tls.VersionTLS10`, `SslProtocols.Tls11`, `PROTOCOL_TLSv1`,
/// `SSLv3`, `DTLSv1.2`. Returns the protocol and a canonical version (`1.0`, `1.2`, `3.0`).
pub fn parse_protocol_version(text: &str) -> Option<(crate::model::ProtocolKind, String)> {
    use crate::model::ProtocolKind;
    let text = clean(text)?;
    // Compact to alphanumerics and read from the last protocol mention, so qualifiers
    // (`tls.`, `SslProtocols.`, `ssl.PROTOCOL_`) drop away while `1.2` survives as `12`.
    let compact: String = text
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(|c| c.to_lowercase())
        .collect();
    let strip_tail = |rest: &str| -> String {
        rest.trim_end_matches("version")
            .trim_end_matches("method")
            .trim_end_matches("client")
            .trim_end_matches("server")
            .trim_start_matches('v')
            .to_owned()
    };
    let (protocol, digits) = if let Some(index) = compact.rfind("tls") {
        let protocol = if index > 0 && compact.as_bytes()[index - 1] == b'd' {
            ProtocolKind::Dtls
        } else {
            ProtocolKind::Tls
        };
        (protocol, strip_tail(&compact[index + 3..]))
    } else {
        let index = compact.rfind("ssl")?;
        let version = match strip_tail(&compact[index + 3..]).as_str() {
            "2" | "20" => "2.0",
            "3" | "30" => "3.0",
            _ => return None,
        };
        return Some((ProtocolKind::Tls, format!("ssl{version}")));
    };
    let digits = digits.as_str();
    let version = match digits {
        "1" | "10" => "1.0",
        "11" => "1.1",
        "12" => "1.2",
        "13" => "1.3",
        _ => return None,
    };
    Some((protocol, version.to_owned()))
}

// ---------------------------------------------------------------------------------------------
// TLS cipher suites
// ---------------------------------------------------------------------------------------------

/// The algorithms a TLS cipher suite commits to. TLS 1.3 suites name only the AEAD and hash;
/// key exchange and authentication are negotiated separately (groups and signature schemes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuite {
    /// IANA name, e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    pub name: String,
    pub tls13: bool,
    pub key_exchange: Option<AlgorithmRef>,
    pub authentication: Option<AlgorithmRef>,
    pub cipher: Option<AlgorithmRef>,
    pub mac: Option<AlgorithmRef>,
    /// Structural weaknesses independent of the component algorithms.
    pub weaknesses: Vec<String>,
}

impl CipherSuite {
    pub fn algorithms(&self) -> impl Iterator<Item = &AlgorithmRef> {
        [
            &self.key_exchange,
            &self.authentication,
            &self.cipher,
            &self.mac,
        ]
        .into_iter()
        .flatten()
    }
}

/// Parses an IANA (`TLS_...`) or OpenSSL (`ECDHE-RSA-AES128-GCM-SHA256`) cipher suite name.
pub fn parse_cipher_suite(text: &str) -> Option<CipherSuite> {
    let text = clean(text)?;
    let upper = text.to_ascii_uppercase();
    if let Some(rest) = upper
        .strip_prefix("TLS_")
        .or_else(|| upper.strip_prefix("SSL_"))
    {
        return iana_suite(rest, &upper);
    }
    openssl_suite(&upper)
}

fn iana_suite(rest: &str, full: &str) -> Option<CipherSuite> {
    let mut suite = CipherSuite {
        name: full.to_owned(),
        ..CipherSuite::default()
    };
    let Some((exchange, protection)) = rest.split_once("_WITH_") else {
        // TLS 1.3: TLS_<AEAD>_<HASH>
        let (cipher, hash) = rest.rsplit_once('_')?;
        suite.tls13 = true;
        suite.cipher = Some(suite_cipher(cipher)?);
        suite.mac = Some(AlgorithmRef::new(suite_hash(hash)?)); // TLS 1.3: always the HKDF hash
        return Some(suite);
    };
    let (key_exchange, authentication) = suite_exchange(exchange, &mut suite.weaknesses)?;
    suite.key_exchange = key_exchange;
    suite.authentication = authentication;
    let (cipher, mac) = protection.rsplit_once('_')?;
    suite.cipher = suite_cipher(cipher);
    if cipher == "NULL" {
        suite
            .weaknesses
            .push("NULL cipher: traffic is authenticated but not encrypted".into());
    }
    suite.mac = suite_mac(mac, suite.cipher.as_ref());
    if suite.cipher.is_none() && cipher != "NULL" {
        return None;
    }
    Some(suite)
}

type Exchange = (Option<AlgorithmRef>, Option<AlgorithmRef>);

fn suite_exchange(exchange: &str, weaknesses: &mut Vec<String>) -> Option<Exchange> {
    let stripped = exchange.replace("_EXPORT1024", "").replace("_EXPORT", "");
    if stripped.len() != exchange.len() {
        weaknesses
            .push("EXPORT-grade suite: deliberately weakened key sizes (FREAK, Logjam)".into());
    }
    let tokens: Vec<&str> = stripped.split('_').collect();
    let key_exchange = |id: &str| Some(AlgorithmRef::new(id));
    let auth = |token: &str| -> Option<Option<AlgorithmRef>> {
        match token {
            "RSA" => Some(Some(AlgorithmRef::new("rsa"))),
            "ECDSA" => Some(Some(AlgorithmRef::new("ecdsa"))),
            "DSS" => Some(Some(AlgorithmRef::new("dsa"))),
            "PSK" => Some(None),
            "ANON" => Some(None),
            _ => None,
        }
    };
    let result = match tokens.as_slice() {
        ["RSA"] => (key_exchange("rsa"), key_exchange("rsa")),
        ["PSK"] => (None, None),
        // pre-shared-key variants authenticate with the PSK, not a certificate
        ["DHE", "PSK"] => (key_exchange("dh"), None),
        ["ECDHE", "PSK"] => (key_exchange("ecdh"), None),
        ["RSA", "PSK"] => (key_exchange("rsa"), None),
        ["DHE" | "DH" | "EDH", rest] => (key_exchange("dh"), auth(rest)?),
        ["ECDHE" | "ECDH", rest] => (key_exchange("ecdh"), auth(rest)?),
        _ => return None,
    };
    if tokens.contains(&"ANON") {
        weaknesses
            .push("anonymous key exchange: no server authentication, trivially intercepted".into());
    }
    Some(result)
}

fn suite_cipher(token: &str) -> Option<AlgorithmRef> {
    let params = |bits: u32, mode: &str| Params {
        key_bits: Some(bits),
        mode: Some(mode.to_owned()),
        ..Params::default()
    };
    Some(match token {
        "AES_128_GCM" => AlgorithmRef::with_params("aes", params(128, "gcm")),
        "AES_256_GCM" => AlgorithmRef::with_params("aes", params(256, "gcm")),
        "AES_128_CCM" | "AES_128_CCM_8" => AlgorithmRef::with_params("aes", params(128, "ccm")),
        "AES_256_CCM" | "AES_256_CCM_8" => AlgorithmRef::with_params("aes", params(256, "ccm")),
        "AES_128_CBC" => AlgorithmRef::with_params("aes", params(128, "cbc")),
        "AES_256_CBC" => AlgorithmRef::with_params("aes", params(256, "cbc")),
        "CHACHA20_POLY1305" => AlgorithmRef::new("chacha20-poly1305"),
        "3DES_EDE_CBC" => AlgorithmRef::with_params(
            "3des",
            Params {
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "DES_CBC" | "DES40_CBC" => AlgorithmRef::with_params(
            "des",
            Params {
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "RC4_128" | "RC4_40" => AlgorithmRef::new("rc4"),
        "RC2_CBC_40" => AlgorithmRef::new("rc2"),
        "IDEA_CBC" => AlgorithmRef::new("idea"),
        "SEED_CBC" => AlgorithmRef::new("seed"),
        "CAMELLIA_128_CBC" => AlgorithmRef::with_params("camellia", params(128, "cbc")),
        "CAMELLIA_256_CBC" => AlgorithmRef::with_params("camellia", params(256, "cbc")),
        "CAMELLIA_128_GCM" => AlgorithmRef::with_params("camellia", params(128, "gcm")),
        "CAMELLIA_256_GCM" => AlgorithmRef::with_params("camellia", params(256, "gcm")),
        "ARIA_128_GCM" => AlgorithmRef::with_params("aria", params(128, "gcm")),
        "ARIA_256_GCM" => AlgorithmRef::with_params("aria", params(256, "gcm")),
        "ARIA_128_CBC" => AlgorithmRef::with_params("aria", params(128, "cbc")),
        "ARIA_256_CBC" => AlgorithmRef::with_params("aria", params(256, "cbc")),
        "SM4_GCM" => AlgorithmRef::with_params(
            "sm4",
            Params {
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "SM4_CCM" => AlgorithmRef::with_params(
            "sm4",
            Params {
                mode: Some("ccm".into()),
                ..Params::default()
            },
        ),
        _ => return None,
    })
}

/// The algorithm a suite's trailing hash names. In CBC and stream suites it is the record MAC,
/// so HMAC with that digest (`..._CBC_SHA` is HMAC-SHA1, not a bare SHA-1); in AEAD suites the
/// cipher authenticates and the hash only drives the PRF / HKDF.
fn suite_mac(token: &str, cipher: Option<&AlgorithmRef>) -> Option<AlgorithmRef> {
    let hash = suite_hash(token)?;
    let aead = cipher.is_some_and(|c| {
        c.id == "chacha20-poly1305"
            || matches!(c.params.mode.as_deref(), Some("gcm" | "ccm" | "ccm8"))
    });
    Some(if aead {
        AlgorithmRef::new(hash)
    } else {
        AlgorithmRef::with_params(
            "hmac",
            Params {
                digest: Some(hash.into()),
                ..Params::default()
            },
        )
    })
}

fn suite_hash(token: &str) -> Option<&'static str> {
    match token {
        "SHA" => Some("sha-1"),
        "SHA256" => Some("sha-256"),
        "SHA384" => Some("sha-384"),
        "SHA512" => Some("sha-512"),
        "MD5" => Some("md5"),
        "SM3" => Some("sm3"),
        _ => None,
    }
}

/// OpenSSL suite names are hyphenated tokens: `[KX-][AUTH-]CIPHER[-MODE][-MAC]`. An absent key
/// exchange means static RSA key transport with RSA authentication (`AES128-SHA`).
fn openssl_suite(upper: &str) -> Option<CipherSuite> {
    let tokens: Vec<&str> = upper.split('-').collect();
    if tokens.len() < 2 {
        return None;
    }
    let mut suite = CipherSuite::default();
    let mut index = 0;
    let (key_exchange, authentication) = match tokens[0] {
        "ECDHE" | "EECDH" => {
            index += 1;
            let auth = openssl_auth(tokens.get(1).copied(), &mut index, &mut suite.weaknesses);
            (Some(AlgorithmRef::new("ecdh")), auth)
        }
        "DHE" | "EDH" => {
            index += 1;
            let auth = openssl_auth(tokens.get(1).copied(), &mut index, &mut suite.weaknesses);
            (Some(AlgorithmRef::new("dh")), auth)
        }
        "ADH" => {
            index += 1;
            suite.weaknesses.push(
                "anonymous key exchange: no server authentication, trivially intercepted".into(),
            );
            (Some(AlgorithmRef::new("dh")), None)
        }
        "AECDH" => {
            index += 1;
            suite.weaknesses.push(
                "anonymous key exchange: no server authentication, trivially intercepted".into(),
            );
            (Some(AlgorithmRef::new("ecdh")), None)
        }
        "PSK" => {
            index += 1;
            (None, None)
        }
        _ => (
            Some(AlgorithmRef::new("rsa")),
            Some(AlgorithmRef::new("rsa")),
        ),
    };
    suite.key_exchange = key_exchange;
    suite.authentication = authentication;

    let remaining = &tokens[index..];
    let (mac_token, cipher_tokens) = match remaining.last() {
        Some(last) if suite_hash(last).is_some() => {
            (Some(*last), &remaining[..remaining.len() - 1])
        }
        _ => (None, remaining),
    };
    let cipher_name = cipher_tokens.join("-");
    suite.cipher = Some(match cipher_name.as_str() {
        "AES128" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(128),
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "AES256" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "AES128-GCM" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(128),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "AES256-GCM" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "AES128-CCM" | "AES128-CCM8" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(128),
                mode: Some("ccm".into()),
                ..Params::default()
            },
        ),
        "AES256-CCM" | "AES256-CCM8" => AlgorithmRef::with_params(
            "aes",
            Params {
                key_bits: Some(256),
                mode: Some("ccm".into()),
                ..Params::default()
            },
        ),
        "CHACHA20-POLY1305" => AlgorithmRef::new("chacha20-poly1305"),
        "DES-CBC3" => AlgorithmRef::with_params(
            "3des",
            Params {
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "DES-CBC" => AlgorithmRef::with_params(
            "des",
            Params {
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "RC4" => AlgorithmRef::new("rc4"),
        "IDEA-CBC" => AlgorithmRef::new("idea"),
        "SEED" => AlgorithmRef::new("seed"),
        "CAMELLIA128" => AlgorithmRef::with_params(
            "camellia",
            Params {
                key_bits: Some(128),
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "CAMELLIA256" => AlgorithmRef::with_params(
            "camellia",
            Params {
                key_bits: Some(256),
                mode: Some("cbc".into()),
                ..Params::default()
            },
        ),
        "ARIA128-GCM" => AlgorithmRef::with_params(
            "aria",
            Params {
                key_bits: Some(128),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "ARIA256-GCM" => AlgorithmRef::with_params(
            "aria",
            Params {
                key_bits: Some(256),
                mode: Some("gcm".into()),
                ..Params::default()
            },
        ),
        "NULL" => {
            suite
                .weaknesses
                .push("NULL cipher: traffic is authenticated but not encrypted".into());
            suite.cipher = None;
            suite.mac = mac_token.and_then(|token| suite_mac(token, None));
            suite.name = upper.to_owned();
            return Some(suite);
        }
        _ => return None,
    });
    suite.mac = match mac_token {
        Some(token) => suite_mac(token, suite.cipher.as_ref()),
        // AEAD suites without an explicit hash use SHA-256 for the PRF
        None => Some(AlgorithmRef::new("sha-256")),
    };
    suite.name = upper.to_owned();
    Some(suite)
}

fn openssl_auth(
    token: Option<&str>,
    index: &mut usize,
    weaknesses: &mut Vec<String>,
) -> Option<AlgorithmRef> {
    match token {
        Some("RSA") => {
            *index += 1;
            Some(AlgorithmRef::new("rsa"))
        }
        Some("ECDSA") => {
            *index += 1;
            Some(AlgorithmRef::new("ecdsa"))
        }
        Some("DSS") => {
            *index += 1;
            Some(AlgorithmRef::new("dsa"))
        }
        Some("PSK") => {
            *index += 1;
            None
        }
        Some("ANULL") => {
            *index += 1;
            weaknesses.push(
                "anonymous key exchange: no server authentication, trivially intercepted".into(),
            );
            None
        }
        // `DHE-AES128-SHA`-style names omit authentication; OpenSSL implies RSA
        _ => Some(AlgorithmRef::new("rsa")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(text: &str) -> AlgorithmRef {
        resolve(text).unwrap_or_else(|| panic!("`{text}` should resolve"))
    }

    fn p(key_bits: Option<u32>, mode: Option<&str>) -> Params {
        Params {
            key_bits,
            mode: mode.map(str::to_owned),
            ..Params::default()
        }
    }

    #[test]
    fn generic_names_with_parameters() {
        assert_eq!(
            r("aes-256-gcm"),
            AlgorithmRef::with_params("aes", p(Some(256), Some("gcm")))
        );
        assert_eq!(
            r("AES256GCM"),
            AlgorithmRef::with_params("aes", p(Some(256), Some("gcm")))
        );
        assert_eq!(
            r("aes_128_cbc"),
            AlgorithmRef::with_params("aes", p(Some(128), Some("cbc")))
        );
        assert_eq!(r("des-ede3-cbc").id, "3des");
        assert_eq!(r("sha256").id, "sha-256");
        assert_eq!(r("SHA3-256").id, "sha3-256");
        assert_eq!(r("sha-512/256").id, "sha-512-256");
        assert_eq!(r("chacha20-poly1305").id, "chacha20-poly1305");
        assert_eq!(r("RSA").id, "rsa");
        assert_eq!(r("rsa-2048").params.key_bits, Some(2048));
    }

    #[test]
    fn pqc_parameter_sets_are_not_key_sizes() {
        let kem = r("ML-KEM-768");
        assert_eq!(kem.id, "ml-kem");
        assert_eq!(kem.params.parameter_set.as_deref(), Some("768"));
        assert_eq!(
            kem.params.key_bits, None,
            "768 is a parameter set, not a key size"
        );
        assert_eq!(r("Kyber1024").params.parameter_set.as_deref(), Some("1024"));
        assert_eq!(r("dilithium3").params.parameter_set.as_deref(), Some("65"));
        assert_eq!(r("ML-DSA-87").params.parameter_set.as_deref(), Some("87"));
        assert_eq!(r("X25519MLKEM768").id, "x25519-mlkem768");
    }

    #[test]
    fn digest_parameterised_names() {
        let hmac = r("HmacSHA256");
        assert_eq!(hmac.id, "hmac");
        assert_eq!(hmac.params.digest.as_deref(), Some("sha-256"));
        let hmac = r("hmac-sha512");
        assert_eq!(hmac.params.digest.as_deref(), Some("sha-512"));
        let kdf = r("PBKDF2WithHmacSHA1");
        assert_eq!(kdf.id, "pbkdf2");
        assert_eq!(kdf.params.digest.as_deref(), Some("sha-1"));
    }

    #[test]
    fn strictness_rejects_identifiers_that_merely_start_with_an_algorithm() {
        for text in [
            "AESUtil",
            "rsa_key_path",
            "description",
            "sha256sum",
            "md5hex",
            "desktop",
            "Session",
            "shared",
        ] {
            assert!(resolve(text).is_none(), "`{text}` must not resolve");
        }
    }

    #[test]
    fn jca_transformations() {
        let gcm = r("AES/GCM/NoPadding");
        assert_eq!(gcm.params.mode.as_deref(), Some("gcm"));
        assert_eq!(gcm.params.padding.as_deref(), Some("none"));
        let oaep = r("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        assert_eq!(oaep.id, "rsa");
        assert_eq!(
            oaep.params.mode, None,
            "ECB is meaningless for RSA and is dropped"
        );
        assert_eq!(oaep.params.padding.as_deref(), Some("oaep"));
        assert_eq!(oaep.params.digest.as_deref(), Some("sha-256"));
        assert_eq!(r("DESede/CBC/PKCS5Padding").id, "3des");
    }

    #[test]
    fn bare_jca_block_cipher_defaults_to_ecb() {
        let aes = resolve_jca_cipher("AES").unwrap();
        assert_eq!(aes.params.mode.as_deref(), Some("ecb"));
        let rsa = resolve_jca_cipher("RSA").unwrap();
        assert_eq!(rsa.params.mode, None);
    }

    #[test]
    fn jca_signatures() {
        let rsa = r("SHA256withRSA");
        assert_eq!(rsa.id, "rsa");
        assert_eq!(rsa.params.digest.as_deref(), Some("sha-256"));
        let pss = r("SHA384withRSA/PSS");
        assert_eq!(pss.params.padding.as_deref(), Some("pss"));
        let ecdsa = r("SHA512withECDSA");
        assert_eq!(ecdsa.id, "ecdsa");
        assert_eq!(ecdsa.params.digest.as_deref(), Some("sha-512"));
        assert_eq!(r("SHA1withRSA").params.digest.as_deref(), Some("sha-1"));
    }

    #[test]
    fn jose_identifiers() {
        assert_eq!(r("RS256").params.digest.as_deref(), Some("sha-256"));
        assert_eq!(r("ES384").params.curve.as_deref(), Some("P-384"));
        assert_eq!(
            r("A256GCM"),
            AlgorithmRef::with_params("aes", p(Some(256), Some("gcm")))
        );
        assert_eq!(r("EdDSA").id, "ed25519");
        assert_eq!(r("HS512").params.digest.as_deref(), Some("sha-512"));
    }

    #[test]
    fn ssh_names() {
        let legacy = r("ssh-rsa");
        assert_eq!(
            legacy.params.digest.as_deref(),
            Some("sha-1"),
            "ssh-rsa signs with SHA-1"
        );
        assert_eq!(r("rsa-sha2-512").params.digest.as_deref(), Some("sha-512"));
        let group14 = r("diffie-hellman-group14-sha256");
        assert_eq!(group14.params.key_bits, Some(2048));
        let group1 = r("diffie-hellman-group1-sha1");
        assert_eq!(group1.params.key_bits, Some(1024));
        assert_eq!(
            r("ecdh-sha2-nistp384").params.curve.as_deref(),
            Some("P-384")
        );
        assert_eq!(
            r("aes256-gcm@openssh.com"),
            AlgorithmRef::with_params("aes", p(Some(256), Some("gcm")))
        );
        assert_eq!(
            r("hmac-sha2-256-etm@openssh.com").params.digest.as_deref(),
            Some("sha-256")
        );
        assert_eq!(r("curve25519-sha256").id, "x25519");
        assert_eq!(r("mlkem768x25519-sha256").id, "x25519-mlkem768");
    }

    #[test]
    fn groups_and_curves() {
        assert_eq!(
            resolve_group("secp384r1").unwrap().params.curve.as_deref(),
            Some("P-384")
        );
        assert_eq!(resolve_group("x25519").unwrap().id, "x25519");
        assert_eq!(
            resolve_group("X25519MLKEM768").unwrap().id,
            "x25519-mlkem768"
        );
        assert_eq!(
            resolve_group("ffdhe3072").unwrap().params.key_bits,
            Some(3072)
        );
        assert_eq!(resolve_curve("prime256v1").as_deref(), Some("P-256"));
    }

    #[test]
    fn iana_tls12_suite() {
        let suite = parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").unwrap();
        assert!(!suite.tls13);
        assert_eq!(suite.key_exchange.unwrap().id, "ecdh");
        assert_eq!(suite.authentication.unwrap().id, "rsa");
        assert_eq!(
            suite.cipher.unwrap(),
            AlgorithmRef::with_params("aes", p(Some(128), Some("gcm")))
        );
        assert_eq!(suite.mac.unwrap().id, "sha-256");
    }

    #[test]
    fn iana_tls13_suite() {
        let suite = parse_cipher_suite("TLS_AES_256_GCM_SHA384").unwrap();
        assert!(suite.tls13);
        assert!(suite.key_exchange.is_none());
        assert_eq!(suite.cipher.unwrap().params.key_bits, Some(256));
        assert_eq!(suite.mac.unwrap().id, "sha-384");
        assert_eq!(
            parse_cipher_suite("TLS_CHACHA20_POLY1305_SHA256")
                .unwrap()
                .cipher
                .unwrap()
                .id,
            "chacha20-poly1305"
        );
    }

    #[test]
    fn legacy_and_weak_suites() {
        let rsa = parse_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA").unwrap();
        assert_eq!(
            rsa.key_exchange.unwrap().id,
            "rsa",
            "static RSA key transport, no forward secrecy"
        );
        assert_eq!(rsa.cipher.unwrap().id, "3des");
        let mac = rsa.mac.unwrap();
        assert_eq!(
            (mac.id.as_str(), mac.params.digest.as_deref()),
            ("hmac", Some("sha-1")),
            "CBC suites MAC with HMAC"
        );
        let anon = parse_cipher_suite("TLS_DH_anon_WITH_AES_128_CBC_SHA").unwrap();
        assert!(anon.weaknesses.iter().any(|w| w.contains("anonymous")));
        let null = parse_cipher_suite("TLS_RSA_WITH_NULL_SHA256").unwrap();
        assert!(null.weaknesses.iter().any(|w| w.contains("NULL")));
    }

    #[test]
    fn cloud_key_specs() {
        let spec = |t: &str| parse_key_spec(t).unwrap_or_else(|| panic!("`{t}`"));
        assert_eq!(spec("RSA_2048").params.key_bits, Some(2048));
        assert_eq!(spec("ECC_NIST_P256").params.curve.as_deref(), Some("P-256"));
        assert_eq!(
            spec("ECC_SECG_P256K1").params.curve.as_deref(),
            Some("secp256k1")
        );
        assert_eq!(spec("SYMMETRIC_DEFAULT").params.key_bits, Some(256));
        assert_eq!(spec("HMAC_512").params.digest.as_deref(), Some("sha-512"));
        let gcp = spec("RSA_SIGN_PSS_3072_SHA256");
        assert_eq!(
            (
                gcp.params.key_bits,
                gcp.params.padding.as_deref(),
                gcp.params.digest.as_deref()
            ),
            (Some(3072), Some("pss"), Some("sha-256"))
        );
        assert_eq!(
            spec("EC_SIGN_P384_SHA384").params.curve.as_deref(),
            Some("P-384")
        );
        assert_eq!(spec("EC_SIGN_ED25519").id, "ed25519");
        assert_eq!(
            spec("ML_DSA_65").params.parameter_set.as_deref(),
            Some("65")
        );
        assert_eq!(
            spec("PQ_SIGN_ML_DSA_87").params.parameter_set.as_deref(),
            Some("87")
        );
        assert_eq!(spec("EC_prime256v1").params.curve.as_deref(), Some("P-256"));
        assert!(parse_key_spec("ENCRYPT_DECRYPT").is_none());
    }

    #[test]
    fn managed_tls_policies() {
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-TLS13-1-2-2021-06"),
            Some(("1.2".into(), false))
        );
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"),
            Some(("1.2".into(), true))
        );
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-TLS13-1-3-2021-06"),
            Some(("1.3".into(), false))
        );
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-2016-08"),
            Some(("1.0".into(), false))
        );
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-TLS-1-0-2015-04"),
            Some(("1.0".into(), false))
        );
        assert_eq!(
            parse_tls_policy("TLSv1.2_2021"),
            Some(("1.2".into(), false))
        );
        assert_eq!(parse_tls_policy("TLS_1_2"), Some(("1.2".into(), false)));
        assert_eq!(
            parse_tls_policy("TLSv1_2016"),
            Some(("1.0".into(), false)),
            "2016 is a year, not a minor version"
        );
        assert_eq!(
            parse_tls_policy("ELBSecurityPolicy-FS-1-2-Res-2020-10"),
            Some(("1.2".into(), false))
        );
    }

    #[test]
    fn protocol_versions_in_their_many_spellings() {
        use crate::model::ProtocolKind;
        let tls = |v: &str| Some((ProtocolKind::Tls, v.to_owned()));
        assert_eq!(parse_protocol_version("TLSv1.2"), tls("1.2"));
        assert_eq!(parse_protocol_version("TLS1_2_VERSION"), tls("1.2"));
        assert_eq!(parse_protocol_version("tls.VersionTLS10"), tls("1.0"));
        assert_eq!(parse_protocol_version("SslProtocols.Tls11"), tls("1.1"));
        assert_eq!(parse_protocol_version("ssl.PROTOCOL_TLSv1"), tls("1.0"));
        assert_eq!(parse_protocol_version("TLSv1_3"), tls("1.3"));
        assert_eq!(parse_protocol_version("SSLv3"), tls("ssl3.0"));
        assert_eq!(parse_protocol_version("TLSv1_2_method"), tls("1.2"));
        assert_eq!(
            parse_protocol_version("DTLSv1.2"),
            Some((ProtocolKind::Dtls, "1.2".into()))
        );
        assert_eq!(
            parse_protocol_version("TLS"),
            None,
            "unversioned is not a version"
        );
        assert_eq!(parse_protocol_version("keystore"), None);
    }

    #[test]
    fn openssl_suite_names() {
        let suite = parse_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
        assert_eq!(suite.key_exchange.unwrap().id, "ecdh");
        assert_eq!(suite.authentication.unwrap().id, "rsa");
        assert_eq!(suite.cipher.unwrap().params.mode.as_deref(), Some("gcm"));
        let implicit = parse_cipher_suite("AES128-SHA").unwrap();
        assert_eq!(implicit.key_exchange.unwrap().id, "rsa");
        assert_eq!(
            implicit.mac.unwrap().params.digest.as_deref(),
            Some("sha-1")
        );
        let chacha = parse_cipher_suite("ECDHE-ECDSA-CHACHA20-POLY1305").unwrap();
        assert_eq!(chacha.authentication.unwrap().id, "ecdsa");
        assert_eq!(chacha.cipher.unwrap().id, "chacha20-poly1305");
        assert_eq!(
            parse_cipher_suite("DES-CBC3-SHA")
                .unwrap()
                .cipher
                .unwrap()
                .id,
            "3des"
        );
        let rc4 = parse_cipher_suite("RC4-MD5").unwrap().mac.unwrap();
        assert_eq!(
            (rc4.id.as_str(), rc4.params.digest.as_deref()),
            ("hmac", Some("md5"))
        );
        assert!(
            parse_cipher_suite("HIGH").is_none(),
            "cipher-string keywords are not suites"
        );
    }
}
