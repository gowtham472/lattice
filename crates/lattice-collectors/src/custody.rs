//! Keys held in hardware or a key service, found through the configuration that references them.
//!
//! A key in an HSM, a smart card, a TPM or a cloud KMS never appears as a file, but everything
//! that uses it names it: a PKCS#11 URI (RFC 7512) in a web server or OpenSSL configuration, an
//! OpenSSL engine or TPM handle, a Java PKCS#11 keystore, a Vault seal, a TPM2-sealed LUKS volume
//! in `crypttab`. Each reference becomes a key asset with its custody, so the inventory shows
//! which keys are migrated by changing hardware or a key service rather than a file.
//!
//! Nothing is opened, loaded or asked of a device: this is text. PINs never leave: the query part
//! of a PKCS#11 URI (where `pin-value` lives) is dropped before anything is recorded.

use lattice_core::{Custody, CustodyKind, MaterialType};

/// One reference to a key held elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub custody: Custody,
    pub material_type: MaterialType,
    pub rule: &'static str,
    /// What was matched, safe to record.
    pub token: String,
    pub line: u64,
    /// Stable identity of the referenced key, independent of the file that names it.
    pub key: String,
}

const MAX_FIELD: usize = 64;

fn clip(value: &str) -> String {
    value.chars().take(MAX_FIELD).collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = value.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_comment(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with('#') || line.starts_with(';') || line.starts_with("//")
}

/// The path part of every `pkcs11:` URI on a line, without its query.
fn pkcs11_uris(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("pkcs11:") {
        let after = &rest[start + "pkcs11:".len()..];
        let end = after
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '%' | ';' | '=' | '.' | '_' | '~' | '-'))
            })
            .unwrap_or(after.len());
        found.push(&after[..end]);
        // resume right after the prefix: in `engine:pkcs11:pkcs11:token=…` the first match is
        // the engine's name and the URI starts inside it
        rest = after;
    }
    found
}

fn pkcs11(path: &str, line: u64) -> Option<Reference> {
    let mut attributes = std::collections::BTreeMap::new();
    for pair in path.split(';') {
        if let Some((name, value)) = pair.split_once('=') {
            attributes.insert(name.to_ascii_lowercase(), percent_decode(value));
        }
    }
    // `engine:pkcs11:` and bare `pkcs11:` name a mechanism, not a key
    if attributes.is_empty() {
        return None;
    }
    let material_type = match attributes.get("type").map(String::as_str) {
        Some("private") => MaterialType::PrivateKey,
        Some("public") => MaterialType::PublicKey,
        Some("secret-key") => MaterialType::SecretKey,
        // certificates and data objects are not keys
        Some(_) => return None,
        None => MaterialType::Key,
    };
    let mut parts = Vec::new();
    if let Some(token) = attributes.get("token") {
        parts.push(format!("token \"{}\"", clip(token)));
    }
    if let Some(object) = attributes.get("object") {
        parts.push(format!("object \"{}\"", clip(object)));
    } else if let Some(id) = attributes.get("id") {
        parts.push(format!("id {}", clip(id)));
    }
    let software = attributes
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "token" | "model" | "manufacturer"))
        .any(|(_, value)| value.to_ascii_lowercase().contains("softhsm"));
    let detail = format!(
        "PKCS#11 {}{}",
        if parts.is_empty() {
            "token".to_owned()
        } else {
            parts.join(", ")
        },
        if software {
            " (SoftHSM: a software token)"
        } else {
            ""
        }
    );
    Some(Reference {
        custody: Custody {
            kind: CustodyKind::Pkcs11Token,
            detail,
            usage: None,
        },
        material_type,
        rule: "config.custody.pkcs11-uri",
        token: clip(&format!("pkcs11:{path}")),
        line,
        key: format!("pkcs11:{path}"),
    })
}

/// `engine:tpm2tss:/etc/keys/tls.tss` style references (OpenSSL engines).
fn engine_references(line: &str, number: u64, out: &mut Vec<Reference>) {
    let mut rest = line;
    while let Some(start) = rest.find("engine:") {
        let after = &rest[start + "engine:".len()..];
        let Some((engine, tail)) = after.split_once(':') else {
            break;
        };
        let payload: String = tail
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ';'))
            .collect();
        if matches!(engine, "tpm2tss" | "tpm2" | "tpm") && !payload.is_empty() {
            out.push(Reference {
                custody: Custody {
                    kind: CustodyKind::Tpm,
                    detail: format!("OpenSSL {engine} engine key {}", clip(&payload)),
                    usage: None,
                },
                material_type: MaterialType::PrivateKey,
                rule: "config.custody.openssl-engine",
                token: clip(&format!("engine:{engine}:{payload}")),
                line: number,
                key: format!("tpm:{payload}"),
            });
        }
        rest = tail;
    }
}

/// TPM2 persistent handles (`handle:0x81000001`), as the OpenSSL tpm2 provider names keys.
fn tpm_handles(line: &str, number: u64, out: &mut Vec<Reference>) {
    let mut rest = line;
    while let Some(start) = rest.find("handle:0x") {
        let after = &rest[start + "handle:0x".len()..];
        let digits: String = after.chars().take_while(char::is_ascii_hexdigit).collect();
        if digits.len() == 8 && digits.starts_with("81") {
            out.push(Reference {
                custody: Custody {
                    kind: CustodyKind::Tpm,
                    detail: format!("TPM2 persistent key handle 0x{digits}"),
                    usage: None,
                },
                material_type: MaterialType::PrivateKey,
                rule: "config.custody.tpm-handle",
                token: format!("handle:0x{digits}"),
                line: number,
                key: format!("tpm-handle:0x{}", digits.to_ascii_lowercase()),
            });
        }
        rest = after;
    }
}

/// `javax.net.ssl.keyStoreType=PKCS11`, `server.ssl.key-store-type: PKCS11`, `keystore.type=PKCS11`.
fn java_keystore(line: &str, number: u64, out: &mut Vec<Reference>) {
    let Some((key, value)) = line
        .split_once('=')
        .or_else(|| line.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches(['"', '\'', ','])))
    else {
        return;
    };
    let lower = key.to_ascii_lowercase().replace(['-', '_', '.'], "");
    if lower.contains("keystoretype")
        && !lower.contains("trust")
        && value.eq_ignore_ascii_case("pkcs11")
    {
        let key = key.trim_matches(['"', '\'']);
        out.push(Reference {
            custody: Custody {
                kind: CustodyKind::Pkcs11Token,
                detail: format!("Java PKCS#11 keystore ({})", clip(key)),
                usage: None,
            },
            material_type: MaterialType::PrivateKey,
            rule: "config.custody.java-pkcs11-keystore",
            token: clip(&format!("{key}={value}")),
            line: number,
            key: "java-pkcs11-keystore".into(),
        });
    }
}

/// `crypttab` entries unlocked by a TPM2 or a PKCS#11 token.
fn crypttab(line: &str, number: u64, out: &mut Vec<Reference>) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (Some(name), Some(options)) = (fields.first(), fields.get(3)) else {
        return;
    };
    for option in options.split(',') {
        let (kind, detail, rule) = if option.starts_with("tpm2-device=") {
            (
                CustodyKind::Tpm,
                format!("LUKS volume key for {} sealed to the TPM2", clip(name)),
                "config.custody.crypttab-tpm2",
            )
        } else if option.starts_with("pkcs11-uri=") {
            (
                CustodyKind::Pkcs11Token,
                format!(
                    "LUKS volume key for {} unlocked by a PKCS#11 token",
                    clip(name)
                ),
                "config.custody.crypttab-pkcs11",
            )
        } else {
            continue;
        };
        out.push(Reference {
            custody: Custody {
                kind,
                detail,
                usage: None,
            },
            material_type: MaterialType::SecretKey,
            rule,
            token: clip(&format!(
                "{name} {}",
                option.split('=').next().unwrap_or(option)
            )),
            line: number,
            key: format!("luks:{name}"),
        });
    }
}

/// Vault `seal "..." {` stanzas: the key that protects Vault's own keys.
fn vault_seal(lines: &[&str], index: usize, out: &mut Vec<Reference>) {
    let line = lines[index].trim();
    let Some(rest) = line.strip_prefix("seal") else {
        return;
    };
    let Some(kind) = rest
        .trim()
        .strip_prefix('"')
        .and_then(|r| r.split('"').next())
    else {
        return;
    };
    let label = lines
        .iter()
        .skip(index + 1)
        .take(30)
        .take_while(|l| l.trim() != "}")
        .find_map(|l| {
            let (key, value) = l.split_once('=')?;
            matches!(
                key.trim(),
                "key_label" | "kms_key_id" | "key_name" | "crypto_key"
            )
            .then(|| clip(value.trim().trim_matches('"')))
        });
    let (custody, provider) = match kind {
        "pkcs11" => (CustodyKind::Pkcs11Token, "a PKCS#11 HSM"),
        "awskms" => (CustodyKind::CloudKms, "AWS KMS"),
        "gcpckms" => (CustodyKind::CloudKms, "Google Cloud KMS"),
        "azurekeyvault" => (CustodyKind::CloudKms, "Azure Key Vault"),
        "ocikms" => (CustodyKind::CloudKms, "OCI KMS"),
        "alicloudkms" => (CustodyKind::CloudKms, "Alibaba Cloud KMS"),
        _ => return,
    };
    out.push(Reference {
        custody: Custody {
            kind: custody,
            detail: match &label {
                Some(label) => format!("Vault seal key \"{label}\" in {provider}"),
                None => format!("Vault seal key in {provider}"),
            },
            usage: None,
        },
        material_type: MaterialType::SecretKey,
        rule: "config.custody.vault-seal",
        token: format!("seal \"{kind}\""),
        line: index as u64 + 1,
        key: format!("vault-seal:{kind}:{}", label.unwrap_or_default()),
    });
}

/// Every reference to a key held elsewhere in one configuration file.
pub fn find(path: &str, text: &str) -> Vec<Reference> {
    let file = path.rsplit('/').next().unwrap_or(path);
    let is_crypttab = file == "crypttab";
    let lines: Vec<&str> = text.lines().take(200_000).collect();
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        let number = index as u64 + 1;
        for uri in pkcs11_uris(line) {
            out.extend(pkcs11(uri, number));
        }
        engine_references(line, number, &mut out);
        tpm_handles(line, number, &mut out);
        java_keystore(line, number, &mut out);
        if is_crypttab {
            crypttab(line, number, &mut out);
        }
        vault_seal(&lines, index, &mut out);
    }
    out.sort_by(|a, b| (a.line, &a.key).cmp(&(b.line, &b.key)));
    out.dedup_by(|a, b| a.key == b.key && a.line == b.line);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(references: &[Reference]) -> Vec<(CustodyKind, &str)> {
        references
            .iter()
            .map(|r| (r.custody.kind, r.custody.detail.as_str()))
            .collect()
    }

    #[test]
    fn pkcs11_uris_never_keep_the_pin() {
        let found = find(
            "nginx.conf",
            "ssl_certificate_key \"engine:pkcs11:pkcs11:token=prod-ca;object=tls;type=private?pin-value=123456\";\n",
        );
        assert_eq!(found.len(), 1, "{found:?}");
        let reference = &found[0];
        assert_eq!(reference.custody.kind, CustodyKind::Pkcs11Token);
        assert_eq!(
            reference.custody.detail,
            "PKCS#11 token \"prod-ca\", object \"tls\""
        );
        assert_eq!(reference.material_type, MaterialType::PrivateKey);
        for text in [&reference.token, &reference.key, &reference.custody.detail] {
            assert!(!text.contains("123456") && !text.contains("pin"), "{text}");
        }
    }

    #[test]
    fn certificates_in_tokens_are_not_keys_and_softhsm_is_named() {
        assert!(
            find(
                "a.conf",
                "SSLCertificateFile pkcs11:token=x;object=c;type=cert\n"
            )
            .is_empty()
        );
        let found = find(
            "a.conf",
            "key = pkcs11:model=SoftHSM%20v2;token=dev;object=k\n",
        );
        assert!(found[0].custody.detail.contains("SoftHSM"), "{found:?}");
    }

    #[test]
    fn tpm_engines_handles_and_crypttab() {
        let found = find(
            "nginx.conf",
            "ssl_certificate_key engine:tpm2tss:/etc/nginx/tls.tss;\nssl_certificate_key handle:0x81000001;\n",
        );
        assert_eq!(
            kinds(&found),
            [
                (
                    CustodyKind::Tpm,
                    "OpenSSL tpm2tss engine key /etc/nginx/tls.tss"
                ),
                (CustodyKind::Tpm, "TPM2 persistent key handle 0x81000001"),
            ]
        );
        let crypttab = find(
            "etc/crypttab",
            "# comment tpm2-device=auto\nroot UUID=abc none tpm2-device=auto,discard\nhome UUID=def - pkcs11-uri=auto\nswap /dev/sdb none luks\n",
        );
        assert_eq!(crypttab.len(), 2, "{crypttab:?}");
        assert_eq!(crypttab[0].material_type, MaterialType::SecretKey);
        assert!(crypttab[0].custody.detail.contains("root"));
        assert_eq!(crypttab[1].custody.kind, CustodyKind::Pkcs11Token);
        assert!(find("fstab", "root UUID=abc none tpm2-device=auto\n").is_empty());
    }

    #[test]
    fn java_keystores_and_vault_seals() {
        let found = find(
            "application.yml",
            "server:\n  ssl:\n    key-store-type: PKCS11\n    trust-store-type: PKCS11\n",
        );
        assert_eq!(found.len(), 1, "trust stores hold certificates: {found:?}");
        assert_eq!(found[0].custody.kind, CustodyKind::Pkcs11Token);
        let found = find("app.properties", "javax.net.ssl.keyStoreType=PKCS12\n");
        assert!(found.is_empty());

        let vault = find(
            "vault.hcl",
            "seal \"pkcs11\" {\n  lib = \"/usr/lib/libCryptoki2.so\"\n  key_label = \"vault-root\"\n  pin = \"secret\"\n}\nseal \"awskms\" {\n  kms_key_id = \"alias/vault\"\n}\nseal \"transit\" {\n}\n",
        );
        assert_eq!(
            kinds(&vault),
            [
                (
                    CustodyKind::Pkcs11Token,
                    "Vault seal key \"vault-root\" in a PKCS#11 HSM"
                ),
                (
                    CustodyKind::CloudKms,
                    "Vault seal key \"alias/vault\" in AWS KMS"
                ),
            ]
        );
        assert!(vault.iter().all(|r| !r.custody.detail.contains("secret")));
    }

    #[test]
    fn comments_are_ignored() {
        assert!(
            find(
                "nginx.conf",
                "# ssl_certificate_key pkcs11:token=x;object=y;\n"
            )
            .is_empty()
        );
    }
}
