//! Who may do what.
//!
//! Every API caller is a named principal with one role:
//!
//! | Role       | May                                                                 |
//! |------------|---------------------------------------------------------------------|
//! | `viewer`   | read scans, reports, CBOMs, graphs, PDFs and comparisons            |
//! | `operator` | also browse the configured roots and start scans                    |
//! | `admin`    | also read the audit log                                             |
//!
//! Principals come from a users file: each entry names a user, a role, and how the user proves
//! who they are: the BLAKE3 digest of a bearer token, the SHA-256 fingerprint of a client
//! certificate (with mutual TLS), or both. The file holds no secrets. `lattice user add` issues a
//! token or pins a certificate. The single `--token` of earlier releases is still accepted and
//! acts as an admin named `token`. A loopback server with none of these is a single-user tool:
//! every local caller is the admin `local`.
//!
//! When a connection presents a client certificate that pins a user, that is the principal; a
//! bearer token naming a different user on the same request is refused as ambiguous.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            other => Err(format!(
                "unknown role {other:?}; expected viewer, operator or admin"
            )),
        }
    }
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    pub name: String,
    pub role: Role,
}

/// One entry of the users file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// Hex BLAKE3 of the user's bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_blake3: Option<String>,
    /// Hex SHA-256 of the user's client certificate (DER), for mutual TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersFile {
    #[serde(default)]
    user: Vec<User>,
}

/// Parses a users file (`[[user]]` tables).
pub fn parse_users(source: &str) -> Result<Vec<User>, String> {
    let file: UsersFile = toml::from_str(source).map_err(|e| e.to_string())?;
    Ok(file.user)
}

/// Token prefix, so a leaked token is recognisable in logs and secret scanners.
pub const TOKEN_PREFIX: &str = "lattice_";

/// A fresh random bearer token and the users-file entry that grants it `role`.
pub fn issue(name: &str, role: Role) -> Result<(String, User), String> {
    if !valid_name(name) {
        return Err("user names may use only letters, digits, '.', '_' and '-'".into());
    }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| format!("no randomness available: {e}"))?;
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(secret));
    let user = User {
        name: name.to_owned(),
        role,
        token_blake3: Some(blake3::hash(token.as_bytes()).to_hex().to_string()),
        certificate_sha256: None,
    };
    Ok((token, user))
}

/// A users-file entry that authenticates `name` by the client certificate with this DER.
pub fn pin_certificate(name: &str, role: Role, der: &[u8]) -> Result<User, String> {
    if !valid_name(name) {
        return Err("user names may use only letters, digits, '.', '_' and '-'".into());
    }
    Ok(User {
        name: name.to_owned(),
        role,
        token_blake3: None,
        certificate_sha256: Some(crate::tls::fingerprint(der)),
    })
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// How callers are identified.
#[derive(Debug)]
pub enum Access {
    /// Loopback, no credentials configured: everyone is the local admin.
    Open,
    Credentials {
        /// Bearer tokens, by BLAKE3 digest.
        tokens: HashMap<[u8; 32], Principal>,
        /// Client certificates, by SHA-256 fingerprint.
        certificates: HashMap<[u8; 32], Principal>,
    },
}

fn digest(field: &str, user: &str, hex_digest: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_digest)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("user {user:?}: {field} must be 64 hex characters"))
}

impl Access {
    /// Builds the table from the users file and the legacy single token.
    pub fn new(users: Vec<User>, legacy_token: Option<&str>) -> Result<Self, String> {
        let mut table = HashMap::new();
        let mut certificates = HashMap::new();
        let mut names = std::collections::BTreeSet::new();
        for user in users {
            if !valid_name(&user.name) {
                return Err(format!("user {:?}: invalid name", user.name));
            }
            if !names.insert(user.name.clone()) {
                return Err(format!("user {:?} is defined twice", user.name));
            }
            if user.token_blake3.is_none() && user.certificate_sha256.is_none() {
                return Err(format!(
                    "user {:?} has neither token_blake3 nor certificate_sha256",
                    user.name
                ));
            }
            let principal = Principal {
                name: user.name.clone(),
                role: user.role,
            };
            if let Some(token) = &user.token_blake3 {
                let key = digest("token_blake3", &user.name, token)?;
                if table.insert(key, principal.clone()).is_some() {
                    return Err("two users share one token".into());
                }
            }
            if let Some(certificate) = &user.certificate_sha256 {
                let key = digest("certificate_sha256", &user.name, certificate)?;
                if certificates.insert(key, principal).is_some() {
                    return Err("two users share one certificate".into());
                }
            }
        }
        if let Some(token) = legacy_token.map(str::trim).filter(|t| !t.is_empty()) {
            let principal = Principal {
                name: "token".into(),
                role: Role::Admin,
            };
            if table
                .insert(*blake3::hash(token.as_bytes()).as_bytes(), principal)
                .is_some()
            {
                return Err("--token is also a user's token".into());
            }
        }
        Ok(if table.is_empty() && certificates.is_empty() {
            Self::Open
        } else {
            Self::Credentials {
                tokens: table,
                certificates,
            }
        })
    }

    pub fn requires_credentials(&self) -> bool {
        matches!(self, Self::Credentials { .. })
    }

    /// Whether any user is identified by a client certificate.
    pub fn pins_certificates(&self) -> bool {
        matches!(self, Self::Credentials { certificates, .. } if !certificates.is_empty())
    }

    /// The principal a request identifies, by its client certificate (with mutual TLS) or its
    /// `Authorization` header. Tokens are looked up by BLAKE3 digest, so lookup time does not
    /// depend on how much of a token is right.
    pub fn authenticate(
        &self,
        authorization: Option<&str>,
        certificate: Option<&crate::tls::ClientCertificate>,
    ) -> Option<Principal> {
        let Self::Credentials {
            tokens,
            certificates,
        } = self
        else {
            return Some(Principal {
                name: "local".into(),
                role: Role::Admin,
            });
        };
        let by_certificate = certificate
            .and_then(|c| hex::decode(&c.0).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|key| certificates.get(&key));
        let by_token = authorization
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            .and_then(|token| tokens.get(blake3::hash(token.as_bytes()).as_bytes()));
        match (by_certificate, by_token) {
            (Some(a), Some(b)) if a != b => None,
            (Some(principal), _) | (None, Some(principal)) => Some(principal.clone()),
            (None, None) => None,
        }
    }
}

/// The role an API request needs; `None` for public endpoints.
pub fn required_role(method: &axum::http::Method, path: &str) -> Option<Role> {
    use axum::http::Method;
    if path == "/api/health" {
        return None;
    }
    if path == "/api/audit" {
        return Some(Role::Admin);
    }
    if !matches!(*method, Method::GET | Method::HEAD) || path.ends_with("/entries") {
        return Some(Role::Operator);
    }
    Some(Role::Viewer)
}
