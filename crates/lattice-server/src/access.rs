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
//! Principals come from a users file: each entry names a user, a role and the BLAKE3 digest of
//! that user's bearer token, so the file holds no secrets. `lattice token` generates a token and
//! its entry. The single `--token` of earlier releases is still accepted and acts as an admin
//! named `token`. A loopback server with neither is a single-user tool: every local caller is the
//! admin `local`.

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
    pub token_blake3: String,
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
        token_blake3: blake3::hash(token.as_bytes()).to_hex().to_string(),
    };
    Ok((token, user))
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
    /// Bearer tokens, by BLAKE3 digest.
    Tokens(HashMap<[u8; 32], Principal>),
}

impl Access {
    /// Builds the table from the users file and the legacy single token.
    pub fn new(users: Vec<User>, legacy_token: Option<&str>) -> Result<Self, String> {
        let mut table = HashMap::new();
        let mut names = std::collections::BTreeSet::new();
        for user in users {
            if !valid_name(&user.name) {
                return Err(format!("user {:?}: invalid name", user.name));
            }
            if !names.insert(user.name.clone()) {
                return Err(format!("user {:?} is defined twice", user.name));
            }
            let digest: [u8; 32] = hex::decode(&user.token_blake3)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    format!(
                        "user {:?}: token_blake3 must be 64 hex characters",
                        user.name
                    )
                })?;
            let principal = Principal {
                name: user.name,
                role: user.role,
            };
            if table.insert(digest, principal).is_some() {
                return Err("two users share one token".into());
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
        Ok(if table.is_empty() {
            Self::Open
        } else {
            Self::Tokens(table)
        })
    }

    pub fn requires_credentials(&self) -> bool {
        matches!(self, Self::Tokens(_))
    }

    /// The principal a request's `Authorization` header identifies. Tokens are compared through
    /// their BLAKE3 digests, so lookup time does not depend on how much of a token is right.
    pub fn authenticate(&self, authorization: Option<&str>) -> Option<Principal> {
        match self {
            Self::Open => Some(Principal {
                name: "local".into(),
                role: Role::Admin,
            }),
            Self::Tokens(table) => {
                let token = authorization?.strip_prefix("Bearer ")?.trim();
                table
                    .get(blake3::hash(token.as_bytes()).as_bytes())
                    .cloned()
            }
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
