//! Request guards and target confinement.
//!
//! * **Host check.** A loopback-bound server accepts only `localhost` / loopback `Host` headers,
//!   which defeats DNS rebinding: a hostile web page cannot reach the API through a name it
//!   controls that resolves to 127.0.0.1.
//! * **Bearer token.** Required for every API call except `/api/health` whenever one is
//!   configured, and the server refuses to bind a non-loopback address without one. Compared
//!   through BLAKE3 digests, so the comparison time does not depend on the token.
//! * **Confinement.** Clients name a configured root and a relative path; the path is
//!   canonicalised (resolving symlinks) and must stay inside the root.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::{ApiError, AppState};

pub async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    if state.loopback_only {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !is_loopback_host(host) {
            return ApiError::new(
                StatusCode::MISDIRECTED_REQUEST,
                "requests must address localhost",
            )
            .into_response();
        }
    }
    let path = request.uri().path();
    if let Some(expected) = &state.token_digest
        && path.starts_with("/api/")
        && path != "/api/health"
    {
        let presented = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|token| blake3::hash(token.trim().as_bytes()));
        if presented.as_ref() != Some(expected) {
            return ApiError::new(StatusCode::UNAUTHORIZED, "a valid bearer token is required")
                .into_response();
        }
    }
    next.run(request).await
}

fn is_loopback_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(name, _)| name)
    } else {
        host.rsplit_once(':').map_or(host, |(name, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                name
            } else {
                host
            }
        })
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

/// A configured scan root.
#[derive(Debug, Clone)]
pub struct Root {
    pub name: String,
    /// Canonical path.
    pub path: PathBuf,
}

/// Resolves `relative` inside `root`, refusing anything that escapes it.
pub fn confine(root: &Root, relative: &str) -> Result<PathBuf, ApiError> {
    let relative = relative.trim().trim_start_matches(['/', '\\']);
    let candidate = Path::new(relative);
    if candidate
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "path must be relative to the root, without `..`",
        ));
    }
    let resolved = root
        .path
        .join(candidate)
        .canonicalize()
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such path in this root"))?;
    if !resolved.starts_with(&root.path) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "path resolves outside the root",
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for host in [
            "localhost",
            "localhost:7443",
            "127.0.0.1:80",
            "[::1]:7443",
            "LOCALHOST",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "evil.example",
            "127.0.0.1.evil.example:80",
            "10.0.0.5",
            "",
            "localhost.evil:1",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn confinement() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("app/src")).unwrap();
        let root = Root {
            name: "work".into(),
            path: dir.path().canonicalize().unwrap(),
        };
        assert!(confine(&root, "app/src").unwrap().ends_with("app/src"));
        assert_eq!(confine(&root, "").unwrap(), root.path);
        assert_eq!(
            confine(&root, "../etc").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            confine(&root, "missing").unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/", dir.path().join("escape")).unwrap();
            assert_eq!(
                confine(&root, "escape").unwrap_err().status,
                StatusCode::FORBIDDEN
            );
        }
    }
}
