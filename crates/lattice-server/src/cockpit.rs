//! The cockpit compiled into the binary (see `build.rs`), served when no `--ui` directory is
//! given. It is a single-page app: a path that names no file gets `index.html`.

use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

mod table {
    include!(concat!(env!("OUT_DIR"), "/cockpit.rs"));
}

/// Whether this build carries the cockpit.
pub fn embedded() -> bool {
    !table::FILES.is_empty()
}

/// The response for `uri` from `files`.
pub(crate) fn respond(files: &'static [(&'static str, &'static [u8])], uri: &Uri) -> Response {
    let wanted = uri.path().trim_start_matches('/');
    let found = files
        .binary_search_by(|(path, _)| (*path).cmp(wanted))
        .ok()
        .map(|index| files[index])
        .or_else(|| {
            files
                .iter()
                .copied()
                .find(|(path, _)| *path == "index.html")
        });
    let Some((path, bytes)) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Vite names assets by content hash, so they never change; the page itself may
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(mime(path))),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        bytes,
    )
        .into_response()
}

pub(crate) async fn serve(uri: Uri) -> Response {
    respond(table::FILES, &uri)
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static FILES: &[(&str, &[u8])] = &[
        ("assets/index-abc.js", b"console.log(1)"),
        ("index.html", b"<!doctype html>"),
        ("lattice.svg", b"<svg/>"),
    ];

    fn get(path: &str) -> Response {
        respond(FILES, &path.parse().unwrap())
    }

    #[test]
    fn files_are_served_with_their_types_and_routes_get_the_page() {
        let script = get("/assets/index-abc.js");
        assert_eq!(script.status(), StatusCode::OK);
        assert_eq!(
            script.headers()[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert!(
            script.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
        assert_eq!(
            get("/lattice.svg").headers()[header::CONTENT_TYPE],
            "image/svg+xml"
        );
        // a client-side route is the app
        let route = get("/inventory/42");
        assert_eq!(
            route.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(route.headers()[header::CACHE_CONTROL], "no-cache");
        // no traversal: paths are only looked up, never joined onto a directory
        assert_eq!(
            get("/../../etc/passwd").headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
    }
}
