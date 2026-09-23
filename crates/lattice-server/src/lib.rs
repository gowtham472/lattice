//! The LATTICE HTTP API and cockpit host.
//!
//! ```text
//! GET  /api/health                         liveness and versions (no auth)
//! GET  /api/roots                          configured scan roots (names only)
//! GET  /api/roots/{root}/entries?path=     sub-directories, to pick a target
//! POST /api/scans                          {root, path, subject?, subjectVersion?} → 202
//! GET  /api/scans                          all scans, newest first
//! GET  /api/scans/{id}                     one scan's status and summary
//! GET  /api/scans/{id}/report              explainable report
//! GET  /api/scans/{id}/cbom[?download=1]   CycloneDX 1.6 CBOM
//! GET  /api/scans/{id}/graph               crypto graph
//! GET  /api/compare?baseline=&current=&failOn=
//! ```
//!
//! Scans run one at a time on the blocking pool; the async runtime only moves bytes. Every
//! response carries a strict Content-Security-Policy, and API responses are never cached.

mod security;
mod store;

pub use security::Root;
pub use store::{ScanMeta, Status};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router, middleware};
use lattice_engine::Config;
use lattice_risk::Tier;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use store::{Artefacts, Store, valid_id};
use tokio::sync::Semaphore;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

/// Upper bound on queued plus running scans, so a client cannot queue unbounded work.
const MAX_ACTIVE_SCANS: usize = 16;
const MAX_DIRECTORY_ENTRIES: usize = 500;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; \
     base-uri 'none'; form-action 'none'";

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("refusing to listen on non-loopback address {0} without an API token")]
    TokenRequired(SocketAddr),
    #[error("scan root {name}: {reason}")]
    Root { name: String, reason: String },
    #[error("data directory: {0}")]
    Store(std::io::Error),
    #[error("cannot listen on {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
    #[error("server failed: {0}")]
    Serve(std::io::Error),
}

pub struct ServerConfig {
    pub bind: SocketAddr,
    /// (name, path) pairs; the only places scans may read.
    pub roots: Vec<(String, PathBuf)>,
    pub token: Option<String>,
    pub data_dir: Option<PathBuf>,
    /// Built cockpit (`cockpit/dist`). Without it only the API is served.
    pub ui_dir: Option<PathBuf>,
    /// Template for every scan; the timestamp and subject are set per scan.
    pub engine: Config,
    /// How the process is confined, reported by `/api/health`.
    pub sandbox: Option<lattice_sandbox::Report>,
}

pub struct AppState {
    roots: Vec<Root>,
    store: Store,
    engine: Config,
    sandbox: Option<lattice_sandbox::Report>,
    scans: Semaphore,
    counter: AtomicU64,
    pub(crate) loopback_only: bool,
    pub(crate) token_digest: Option<blake3::Hash>,
}

/// A JSON error body: `{"error": "..."}`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, format!("{what} not found"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Validates the configuration and builds the application.
pub fn app(config: ServerConfig) -> Result<Router, ServerError> {
    let loopback_only = config.bind.ip().is_loopback();
    if !loopback_only && config.token.as_deref().is_none_or(str::is_empty) {
        return Err(ServerError::TokenRequired(config.bind));
    }
    let mut roots = Vec::new();
    for (name, path) in config.roots {
        let invalid = |reason: &str| ServerError::Root {
            name: name.clone(),
            reason: reason.into(),
        };
        if !valid_id(&name) {
            return Err(invalid("names may use only letters, digits and '-'"));
        }
        if roots.iter().any(|root: &Root| root.name == name) {
            return Err(invalid("defined twice"));
        }
        let path = path.canonicalize().map_err(|e| invalid(&e.to_string()))?;
        if !path.is_dir() {
            return Err(invalid("not a directory"));
        }
        roots.push(Root { name, path });
    }
    let state = Arc::new(AppState {
        roots,
        store: Store::open(config.data_dir).map_err(ServerError::Store)?,
        engine: config.engine,
        sandbox: config.sandbox,
        scans: Semaphore::new(1),
        counter: AtomicU64::new(0),
        loopback_only,
        token_digest: config
            .token
            .filter(|t| !t.is_empty())
            .map(|t| blake3::hash(t.trim().as_bytes())),
    });

    let api = Router::new()
        .route("/health", get(health))
        .route("/roots", get(roots_list))
        .route("/roots/{root}/entries", get(entries))
        .route("/scans", get(scans_list).post(scans_create))
        .route("/scans/{id}", get(scan_get))
        .route("/scans/{id}/report", get(scan_report))
        .route("/scans/{id}/cbom", get(scan_cbom))
        .route("/scans/{id}/graph", get(scan_graph))
        .route("/compare", get(compare))
        .fallback(|| async { ApiError::not_found("endpoint") })
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let router = Router::new().nest("/api", api);
    let router = match config.ui_dir {
        // single-page app: unknown paths get index.html; /api paths never reach this
        Some(dir) => {
            let index = dir.join("index.html");
            router.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)))
        }
        None => router.fallback(|| async {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "the cockpit is not installed; start the server with --ui",
            )
        }),
    };
    Ok(router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::guard,
        ))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .with_state(state))
}

/// Binds and serves until Ctrl-C.
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    let listener = bind(config.bind).await?;
    serve_on(listener, config).await
}

/// Opens the listening socket. Separate from [`serve_on`] so the process can be confined in
/// between: once the listener exists, no further socket is ever needed.
pub async fn bind(address: SocketAddr) -> Result<tokio::net::TcpListener, ServerError> {
    tokio::net::TcpListener::bind(address)
        .await
        .map_err(|e| ServerError::Bind(address, e))
}

/// Serves on an already-bound listener until Ctrl-C.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
) -> Result<(), ServerError> {
    let bind = config.bind;
    let router = app(config)?;
    tracing::info!(%bind, "LATTICE server listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(ServerError::Serve)
}

fn now() -> (i64, String) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    (seconds, lattice_core::rfc3339(seconds))
}

// ---- handlers -----------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Health {
    status: &'static str,
    version: &'static str,
    knowledge_version: String,
    /// Compiled-in knowledge, or the activated bundle's sequence.
    knowledge_sequence: u64,
    /// Key id that signed the activated knowledge bundle, if one is in use.
    knowledge_signer: Option<String>,
    policy_version: String,
    q_day: (u16, u16),
    active_scans: usize,
    sandbox: Option<lattice_sandbox::Report>,
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Health> {
    let policy = &state.engine.policy;
    Json(Health {
        status: "ok",
        version: lattice_engine::TOOL_VERSION,
        knowledge_version: lattice_core::Registry::active().version().to_owned(),
        knowledge_sequence: lattice_engine::knowledge::active_bundle()
            .map_or(lattice_core::KNOWLEDGE_SEQUENCE, |b| b.sequence),
        knowledge_signer: lattice_engine::knowledge::active_bundle().map(|b| b.key_id.clone()),
        policy_version: policy.version.clone(),
        q_day: (policy.q_day.earliest_year, policy.q_day.latest_year),
        active_scans: state.store.active().await,
        sandbox: state.sandbox.clone(),
    })
}

#[derive(Serialize)]
struct RootInfo {
    name: String,
}

async fn roots_list(State(state): State<Arc<AppState>>) -> Json<Vec<RootInfo>> {
    Json(
        state
            .roots
            .iter()
            .map(|r| RootInfo {
                name: r.name.clone(),
            })
            .collect(),
    )
}

fn root<'s>(state: &'s AppState, name: &str) -> ApiResult<&'s Root> {
    state
        .roots
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| ApiError::not_found("root"))
}

#[derive(Deserialize)]
struct EntriesQuery {
    #[serde(default)]
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entries {
    path: String,
    directories: Vec<String>,
    files: usize,
    truncated: bool,
}

async fn entries(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<EntriesQuery>,
) -> ApiResult<Json<Entries>> {
    let root = root(&state, &name)?.clone();
    let directory = security::confine(&root, &query.path)?;
    let listing = tokio::task::spawn_blocking(move || -> std::io::Result<Entries> {
        let mut directories = Vec::new();
        let mut files = 0;
        let mut truncated = false;
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            // symlinks are neither followed nor offered
            let kind = entry.file_type()?;
            if kind.is_dir() {
                if directories.len() >= MAX_DIRECTORY_ENTRIES {
                    truncated = true;
                    continue;
                }
                directories.push(entry.file_name().to_string_lossy().into_owned());
            } else if kind.is_file() {
                files += 1;
            }
        }
        directories.sort();
        let path = lattice_core::report_path(&root.path, &directory);
        Ok(Entries {
            path: if path == "." { String::new() } else { path },
            directories,
            files,
            truncated,
        })
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "listing failed"))?
    .map_err(|e| ApiError::new(StatusCode::FORBIDDEN, format!("cannot list: {e}")))?;
    Ok(Json(listing))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScanRequest {
    root: String,
    #[serde(default)]
    path: String,
    subject: Option<String>,
    subject_version: Option<String>,
}

fn clean_label(value: Option<String>, what: &str) -> ApiResult<Option<String>> {
    match value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()) {
        Some(v) if v.chars().count() > 128 || v.chars().any(char::is_control) => {
            Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("{what} must be at most 128 printable characters"),
            ))
        }
        other => Ok(other),
    }
}

async fn scans_create(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> ApiResult<(StatusCode, Json<ScanMeta>)> {
    let root = root(&state, &request.root)?.clone();
    let target = security::confine(&root, &request.path)?;
    let subject = clean_label(request.subject, "subject")?;
    let subject_version = clean_label(request.subject_version, "subjectVersion")?;
    if state.store.active().await >= MAX_ACTIVE_SCANS {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many scans queued; try again later",
        ));
    }

    let (timestamp, requested) = now();
    let relative = lattice_core::report_path(&root.path, &target);
    let subject = subject.unwrap_or_else(|| {
        target
            .file_name()
            .map_or_else(|| root.name.clone(), |n| n.to_string_lossy().into_owned())
    });
    let sequence = state.counter.fetch_add(1, Ordering::Relaxed);
    let digest =
        blake3::hash(format!("{}|{relative}|{timestamp}|{sequence}", root.name).as_bytes());
    let id = format!(
        "{}-{}",
        requested.replace([':', '-'], "").trim_end_matches('Z'),
        &digest.to_hex()[..8]
    );
    let meta = ScanMeta {
        id: id.clone(),
        subject: subject.clone(),
        root: root.name.clone(),
        path: if relative == "." {
            String::new()
        } else {
            relative
        },
        status: Status::Queued,
        error: None,
        requested,
        finished: None,
        duration_ms: None,
        summary: None,
        failures: 0,
    };
    state.store.insert(meta.clone()).await;

    let mut config = state.engine.stamped(timestamp);
    config.subject = Some(subject);
    config.subject_version = subject_version;
    let task_state = state.clone();
    tokio::spawn(async move { run_scan(task_state, id, target, config).await });
    Ok((StatusCode::ACCEPTED, Json(meta)))
}

async fn run_scan(state: Arc<AppState>, id: String, target: PathBuf, config: Config) {
    let Ok(_permit) = state.scans.acquire().await else {
        return;
    };
    state
        .store
        .update(&id, |meta| meta.status = Status::Running)
        .await;
    let started = Instant::now();
    let result = tokio::task::spawn_blocking(
        move || -> Result<(Artefacts, lattice_cbom::Summary, usize), String> {
            let outcome = lattice_engine::run(&target, &config).map_err(|e| e.to_string())?;
            let artefacts = Artefacts {
                report: to_json(&outcome.report)?,
                cbom: lattice_cbom::render(&outcome.cbom),
                graph: to_json(&outcome.graph)?,
                bom: outcome.cbom,
            };
            Ok((
                artefacts,
                outcome.report.summary,
                outcome.report.failures.len(),
            ))
        },
    )
    .await;
    let elapsed = started.elapsed().as_millis() as u64;
    let finished = now().1;
    match result {
        Ok(Ok((artefacts, summary, failures))) => {
            tracing::info!(scan = %id, assets = summary.assets, elapsed_ms = elapsed, "scan finished");
            state
                .store
                .complete(&id, artefacts, |meta| {
                    meta.status = Status::Done;
                    meta.summary = Some(summary);
                    meta.failures = failures;
                    meta.finished = Some(finished);
                    meta.duration_ms = Some(elapsed);
                })
                .await;
        }
        failed => {
            let error = match failed {
                Ok(Err(error)) => error,
                _ => "the scan panicked; see the server log".to_owned(),
            };
            tracing::warn!(scan = %id, %error, "scan failed");
            state
                .store
                .update(&id, |meta| {
                    meta.status = Status::Failed;
                    meta.error = Some(error);
                    meta.finished = Some(finished);
                    meta.duration_ms = Some(elapsed);
                })
                .await;
        }
    }
}

fn to_json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

async fn scans_list(State(state): State<Arc<AppState>>) -> Json<Vec<ScanMeta>> {
    Json(state.store.list().await)
}

fn checked(id: &str) -> ApiResult<&str> {
    if valid_id(id) {
        Ok(id)
    } else {
        Err(ApiError::not_found("scan"))
    }
}

async fn scan_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ScanMeta>> {
    state
        .store
        .meta(checked(&id)?)
        .await
        .map(Json)
        .ok_or_else(|| ApiError::not_found("scan"))
}

async fn artefacts(state: &AppState, id: &str) -> ApiResult<Arc<Artefacts>> {
    let id = checked(id)?;
    match state.store.artefacts(id).await {
        Some(artefacts) => Ok(artefacts),
        None => match state.store.meta(id).await {
            Some(meta) => Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("scan is {:?}", meta.status).to_lowercase(),
            )),
            None => Err(ApiError::not_found("scan")),
        },
    }
}

fn json_bytes(bytes: Vec<u8>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        bytes,
    )
        .into_response()
}

async fn scan_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    Ok(json_bytes(artefacts(&state, &id).await?.report.clone()))
}

async fn scan_graph(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    Ok(json_bytes(artefacts(&state, &id).await?.graph.clone()))
}

#[derive(Deserialize)]
struct CbomQuery {
    #[serde(default)]
    download: Option<u8>,
}

async fn scan_cbom(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<CbomQuery>,
) -> ApiResult<Response> {
    let artefacts = artefacts(&state, &id).await?;
    let mut response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.cyclonedx+json"),
        )],
        artefacts.cbom.clone(),
    )
        .into_response();
    if query.download == Some(1) {
        // `id` passed `valid_id`, so it is safe inside the header
        let disposition = format!("attachment; filename=\"lattice-{id}.cdx.json\"");
        if let Ok(value) = HeaderValue::from_str(&disposition) {
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, value);
        }
    }
    Ok(response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompareQuery {
    baseline: String,
    current: String,
    fail_on: Option<String>,
}

async fn compare(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompareQuery>,
) -> ApiResult<Json<lattice_engine::compare::Comparison>> {
    let threshold = match query.fail_on.as_deref() {
        None => Tier::High,
        Some(value) => Tier::parse(value)
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "failOn must be a tier"))?,
    };
    let baseline = artefacts(&state, &query.baseline).await?;
    let current = artefacts(&state, &query.current).await?;
    Ok(Json(lattice_engine::compare::compare(
        &baseline.bom,
        &current.bom,
        threshold,
    )))
}

#[cfg(test)]
mod tests;
