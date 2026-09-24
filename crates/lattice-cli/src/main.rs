//! `lattice`: the command-line front end to the LATTICE engine.
//!
//! Exit codes are a contract for pipelines:
//! 0 success, 1 policy regression (ci), 2 usage or scan error, 3 verification failure.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use lattice_cbom::signing::{self, SignatureFile};
use lattice_cbom::{Bom, render};
use lattice_core::policy::Policy;
use lattice_engine::compare::{self, ChangeKind};
use lattice_engine::knowledge;
use lattice_engine::{Config, Report};
use lattice_risk::Tier;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::EnvFilter;

const EXIT_OK: u8 = 0;
const EXIT_REGRESSION: u8 = 1;
const EXIT_ERROR: u8 = 2;
const EXIT_VERIFICATION: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "lattice",
    version,
    about = "Cryptographic discovery, CBOM generation and quantum-risk assessment",
    long_about = "Scans source code, binaries, certificates, keys and configuration without executing \
                  or modifying anything, and without network access. Produces a CycloneDX 1.6 CBOM \
                  and an explainable risk report."
)]
struct Cli {
    /// Log verbosity (error, warn, info, debug, trace). Logs go to stderr.
    #[arg(long, global = true, default_value = "warn", env = "LATTICE_LOG")]
    log: String,

    /// Process confinement (Landlock + seccomp on Linux) applied before reading untrusted
    /// content: `required` refuses to run unconfined.
    #[arg(long, global = true, value_enum, default_value_t = SandboxArg::BestEffort, env = "LATTICE_SANDBOX")]
    sandbox: SandboxArg,

    /// Directory holding an installed knowledge bundle. When one is installed it must verify
    /// against --knowledge-key, or the command refuses to run.
    #[arg(long, global = true, env = "LATTICE_KNOWLEDGE_DIR")]
    knowledge_dir: Option<PathBuf>,

    /// Trusted public key for knowledge bundles (from `lattice keygen`).
    #[arg(long, global = true, env = "LATTICE_KNOWLEDGE_KEY")]
    knowledge_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a target and write its CBOM and risk report.
    Scan(ScanArgs),
    /// Scan a target and fail if it regresses against a baseline CBOM.
    Ci(CiArgs),
    /// Generate an ML-DSA-65 key pair for signing CBOMs.
    Keygen(KeygenArgs),
    /// Sign a CBOM, writing a detached signature next to it.
    Sign(SignArgs),
    /// Verify a CBOM against its detached signature and a trusted public key.
    Verify(VerifyArgs),
    /// Validate a CBOM against the CycloneDX 1.6 schema and check its internal references.
    Validate(ValidateArgs),
    /// Render the executive PDF from a report written by `scan`.
    Report(ReportArgs),
    /// Serve the HTTP API and the cockpit.
    Serve(ServeArgs),
    /// Show what the sandbox enforces on this machine, by attempting forbidden operations.
    SandboxCheck(SandboxCheckArgs),
    /// Record which cryptography running processes ask OpenSSL for (Linux, root).
    Trace(TraceArgs),
    /// Manage the users who may call the server.
    #[command(subcommand)]
    User(UserCommand),
    /// Work with the server's audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Build, install and inspect signed knowledge bundles.
    #[command(subcommand)]
    Knowledge(KnowledgeCommand),
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Check that an audit log's hash chain is intact.
    Verify(AuditVerifyArgs),
}

#[derive(Debug, Args)]
struct AuditVerifyArgs {
    /// The log (<data-dir>/audit.jsonl).
    file: PathBuf,
}

#[derive(Debug, Args)]
struct TraceArgs {
    /// How long to record, in seconds.
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// A library to probe (repeatable). Defaults to the system's libcrypto and libssl.
    #[arg(long = "library")]
    libraries: Vec<PathBuf>,

    /// Trace destination; put it in the scanned estate, in the component it describes.
    #[arg(short, long, default_value = "runtime.lattice-trace.json")]
    output: PathBuf,

    /// Show which functions would be probed, and where, without recording (needs no privilege).
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// Add a user: issue a bearer token, or pin a client certificate for mutual TLS.
    Add(UserAddArgs),
}

#[derive(Debug, Args)]
struct UserAddArgs {
    /// User name recorded in the audit log.
    #[arg(long)]
    name: String,

    /// viewer (read), operator (also start scans) or admin (also read the audit log).
    #[arg(long, value_parser = parse_role)]
    role: lattice_server::Role,

    /// Identify the user by this client certificate (PEM) instead of issuing a token.
    #[arg(long)]
    certificate: Option<PathBuf>,

    /// Append the entry to this users file (created with owner-only permissions); without it
    /// the entry is printed.
    #[arg(long)]
    users: Option<PathBuf>,
}

fn parse_role(value: &str) -> Result<lattice_server::Role, String> {
    value.parse()
}

#[derive(Debug, Subcommand)]
enum KnowledgeCommand {
    /// Build and sign a bundle from a knowledge directory and a rules file (for publishers).
    Pack(KnowledgePackArgs),
    /// Verify a bundle and install it into --knowledge-dir, refusing rollbacks.
    Install(KnowledgeInstallArgs),
    /// Show the compiled-in knowledge and the installed bundle.
    Status,
}

#[derive(Debug, Args)]
struct KnowledgePackArgs {
    /// Directory with algorithms.toml, libraries.toml and policy.toml.
    #[arg(long, default_value = "knowledge")]
    source: PathBuf,

    /// Source detection rules.
    #[arg(long, default_value = "rules/source.toml")]
    rules: PathBuf,

    /// Monotonic sequence number; must exceed every bundle published before.
    #[arg(long)]
    sequence: u64,

    /// Signing key (from `lattice keygen`).
    #[arg(long)]
    key: PathBuf,

    #[arg(long)]
    public_key: PathBuf,

    /// Bundle destination. Defaults to lattice-knowledge-<version>-<sequence>.bundle.json.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Creation time as Unix seconds. Defaults to SOURCE_DATE_EPOCH, then the current time.
    #[arg(long, env = "SOURCE_DATE_EPOCH")]
    timestamp: Option<i64>,
}

#[derive(Debug, Args)]
struct KnowledgeInstallArgs {
    /// The bundle; its signature is read from <bundle>.sig.json.
    bundle: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SandboxArg {
    Required,
    BestEffort,
    Off,
}

impl SandboxArg {
    fn flag(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::BestEffort => "best-effort",
            Self::Off => "off",
        }
    }
}

impl From<SandboxArg> for lattice_sandbox::Mode {
    fn from(value: SandboxArg) -> Self {
        match value {
            SandboxArg::Required => Self::Required,
            SandboxArg::BestEffort => Self::BestEffort,
            SandboxArg::Off => Self::Off,
        }
    }
}

#[derive(Debug, Args)]
struct SandboxCheckArgs {
    /// Print the results as JSON.
    #[arg(long)]
    json: bool,

    /// Internal: run the probes in this (confined) process against READABLE WRITABLE OUTSIDE.
    #[arg(long, hide = true, num_args = 3, value_names = ["READABLE", "WRITABLE", "OUTSIDE"])]
    probe: Option<Vec<PathBuf>>,
}

#[derive(Debug, Args, Clone)]
struct EngineArgs {
    /// Risk policy TOML replacing the embedded one (see knowledge/policy.toml).
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Report timestamp as Unix seconds. Defaults to SOURCE_DATE_EPOCH, then the current time.
    #[arg(long, env = "SOURCE_DATE_EPOCH")]
    timestamp: Option<i64>,

    /// Year Mosca's inequality is evaluated from. Defaults to the timestamp's year.
    #[arg(long)]
    assessment_year: Option<u16>,

    /// Name recorded as the scanned system. Defaults to the target directory's name.
    #[arg(long)]
    subject: Option<String>,

    /// Version recorded for the scanned system.
    #[arg(long)]
    subject_version: Option<String>,

    /// Files larger than this many bytes are skipped and reported.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_file_bytes: u64,

    /// Per-file, per-collector time limit in seconds.
    #[arg(long, default_value_t = 10)]
    parse_timeout: u64,

    /// Also scan vendored dependency trees (node_modules, vendor, ...).
    #[arg(long)]
    include_dependencies: bool,

    /// Container image archives, tarballs and packet captures larger than this are skipped.
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
    max_archive_bytes: u64,

    /// Time limit in seconds for one archive or capture.
    #[arg(long, default_value_t = 900)]
    archive_timeout: u64,

    /// Incremental-scan cache directory: unchanged files are not parsed again. Safe to delete.
    #[arg(long, env = "LATTICE_CACHE")]
    cache: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Directory or file to scan. It is only read.
    target: PathBuf,

    /// CBOM destination, or '-' for stdout.
    #[arg(short, long, default_value = "lattice.cbom.json")]
    output: PathBuf,

    /// Explainable report destination (every score with its reasons).
    #[arg(long, default_value = "lattice.report.json")]
    report: PathBuf,

    /// Also write the crypto graph (nodes and edges) as JSON.
    #[arg(long)]
    graph: Option<PathBuf>,

    /// Also write the executive report as PDF (signed too when --sign-with is given).
    #[arg(long)]
    pdf: Option<PathBuf>,

    /// Sign the CBOM with this private key (from `lattice keygen`).
    #[arg(long, requires = "public_key")]
    sign_with: Option<PathBuf>,

    /// Public key matching --sign-with.
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// How many assets the summary lists.
    #[arg(long, default_value_t = 15)]
    top: usize,

    /// Print nothing on success.
    #[arg(short, long)]
    quiet: bool,

    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Debug, Args)]
struct CiArgs {
    /// Directory or file to scan.
    target: PathBuf,

    /// CBOM to compare against.
    #[arg(long)]
    baseline: PathBuf,

    /// Require the baseline to carry a valid signature from this public key.
    #[arg(long)]
    trusted_key: Option<PathBuf>,

    /// Fail on new or worsened assets at or above this tier.
    #[arg(long, value_enum, default_value_t = TierArg::High)]
    fail_on: TierArg,

    /// Also write the current CBOM here.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Write the comparison as JSON here.
    #[arg(long)]
    changes: Option<PathBuf>,

    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Debug, Args)]
struct KeygenArgs {
    /// Directory for lattice-signing.pub and lattice-signing.key.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,

    /// File name stem.
    #[arg(long, default_value = "lattice-signing")]
    name: String,
}

#[derive(Debug, Args)]
struct ReportArgs {
    /// Report JSON written by `lattice scan --report`.
    report: PathBuf,

    /// PDF destination.
    #[arg(short, long, default_value = "lattice.report.pdf")]
    output: PathBuf,

    /// Sign the PDF with this private key, writing <output>.sig.json.
    #[arg(long, requires = "public_key")]
    sign_with: Option<PathBuf>,

    /// Public key matching --sign-with.
    #[arg(long)]
    public_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SignArgs {
    /// CBOM or executive-report PDF to sign.
    cbom: PathBuf,

    #[arg(long)]
    key: PathBuf,

    #[arg(long)]
    public_key: PathBuf,

    /// Signature destination. Defaults to <cbom>.sig.json.
    #[arg(long)]
    signature: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// CBOM or executive-report PDF to verify.
    cbom: PathBuf,

    /// The trusted public key. Never taken from the CBOM or the signature file.
    #[arg(long)]
    public_key: PathBuf,

    /// Signature file. Defaults to <cbom>.sig.json.
    #[arg(long)]
    signature: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    cbom: PathBuf,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Address to listen on. Anything other than loopback requires --users or --token.
    #[arg(long, default_value = "127.0.0.1:7443")]
    bind: std::net::SocketAddr,

    /// A directory scans may read, as NAME=PATH. Repeatable. Scans can never leave these.
    #[arg(long = "root", value_name = "NAME=PATH", required = true, value_parser = parse_root)]
    roots: Vec<(String, PathBuf)>,

    /// Users file: named users, their roles and token digests (see `lattice user add`).
    #[arg(long, env = "LATTICE_USERS")]
    users: Option<PathBuf>,

    /// A single admin bearer token, for deployments without a users file.
    #[arg(long, env = "LATTICE_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Serve TLS 1.3 (hybrid post-quantum key exchange) with this certificate chain (PEM).
    #[arg(long, env = "LATTICE_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// Private key for --tls-cert (PEM).
    #[arg(long, env = "LATTICE_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Require client certificates chaining to this CA (PEM): mutual TLS.
    #[arg(long, env = "LATTICE_CLIENT_CA", requires = "tls_cert")]
    client_ca: Option<PathBuf>,

    /// Serve plain HTTP on a non-loopback address; only behind a TLS-terminating proxy.
    #[arg(long)]
    allow_plain_http: bool,

    /// Where scan history and artefacts are kept.
    #[arg(long, default_value = ".lattice")]
    data_dir: PathBuf,

    /// Built cockpit directory (cockpit/dist).
    #[arg(long)]
    ui: Option<PathBuf>,

    /// Risk policy TOML replacing the embedded one.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Files larger than this many bytes are skipped and reported.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_file_bytes: u64,

    /// Per-file, per-collector time limit in seconds.
    #[arg(long, default_value_t = 10)]
    parse_timeout: u64,

    /// Container image archives, tarballs and packet captures larger than this are skipped.
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
    max_archive_bytes: u64,

    /// Time limit in seconds for one archive or capture.
    #[arg(long, default_value_t = 900)]
    archive_timeout: u64,

    /// Incremental-scan cache directory shared by the server's scans.
    #[arg(long, env = "LATTICE_CACHE")]
    cache: Option<PathBuf>,
}

fn parse_root(value: &str) -> Result<(String, PathBuf), String> {
    let (name, path) = value.split_once('=').ok_or("expected NAME=PATH")?;
    if name.is_empty() || path.is_empty() {
        return Err("expected NAME=PATH".into());
    }
    Ok((name.to_owned(), PathBuf::from(path)))
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TierArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<TierArg> for Tier {
    fn from(value: TierArg) -> Self {
        match value {
            TierArg::Low => Tier::Low,
            TierArg::Medium => Tier::Medium,
            TierArg::High => Tier::High,
            TierArg::Critical => Tier::Critical,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&cli.log).unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .init();

    let sandbox = lattice_sandbox::Mode::from(cli.sandbox);
    // Knowledge is fixed before anything consults it; a bundle that does not verify stops here.
    if matches!(
        cli.command,
        Command::Scan(_) | Command::Ci(_) | Command::Serve(_)
    ) && let Err(code) =
        activate_knowledge(cli.knowledge_dir.as_deref(), cli.knowledge_key.as_deref())
    {
        return ExitCode::from(code);
    }
    let knowledge = (cli.knowledge_dir, cli.knowledge_key);
    let result = match cli.command {
        Command::Scan(args) => scan(args, sandbox),
        Command::Ci(args) => ci(args, sandbox),
        Command::Keygen(args) => keygen(args).map(|()| EXIT_OK),
        Command::Sign(args) => sign(args).map(|()| EXIT_OK),
        Command::Verify(args) => verify(args, sandbox),
        Command::User(UserCommand::Add(args)) => user_add(args).map(|()| EXIT_OK),
        Command::Audit(AuditCommand::Verify(args)) => audit_verify(args, sandbox),
        Command::Report(args) => report(args, sandbox),
        Command::Trace(args) => trace(args, sandbox),
        Command::Validate(args) => validate(args, sandbox),
        Command::Serve(args) => serve(args, sandbox).map(|()| EXIT_OK),
        Command::SandboxCheck(args) => sandbox_check(args, cli.sandbox),
        Command::Knowledge(command) => knowledge_command(command, knowledge.0, knowledge.1),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("lattice: {error:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

// ---- scan ---------------------------------------------------------------------------------

fn engine_config(args: &EngineArgs) -> Result<Config> {
    let timestamp = match args.timestamp {
        Some(timestamp) => timestamp,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before 1970")?
            .as_secs() as i64,
    };
    let mut config = Config::new(timestamp);
    if let Some(path) = &args.policy {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        config.policy = Policy::from_toml(&text)
            .with_context(|| format!("invalid policy {}", path.display()))?;
    }
    if let Some(year) = args.assessment_year {
        config.assessment_year = year;
    }
    if config.assessment_year > config.policy.q_day.latest_year {
        bail!(
            "assessment year {} is after the policy's latest Q-day {}; update the policy",
            config.assessment_year,
            config.policy.q_day.latest_year
        );
    }
    config.subject = args.subject.clone();
    config.subject_version = args.subject_version.clone();
    config.scan.max_file_bytes = args.max_file_bytes;
    config.scan.parse_timeout = Duration::from_secs(args.parse_timeout.max(1));
    config.scan.include_dependencies = args.include_dependencies;
    config.scan.max_archive_bytes = args.max_archive_bytes;
    config.scan.archive_timeout = Duration::from_secs(args.archive_timeout.max(1));
    config.scan.cache = open_cache(args.cache.as_deref())?;
    Ok(config)
}

/// Opens the incremental cache before confinement: it fingerprints this executable.
fn open_cache(
    dir: Option<&Path>,
) -> Result<Option<std::sync::Arc<lattice_collectors::cache::Cache>>> {
    dir.map(|dir| {
        lattice_collectors::cache::Cache::open(dir)
            .map(std::sync::Arc::new)
            .with_context(|| format!("opening the cache {}", dir.display()))
    })
    .transpose()
}

/// The writable location confinement must allow for the cache (entries live beneath it).
fn cache_marker(dir: &Path) -> PathBuf {
    dir.join("v1").join("entry")
}

/// Confines the process: `read` stay readable, and the directories holding `write` become the
/// only writable places. Those directories are created first, since nothing can be created
/// outside them afterwards.
fn confine(
    mode: lattice_sandbox::Mode,
    read: &[&Path],
    write: &[&Path],
) -> Result<lattice_sandbox::Report> {
    let mut plan = lattice_sandbox::Plan::default();
    for path in read {
        let resolved = path
            .canonicalize()
            .with_context(|| format!("resolving {}", path.display()))?;
        plan.read.push(resolved);
    }
    for path in write {
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(directory)
            .with_context(|| format!("creating {}", directory.display()))?;
        plan.write.push(directory.canonicalize()?);
    }
    let report = lattice_sandbox::apply(&plan, mode)?;
    tracing::info!(sandbox = %report.summary(), "process confined");
    Ok(report)
}

fn scan(args: ScanArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    if !args.target.exists() {
        bail!("{} does not exist", args.target.display());
    }
    let config = engine_config(&args.engine)?;
    let to_stdout = args.output.as_os_str() == "-";
    if to_stdout && args.sign_with.is_some() {
        bail!("--sign-with needs a CBOM file, not stdout");
    }
    // keys are read before confinement: the key files stay out of the sandbox's reach
    let keys = match &args.sign_with {
        Some(key) => {
            let public_key = args
                .public_key
                .as_ref()
                .expect("clap enforces --public-key");
            Some(load_keys(key, public_key)?)
        }
        None => None,
    };
    let signature_file = signature_path(&args.output, None);
    let mut outputs: Vec<&Path> = vec![&args.report];
    if !to_stdout {
        outputs.push(&args.output);
    }
    if let Some(graph) = &args.graph {
        outputs.push(graph);
    }
    let pdf_signature_file = args.pdf.as_deref().map(|pdf| signature_path(pdf, None));
    if let Some(pdf) = &args.pdf {
        outputs.push(pdf);
    }
    if keys.is_some() {
        outputs.push(&signature_file);
        outputs.extend(pdf_signature_file.as_deref());
    }
    let cache_marker = args.engine.cache.as_deref().map(cache_marker);
    if let Some(marker) = &cache_marker {
        outputs.push(marker);
    }
    let confinement = confine(sandbox, &[&args.target], &outputs)?;

    let outcome = lattice_engine::run(&args.target, &config)?;
    let cbom = render(&outcome.cbom);
    if to_stdout {
        std::io::stdout()
            .write_all(&cbom)
            .context("writing the CBOM to stdout")?;
    } else {
        write_atomic(&args.output, &cbom)?;
    }
    let report_bytes = pretty(&outcome.report)?;
    write_atomic(&args.report, &report_bytes)?;
    if let Some(path) = &args.graph {
        write_atomic(path, &pretty(&outcome.graph)?)?;
    }
    let pdf = match &args.pdf {
        Some(path) => {
            let pdf = lattice_report::executive_pdf(&report_bytes)?;
            write_atomic(path, &pdf)?;
            Some(pdf)
        }
        None => None,
    };
    if let Some((private, public)) = &keys {
        let signature = signing::sign(&cbom, private, public)?;
        write_atomic(&signature_file, &pretty(&signature)?)?;
        if let (Some(pdf), Some(path)) = (&pdf, &pdf_signature_file) {
            let signature =
                signing::sign_blob(pdf, lattice_report::PDF_SIGNATURE_CONTEXT, private, public)?;
            write_atomic(path, &pretty(&signature)?)?;
        }
    }
    if !args.quiet && !to_stdout {
        print_summary(&outcome.report, args.top);
        println!();
        println!("CBOM    {}", args.output.display());
        println!("report  {}", args.report.display());
        if let Some(path) = &args.graph {
            println!("graph   {}", path.display());
        }
        if let Some(path) = &args.pdf {
            println!("PDF     {}", path.display());
        }
        if keys.is_some() {
            println!("signed  {}", signature_file.display());
            if let Some(path) = &pdf_signature_file {
                println!("signed  {}", path.display());
            }
        }
        println!("sandbox {}", confinement.summary());
        if args.engine.cache.is_some() {
            println!(
                "cache   {} of {} files reused",
                outcome.report.stats.cache_hits, outcome.report.stats.files_scanned
            );
        }
    }
    Ok(EXIT_OK)
}

fn print_summary(report: &Report, top: usize) {
    let s = &report.summary;
    println!(
        "LATTICE {}  {}  ({})",
        report.provenance.tool_version, report.subject, report.generated
    );
    let provenance = &report.provenance;
    println!(
        "knowledge {} #{} ({}), rules {}, policy {}",
        provenance.knowledge_version,
        provenance.knowledge_sequence,
        provenance.knowledge_signer.as_deref().map_or_else(
            || "compiled in".to_owned(),
            |signer| format!("bundle signed by {signer}")
        ),
        provenance.rules_version,
        provenance.policy_version
    );
    println!(
        "scanned {} files ({} bytes); {} failed; graph: {} functions, {} entry points",
        report.stats.files_scanned,
        report.stats.bytes_scanned,
        report.failures.len(),
        report.graph.functions,
        report.graph.entry_points
    );
    println!(
        "{} assets: {} quantum-vulnerable, {} broken today, {} Mosca-urgent, {} critical, {} high",
        s.assets, s.quantum_vulnerable, s.broken_now, s.mosca_urgent, s.critical, s.high
    );
    if report.assets.is_empty() {
        return;
    }
    println!();
    println!(
        "{:<9} {:>4}  {:<28} {:<34} RECOMMENDATION",
        "TIER", "PRI", "ASSET", "WHERE"
    );
    for asset in report.assets.iter().take(top) {
        let location = asset
            .asset
            .occurrences
            .first()
            .map(|o| o.location.short())
            .unwrap_or_default();
        println!(
            "{:<9} {:>4}  {:<28} {:<34} {} {}",
            asset.assessment.tier.as_str(),
            asset.assessment.priority,
            clip(&asset.asset.finding.display_name(), 28),
            clip(&location, 34),
            asset.recommendation.action,
            asset.recommendation.target
        );
    }
    if report.assets.len() > top {
        println!("... {} more in the report", report.assets.len() - top);
    }
    let plan = &report.plan;
    println!();
    println!(
        "roadmap: {} changes, {} person-weeks, against {}",
        report.roadmap.len(),
        plan.total_person_weeks,
        plan.timeline
    );
    for wave in &plan.waves {
        let due = match (wave.due_year, wave.engineers_needed) {
            _ if wave.overdue => format!("due {} - overdue", wave.due_year.unwrap_or_default()),
            (Some(year), Some(engineers)) => {
                format!("due {year} - {engineers} engineers full-time")
            }
            _ => "no deadline".into(),
        };
        println!(
            "  {:<32} {:>3} items {:>7} pw   {}",
            wave.name, wave.items, wave.person_weeks, due
        );
    }
    if let Some(engineers) = plan.engineers_needed {
        println!("  team to meet every deadline: {engineers} engineers full-time");
    }
    for failure in report.failures.iter().take(5) {
        println!(
            "warning: {} ({}): {}",
            failure.path, failure.collector, failure.reason
        );
    }
}

fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut clipped: String = text.chars().take(width - 1).collect();
    clipped.push('…');
    clipped
}

// ---- ci -----------------------------------------------------------------------------------

fn ci(args: CiArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let baseline_bytes =
        fs::read(&args.baseline).with_context(|| format!("reading {}", args.baseline.display()))?;
    if let Some(key) = &args.trusted_key
        && let Err(error) = verify_bytes(&baseline_bytes, &args.baseline, None, key)
    {
        eprintln!(
            "lattice: baseline {} failed verification: {error:#}",
            args.baseline.display()
        );
        return Ok(EXIT_VERIFICATION);
    }
    if !args.target.exists() {
        bail!("{} does not exist", args.target.display());
    }
    let config = engine_config(&args.engine)?;
    let cache_marker = args.engine.cache.as_deref().map(cache_marker);
    let outputs: Vec<&Path> = [
        args.output.as_deref(),
        args.changes.as_deref(),
        cache_marker.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    confine(sandbox, &[&args.target], &outputs)?;

    let baseline: Bom = serde_json::from_slice(&baseline_bytes)
        .with_context(|| format!("{} is not a LATTICE CBOM", args.baseline.display()))?;
    let outcome = lattice_engine::run(&args.target, &config)?;
    if let Some(path) = &args.output {
        write_atomic(path, &render(&outcome.cbom))?;
    }
    let comparison = compare::compare(&baseline, &outcome.cbom, args.fail_on.into());
    if let Some(path) = &args.changes {
        write_atomic(path, &pretty(&comparison)?)?;
    }

    for change in &comparison.changes {
        let marker = if change.regression { "FAIL" } else { "    " };
        let kind = match change.kind {
            ChangeKind::Added => "added",
            ChangeKind::Worsened => "worsened",
            ChangeKind::Improved => "improved",
            ChangeKind::Removed => "removed",
        };
        println!(
            "{marker} {kind:<9} {:<28} {:<24} {}",
            clip(&change.name, 28),
            clip(&change.component, 24),
            change.reason
        );
    }
    let regressions = comparison.regressions().count();
    if regressions == 0 {
        println!(
            "lattice ci: passed ({} changes, none at or above {})",
            comparison.changes.len(),
            comparison.threshold.as_str()
        );
        Ok(EXIT_OK)
    } else {
        println!(
            "lattice ci: {regressions} regression(s) at or above {}",
            comparison.threshold.as_str()
        );
        Ok(EXIT_REGRESSION)
    }
}

// ---- keys and signatures ------------------------------------------------------------------

fn keygen(args: KeygenArgs) -> Result<()> {
    let public_path = args.out_dir.join(format!("{}.pub", args.name));
    let private_path = args.out_dir.join(format!("{}.key", args.name));
    for path in [&public_path, &private_path] {
        if path.exists() {
            bail!(
                "{} already exists; refusing to overwrite a key",
                path.display()
            );
        }
    }
    let keys = signing::generate_keypair()?;
    write_private(
        &private_path,
        signing::encode_private_key(&keys.private_key).as_bytes(),
    )?;
    write_atomic(
        &public_path,
        signing::encode_public_key(&keys.public_key).as_bytes(),
    )?;
    println!("key id   {}", signing::key_id(&keys.public_key));
    println!("public   {}", public_path.display());
    println!(
        "private  {} (keep offline; owner-only permissions)",
        private_path.display()
    );
    Ok(())
}

fn load_keys(key: &Path, public_key: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let private = signing::decode_private_key(&read_text(key)?)?;
    let public = signing::decode_public_key(&read_text(public_key)?)?;
    Ok((private, public))
}

fn sign_bytes(document: &[u8], key: &Path, public_key: &Path) -> Result<SignatureFile> {
    let (private, public) = load_keys(key, public_key)?;
    Ok(signing::sign(document, &private, &public)?)
}

fn is_pdf(document: &[u8]) -> bool {
    document.starts_with(b"%PDF-")
}

fn sign(args: SignArgs) -> Result<()> {
    let document =
        fs::read(&args.cbom).with_context(|| format!("reading {}", args.cbom.display()))?;
    let path = signature_path(&args.cbom, args.signature.as_deref());
    if is_pdf(&document) {
        let (private, public) = load_keys(&args.key, &args.public_key)?;
        let signature = signing::sign_blob(
            &document,
            lattice_report::PDF_SIGNATURE_CONTEXT,
            &private,
            &public,
        )?;
        write_atomic(&path, &pretty(&signature)?)?;
        println!(
            "signed {} ({} bytes) -> {}",
            args.cbom.display(),
            signature.bytes,
            path.display()
        );
        return Ok(());
    }
    let signature = sign_bytes(&document, &args.key, &args.public_key)?;
    write_atomic(&path, &pretty(&signature)?)?;
    println!(
        "signed {} ({} components) -> {}",
        args.cbom.display(),
        signature.chain.len(),
        path.display()
    );
    Ok(())
}

fn verify_bytes(
    document: &[u8],
    cbom: &Path,
    signature: Option<&Path>,
    public_key: &Path,
) -> Result<SignatureFile> {
    let path = signature_path(cbom, signature);
    let signature: SignatureFile = serde_json::from_str(&read_document(&path)?)
        .with_context(|| format!("{} is not a LATTICE signature file", path.display()))?;
    let trusted = signing::decode_public_key(&read_text(public_key)?)?;
    signing::verify(document, &signature, &trusted)?;
    Ok(signature)
}

fn verify(args: VerifyArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let document =
        fs::read(&args.cbom).with_context(|| format!("reading {}", args.cbom.display()))?;
    let signature_file = signature_path(&args.cbom, args.signature.as_deref());
    let signature_text = read_document(&signature_file)?;
    let key_text = read_text(&args.public_key)?;
    // everything is in memory: the parsing and verification below need no filesystem at all
    confine(sandbox, &[], &[])?;
    if is_pdf(&document) {
        let checked = (|| -> Result<signing::BlobSignature> {
            let signature: signing::BlobSignature = serde_json::from_str(&signature_text)
                .with_context(|| {
                    format!(
                        "{} is not a LATTICE signature file",
                        signature_file.display()
                    )
                })?;
            let trusted = signing::decode_public_key(&key_text)?;
            signing::verify_blob(
                &document,
                &signature,
                lattice_report::PDF_SIGNATURE_CONTEXT,
                &trusted,
            )?;
            Ok(signature)
        })();
        return Ok(match checked {
            Ok(signature) => {
                println!(
                    "verified {}: executive report, {} bytes, signed by key {} ({})",
                    args.cbom.display(),
                    signature.bytes,
                    signature.key_id,
                    signature.algorithm
                );
                EXIT_OK
            }
            Err(error) => {
                eprintln!(
                    "lattice: verification FAILED for {}: {error:#}",
                    args.cbom.display()
                );
                EXIT_VERIFICATION
            }
        });
    }
    let checked = (|| -> Result<SignatureFile> {
        let signature: SignatureFile =
            serde_json::from_str(&signature_text).with_context(|| {
                format!(
                    "{} is not a LATTICE signature file",
                    signature_file.display()
                )
            })?;
        let trusted = signing::decode_public_key(&key_text)?;
        signing::verify(&document, &signature, &trusted)?;
        Ok(signature)
    })();
    match checked {
        Ok(signature) => {
            println!(
                "verified {}: {} components, signed by key {} ({})",
                args.cbom.display(),
                signature.chain.len(),
                signature.key_id,
                signature.algorithm
            );
            Ok(EXIT_OK)
        }
        Err(error) => {
            eprintln!(
                "lattice: verification FAILED for {}: {error:#}",
                args.cbom.display()
            );
            Ok(EXIT_VERIFICATION)
        }
    }
}

fn trace(args: TraceArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let libraries = if args.libraries.is_empty() {
        lattice_tracer::default_libraries()
    } else {
        args.libraries.clone()
    };
    if args.dry_run {
        let probes = lattice_tracer::plan(&libraries)?;
        let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
        for probe in &probes {
            let role = match probe.role {
                lattice_tracer::Role::Call(kind) => format!("{kind:?}"),
                lattice_tracer::Role::SetupEnter => "setup entry".into(),
                lattice_tracer::Role::SetupExit => "setup return".into(),
            };
            *by_kind.entry(role.clone()).or_default() += 1;
            if probe.role != lattice_tracer::Role::Call(lattice_tracer::CallKind::Getter) {
                println!(
                    "{:<32} {:<12} {}:0x{:x}",
                    probe.function,
                    role,
                    probe.library.display(),
                    probe.offset
                );
            }
        }
        println!(
            "{} probes in {} libraries ({}); legacy getters not listed",
            probes.len(),
            libraries.len(),
            by_kind
                .iter()
                .map(|(kind, count)| format!("{kind} {count}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        return Ok(EXIT_OK);
    }

    // confined: tracefs and the output are writable, the libraries and /proc readable; no
    // network and no program execution
    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|root| root.join("uprobe_events").exists());
    let mut read: Vec<&Path> = libraries.iter().map(PathBuf::as_path).collect();
    read.push(Path::new("/proc"));
    let uprobe_events = tracefs.as_ref().map(|root| root.join("uprobe_events"));
    let mut write: Vec<&Path> = vec![&args.output];
    write.extend(uprobe_events.as_deref());
    let confinement = confine(sandbox, &read, &write)?;

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                runtime.block_on(async {
                    let _ = tokio::signal::ctrl_c().await;
                });
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }
    eprintln!(
        "recording for up to {} s (Ctrl-C stops early; sandbox: {})",
        args.duration,
        confinement.summary()
    );
    let options = lattice_tracer::Options {
        libraries,
        duration: Duration::from_secs(args.duration),
        max_distinct: 20_000,
    };
    let (recorded, dropped) = lattice_tracer::record(&options, &|| {
        stop.load(std::sync::atomic::Ordering::Relaxed)
    })?;
    write_atomic(&args.output, &pretty(&recorded)?)?;
    let executables: std::collections::BTreeSet<&str> = recorded
        .events
        .iter()
        .map(|e| e.executable.as_str())
        .collect();
    println!(
        "recorded {} distinct calls from {} executables in {} s{} -> {}",
        recorded.events.len(),
        executables.len(),
        recorded.duration_seconds,
        if dropped > 0 {
            format!(" ({dropped} dropped or rejected)")
        } else {
            String::new()
        },
        args.output.display()
    );
    Ok(EXIT_OK)
}

fn report(args: ReportArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let input =
        fs::read(&args.report).with_context(|| format!("reading {}", args.report.display()))?;
    let keys = match &args.sign_with {
        Some(key) => Some(load_keys(
            key,
            args.public_key
                .as_ref()
                .expect("clap enforces --public-key"),
        )?),
        None => None,
    };
    let signature_file = signature_path(&args.output, None);
    let mut outputs: Vec<&Path> = vec![&args.output];
    if keys.is_some() {
        outputs.push(&signature_file);
    }
    // the report is untrusted input: parse it confined, with only the outputs writable
    confine(sandbox, &[], &outputs)?;
    let pdf = lattice_report::executive_pdf(&input)?;
    write_atomic(&args.output, &pdf)?;
    println!("PDF     {} ({} bytes)", args.output.display(), pdf.len());
    if let Some((private, public)) = &keys {
        let signature =
            signing::sign_blob(&pdf, lattice_report::PDF_SIGNATURE_CONTEXT, private, public)?;
        write_atomic(&signature_file, &pretty(&signature)?)?;
        println!("signed  {}", signature_file.display());
    }
    Ok(EXIT_OK)
}

fn user_add(args: UserAddArgs) -> Result<()> {
    let (token, user) = match &args.certificate {
        Some(path) => {
            let pem = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            let der = lattice_server::tls::first_certificate(&pem)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            let user = lattice_server::access::pin_certificate(&args.name, args.role, &der)
                .map_err(anyhow::Error::msg)?;
            (None, user)
        }
        None => {
            let (token, user) =
                lattice_server::access::issue(&args.name, args.role).map_err(anyhow::Error::msg)?;
            (Some(token), user)
        }
    };
    let mut entry = format!(
        "[[user]]\nname = {:?}\nrole = {:?}\n",
        user.name,
        user.role.as_str()
    );
    if let Some(digest) = &user.token_blake3 {
        entry.push_str(&format!("token_blake3 = {digest:?}\n"));
    }
    if let Some(fingerprint) = &user.certificate_sha256 {
        entry.push_str(&format!("certificate_sha256 = {fingerprint:?}\n"));
    }
    match &args.users {
        Some(path) => {
            if path.exists() {
                let existing = lattice_server::access::parse_users(&read_text(path)?)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                if existing.iter().any(|u| u.name == user.name) {
                    bail!("{} already has a user named {}", path.display(), user.name);
                }
            }
            let mut file = fs::OpenOptions::new();
            file.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut file, 0o600);
            let mut file = file
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?;
            writeln!(file)?;
            file.write_all(entry.as_bytes())?;
            eprintln!(
                "added {} ({}) to {}",
                user.name,
                user.role.as_str(),
                path.display()
            );
        }
        None => {
            eprintln!("add this to the users file:");
            print!("{entry}");
        }
    }
    if let Some(token) = token {
        eprintln!("token for {} (shown once, store it securely):", user.name);
        println!("{token}");
    }
    Ok(())
}

fn audit_verify(args: AuditVerifyArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let bytes = fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    confine(sandbox, &[], &[])?;
    match lattice_server::audit::verify(&bytes) {
        Ok(verified) => {
            println!(
                "verified {}: {} entries, chain intact, head {}",
                args.file.display(),
                verified.entries,
                verified.head
            );
            Ok(EXIT_OK)
        }
        Err(error) => {
            eprintln!(
                "lattice: audit log verification FAILED for {}: {error}",
                args.file.display()
            );
            Ok(EXIT_VERIFICATION)
        }
    }
}

fn validate(args: ValidateArgs, sandbox: lattice_sandbox::Mode) -> Result<u8> {
    let text = read_document(&args.cbom)?;
    confine(sandbox, &[], &[])?;
    let document: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not JSON", args.cbom.display()))?;
    let mut violations = Vec::new();
    if let Err(found) = lattice_cbom::validate::validate(&document) {
        violations.extend(found);
    }
    if let Err(found) = lattice_cbom::validate::check_references(&document) {
        violations.extend(found);
    }
    if violations.is_empty() {
        println!("{}: valid CycloneDX 1.6", args.cbom.display());
        return Ok(EXIT_OK);
    }
    for violation in &violations {
        eprintln!("{violation}");
    }
    eprintln!("{}: {} violation(s)", args.cbom.display(), violations.len());
    Ok(EXIT_VERIFICATION)
}

// ---- serve -------------------------------------------------------------------------------

fn serve(args: ServeArgs, sandbox: lattice_sandbox::Mode) -> Result<()> {
    let mut engine = Config::new(0);
    if let Some(path) = &args.policy {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        engine.policy = Policy::from_toml(&text)
            .with_context(|| format!("invalid policy {}", path.display()))?;
    }
    engine.scan.max_file_bytes = args.max_file_bytes;
    engine.scan.parse_timeout = Duration::from_secs(args.parse_timeout.max(1));
    engine.scan.max_archive_bytes = args.max_archive_bytes;
    engine.scan.archive_timeout = Duration::from_secs(args.archive_timeout.max(1));
    engine.scan.cache = open_cache(args.cache.as_deref())?;
    let ui = args.ui.or_else(installed_cockpit);
    if ui.is_none() {
        eprintln!(
            "lattice: cockpit not found (build it with `npm run build` in cockpit/ or pass --ui); serving the API only"
        );
    }
    fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("creating {}", args.data_dir.display()))?;
    // read before confinement: the users file stays out of the sandbox's reach
    let users = match &args.users {
        Some(path) => lattice_server::access::parse_users(&read_text(path)?)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        None => Vec::new(),
    };
    // certificate, key and client CA are read before confinement too
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(certificate), Some(key)) => {
            let read =
                |path: &Path| fs::read(path).with_context(|| format!("reading {}", path.display()));
            let client_ca = args.client_ca.as_deref().map(read).transpose()?;
            Some(
                lattice_server::tls::configure(
                    &read(certificate)?,
                    &read(key)?,
                    client_ca.as_deref(),
                )
                .map_err(anyhow::Error::msg)?,
            )
        }
        _ => None,
    };
    let scheme = if tls.is_some() { "https" } else { "http" };
    let mut config = lattice_server::ServerConfig {
        bind: args.bind,
        roots: args.roots,
        token: args.token,
        users,
        tls,
        allow_plain_http: args.allow_plain_http,
        data_dir: Some(args.data_dir.clone()),
        ui_dir: ui,
        engine,
        sandbox: None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let listener = lattice_server::bind(config.bind).await?;
        // confined once listening: the roots and the cockpit are read-only, the data directory
        // is the only writable place, and no new socket can be opened again
        let mut read: Vec<&Path> = config
            .roots
            .iter()
            .map(|(_, path)| path.as_path())
            .collect();
        if let Some(ui) = &config.ui_dir {
            read.push(ui);
        }
        let data = args.data_dir.join("scans");
        let audit = args.data_dir.join(lattice_server::audit::FILE_NAME);
        let cache = args.cache.as_deref().map(cache_marker);
        let mut write: Vec<&Path> = vec![&data, &audit];
        if let Some(cache) = &cache {
            write.push(cache);
        }
        let report = confine(sandbox, &read, &write)?;
        println!(
            "LATTICE cockpit on {scheme}://{} (sandbox: {})",
            config.bind,
            report.summary()
        );
        config.sandbox = Some(report);
        lattice_server::serve_on(listener, config).await?;
        Ok::<(), anyhow::Error>(())
    })
}

/// The cockpit next to an installed binary (`<prefix>/bin/lattice` with
/// `<prefix>/share/lattice/cockpit`), else a source checkout's build (`cockpit/dist`).
fn installed_cockpit() -> Option<PathBuf> {
    let installed = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()?
            .parent()
            .map(|prefix| prefix.join("share/lattice/cockpit"))
    });
    installed
        .into_iter()
        .chain([PathBuf::from("cockpit/dist")])
        .find(|dir| dir.join("index.html").is_file())
}

// ---- knowledge bundles ----------------------------------------------------------------------

/// Activates the installed bundle, if any. Errors are printed here; the exit code says why.
fn activate_knowledge(dir: Option<&Path>, key: Option<&Path>) -> Result<(), u8> {
    let Some(dir) = dir else { return Ok(()) };
    let trusted = match key.map(read_text).transpose() {
        Ok(text) => match text.map(|t| signing::decode_public_key(&t)).transpose() {
            Ok(key) => key,
            Err(error) => {
                eprintln!("lattice: knowledge key: {error}");
                return Err(EXIT_ERROR);
            }
        },
        Err(error) => {
            eprintln!("lattice: knowledge key: {error:#}");
            return Err(EXIT_ERROR);
        }
    };
    match knowledge::activate(dir, trusted.as_deref()) {
        Ok(Some(bundle)) => {
            tracing::info!(version = %bundle.version, sequence = bundle.sequence, signer = %bundle.key_id, "knowledge bundle activated");
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => {
            eprintln!("lattice: refusing to run with this knowledge: {error}");
            Err(match error {
                knowledge::KnowledgeError::Signature(_)
                | knowledge::KnowledgeError::Rollback { .. }
                | knowledge::KnowledgeError::Outdated { .. }
                | knowledge::KnowledgeError::MissingKey(_) => EXIT_VERIFICATION,
                _ => EXIT_ERROR,
            })
        }
    }
}

fn knowledge_command(
    command: KnowledgeCommand,
    dir: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<u8> {
    let trusted_key = || -> Result<Vec<u8>> {
        let path = key
            .as_ref()
            .context("--knowledge-key (or LATTICE_KNOWLEDGE_KEY) is required")?;
        Ok(signing::decode_public_key(&read_text(path)?)?)
    };
    match command {
        KnowledgeCommand::Pack(args) => {
            let timestamp = match args.timestamp {
                Some(timestamp) => timestamp,
                None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            };
            let (private, public) = load_keys(&args.key, &args.public_key)?;
            let (bytes, bundle) =
                knowledge::pack(&args.source, &args.rules, args.sequence, timestamp)?;
            let signature = knowledge::sign(&bytes, &private, &public)?;
            let output = args.output.unwrap_or_else(|| {
                PathBuf::from(format!(
                    "lattice-knowledge-{}-{}.bundle.json",
                    bundle.version, bundle.sequence
                ))
            });
            write_atomic(&output, &bytes)?;
            write_atomic(&knowledge::signature_path(&output), &pretty(&signature)?)?;
            println!(
                "packed knowledge {} #{} -> {} (signed by {})",
                bundle.version,
                bundle.sequence,
                output.display(),
                signature.key_id
            );
            Ok(EXIT_OK)
        }
        KnowledgeCommand::Install(args) => {
            let dir = dir.context("--knowledge-dir (or LATTICE_KNOWLEDGE_DIR) is required")?;
            match knowledge::install(
                &args.bundle,
                &knowledge::signature_path(&args.bundle),
                &trusted_key()?,
                &dir,
            ) {
                Ok(bundle) => {
                    println!(
                        "installed knowledge {} #{} into {} (rules {}, policy {}, signed by {})",
                        bundle.version,
                        bundle.sequence,
                        dir.display(),
                        bundle.rules_version,
                        bundle.policy_version,
                        bundle.key_id
                    );
                    Ok(EXIT_OK)
                }
                Err(error) => {
                    eprintln!("lattice: not installed: {error}");
                    Ok(EXIT_VERIFICATION)
                }
            }
        }
        KnowledgeCommand::Status => {
            let compiled = lattice_core::Registry::compiled();
            println!(
                "compiled-in  knowledge {} #{}",
                compiled.version(),
                lattice_core::KNOWLEDGE_SEQUENCE
            );
            let Some(dir) = dir else {
                println!("installed    none (no --knowledge-dir)");
                return Ok(EXIT_OK);
            };
            let key = key.as_ref().map(|_| trusted_key()).transpose()?;
            match knowledge::status(&dir, key.as_deref()) {
                Ok(Some((bundle, verified))) => {
                    println!(
                        "installed    knowledge {} #{} from {} (rules {}, policy {}, signed by {}, {})",
                        bundle.version,
                        bundle.sequence,
                        bundle.created,
                        bundle.rules_version,
                        bundle.policy_version,
                        bundle.key_id,
                        if verified {
                            "verified"
                        } else {
                            "NOT verified: pass --knowledge-key"
                        }
                    );
                    Ok(EXIT_OK)
                }
                Ok(None) => {
                    println!("installed    none in {}", dir.display());
                    Ok(EXIT_OK)
                }
                Err(error) => {
                    eprintln!("lattice: installed bundle is not usable: {error}");
                    Ok(EXIT_VERIFICATION)
                }
            }
        }
    }
}

// ---- sandbox check --------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct Probe {
    name: String,
    layer: String,
    /// What confinement should make of it: `allowed` or `denied`.
    expected: String,
    observed: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProbeResult {
    sandbox: serde_json::Value,
    probes: Vec<Probe>,
}

fn sandbox_check(args: SandboxCheckArgs, mode: SandboxArg) -> Result<u8> {
    if let Some(paths) = &args.probe {
        return run_probes(&paths[0], &paths[1], &paths[2], mode.into());
    }
    // The probes run in a child that confines itself; this process stays free to clean up.
    let base = std::env::temp_dir().join(format!("lattice-sandbox-check-{}", std::process::id()));
    let (readable, writable, outside) = (
        base.join("readable"),
        base.join("writable"),
        base.join("outside"),
    );
    for directory in [&readable, &writable, &outside] {
        fs::create_dir_all(directory)?;
    }
    fs::write(readable.join("sample.txt"), b"readable")?;
    fs::write(outside.join("secret.txt"), b"outside the sandbox")?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--sandbox", mode.flag(), "sandbox-check", "--probe"])
        .args([&readable, &writable, &outside])
        .output()
        .context("running the probe process")?;
    let _ = fs::remove_dir_all(&base);
    if !output.status.success() {
        bail!(
            "probe process failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let result: ProbeResult =
        serde_json::from_slice(&output.stdout).context("reading probe results")?;
    let failed = result
        .probes
        .iter()
        .filter(|p| p.expected != p.observed)
        .count();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let layer = |name: &str| {
            let state = &result.sandbox[name];
            match state["detail"].as_str() {
                Some(detail) => format!("{} ({detail})", state["state"].as_str().unwrap_or("?")),
                None => state["state"].as_str().unwrap_or("?").to_owned(),
            }
        };
        println!("filesystem    {}", layer("filesystem"));
        println!("system calls  {}", layer("syscalls"));
        println!();
        for probe in &result.probes {
            let verdict = if probe.expected == probe.observed {
                "ok  "
            } else {
                "FAIL"
            };
            println!(
                "{verdict} {:<34} {:<12} expected {:<8} observed {}",
                probe.name, probe.layer, probe.expected, probe.observed
            );
        }
    }
    Ok(if failed == 0 {
        EXIT_OK
    } else {
        EXIT_VERIFICATION
    })
}

/// Runs in the confined child: attempts each operation and records what the kernel allowed.
fn run_probes(
    readable: &Path,
    writable: &Path,
    outside: &Path,
    mode: lattice_sandbox::Mode,
) -> Result<u8> {
    let plan = lattice_sandbox::Plan {
        read: vec![readable.to_path_buf()],
        write: vec![writable.to_path_buf()],
    };
    let report = lattice_sandbox::apply(&plan, mode)?;
    let observe = |result: std::io::Result<()>| match result {
        Ok(()) => "allowed".to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => "denied".to_owned(),
        Err(error) => format!("error: {error}"),
    };
    let expect = |active: bool| if active { "denied" } else { "allowed" }.to_owned();
    let filesystem = report.filesystem.is_active();
    let syscalls = report.syscalls.is_active();
    let probe = |name: &str, layer: &str, expected: String, observed: String| Probe {
        name: name.into(),
        layer: layer.into(),
        expected,
        observed,
    };
    let network = match std::net::TcpStream::connect(("127.0.0.1", 9)) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => "denied".to_owned(),
        // connected, refused or unreachable: a socket was created, so the network is reachable
        _ => "allowed".to_owned(),
    };
    let probes = vec![
        probe(
            "read inside a scan target",
            "filesystem",
            "allowed".into(),
            observe(fs::read(readable.join("sample.txt")).map(drop)),
        ),
        probe(
            "write to an output directory",
            "filesystem",
            "allowed".into(),
            observe(fs::write(writable.join("report.json"), b"{}")),
        ),
        probe(
            "read a file outside the targets",
            "filesystem",
            expect(filesystem),
            observe(fs::read(outside.join("secret.txt")).map(drop)),
        ),
        probe(
            "modify a scan target",
            "filesystem",
            expect(filesystem),
            observe(fs::write(readable.join("sample.txt"), b"tampered")),
        ),
        probe(
            "open a network connection",
            "system-call",
            expect(syscalls),
            network,
        ),
        probe(
            "run another program",
            "system-call",
            expect(syscalls),
            observe(
                std::process::Command::new(std::env::current_exe()?)
                    .arg("--version")
                    .output()
                    .map(drop),
            ),
        ),
    ];
    let result = ProbeResult {
        sandbox: serde_json::to_value(&report)?,
        probes,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(EXIT_OK)
}

// ---- files --------------------------------------------------------------------------------

fn signature_path(cbom: &Path, explicit: Option<&Path>) -> PathBuf {
    explicit.map_or_else(
        || {
            let mut name = cbom
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            name.push(".sig.json");
            cbom.with_file_name(name)
        },
        Path::to_path_buf,
    )
}

fn pretty(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Key and signature files are small; refuse anything that is not, rather than read it whole.
fn read_text(path: &Path) -> Result<String> {
    read_limited(path, 1024 * 1024)
}

/// CBOMs and their signatures grow with the estate: a large one is tens of megabytes. The cap
/// only stops a runaway file from exhausting memory.
fn read_document(path: &Path) -> Result<String> {
    read_limited(path, 1024 * 1024 * 1024)
}

fn read_limited(path: &Path, limit: u64) -> Result<String> {
    let size = fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if size > limit {
        bail!("{} is {size} bytes; expected under {limit}", path.display());
    }
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Writes through a temporary file in the same directory and renames it into place, so readers
/// never see a half-written report.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))?;
    let mut temporary = directory.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id()
    ));
    if temporary.exists() {
        temporary.set_extension("again");
    }
    fs::write(&temporary, bytes).with_context(|| format!("writing {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("moving {} into place", path.display()))
}

/// Creates a private key file readable only by its owner. Never overwrites.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(directory) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(directory)
            .with_context(|| format!("creating {}", directory.display()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}
