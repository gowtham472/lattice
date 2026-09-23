use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use lattice_cbom::signing::{self, SigningError};
use lattice_cbom::{build_bom, to_pretty_json, AssetContext, AssessedAsset, Bom, CryptoComponent};
use lattice_classify::DataClassifier;
use lattice_collectors::{
    BinaryCollector, Collector, CollectionFailure, ConfigCollector, ScanOptions, SourceCollector,
};
use lattice_core::{normalize, CryptoAsset};
use lattice_graph::CryptoGraph;
use lattice_risk::{assess, AgilityFactors, Exposure, RiskContext};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// `lattice ci` exit codes, matching the documented pipeline contract: 0 clean, 1 policy
/// regression, 2 scan error, 3 verification failure.
const EXIT_CLEAN: u8 = 0;
const EXIT_POLICY_REGRESSION: u8 = 1;
const EXIT_SCAN_ERROR: u8 = 2;
const EXIT_VERIFICATION_FAILURE: u8 = 3;

#[derive(Debug, Parser)]
#[command(name = "lattice", version, about = "Air-gapped cryptographic discovery and quantum-risk analysis")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan source code, native binaries, and configuration, then emit a deterministic CBOM.
    Scan(ScanArgs),
    /// Re-scan a target and fail with a distinct exit code if it regresses against a baseline CBOM.
    Ci(CiArgs),
    /// Generate an offline ML-DSA-65 keypair for signing CBOM reports.
    Keygen(KeygenArgs),
    /// Hash-chain and sign an existing CBOM report in place.
    Sign(SignArgs),
    /// Verify a CBOM report's hash chain and ML-DSA-65 signature against a trusted public key.
    Verify(VerifyArgs),
}

#[derive(Debug, clap::Args, Clone)]
struct ScanPolicyArgs {
    /// Fallback secrecy lifetime when no specific data-classification rule matches.
    #[arg(long, default_value_t = 5.0)]
    data_lifetime_years: f64,

    /// External exposure applied until graph-derived exposure is available.
    #[arg(long, value_enum, default_value_t = ExposureArg::Internal)]
    exposure: ExposureArg,

    /// Earliest policy-selected year for a cryptographically relevant quantum computer.
    #[arg(long, default_value_t = 2035)]
    q_day_year: u16,

    /// Fixed assessment year, explicit to keep results reproducible.
    #[arg(long, default_value_t = 2026)]
    assessment_year: u16,

    /// Per-file byte limit protecting the scanner from resource exhaustion.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_file_bytes: u64,
}

#[derive(Debug, clap::Args)]
struct ScanArgs {
    /// File or directory to scan. The target is only read, never modified.
    target: PathBuf,

    /// CBOM destination, or '-' to write JSON to stdout.
    #[arg(short, long, default_value = "lattice.cbom.json")]
    output: PathBuf,

    #[command(flatten)]
    policy: ScanPolicyArgs,

    /// Sign the resulting CBOM with this ML-DSA-65 private key file (hex-encoded).
    #[arg(long, requires = "public_key")]
    sign_with: Option<PathBuf>,

    /// Public key file (hex-encoded) recorded alongside the signature; required with --sign-with.
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// Suppress the human-readable scan summary.
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, clap::Args)]
struct CiArgs {
    /// File or directory to scan. The target is only read, never modified.
    target: PathBuf,

    /// Previously captured CBOM to compare against.
    #[arg(long)]
    baseline: PathBuf,

    /// Reject the baseline unless it carries a valid signature from this trusted public key file.
    #[arg(long)]
    trusted_public_key: Option<PathBuf>,

    /// Write the current scan's CBOM to this path in addition to running the gate.
    #[arg(long)]
    output: Option<PathBuf>,

    #[command(flatten)]
    policy: ScanPolicyArgs,
}

#[derive(Debug, clap::Args)]
struct KeygenArgs {
    /// Directory to write lattice.ml-dsa65.pub and lattice.ml-dsa65.key into.
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
struct SignArgs {
    /// CBOM report to sign in place.
    report: PathBuf,

    /// ML-DSA-65 private key file (hex-encoded), from `lattice keygen`.
    #[arg(long)]
    private_key: PathBuf,

    /// ML-DSA-65 public key file (hex-encoded), recorded alongside the signature.
    #[arg(long)]
    public_key: PathBuf,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// CBOM report to verify.
    report: PathBuf,

    /// Trusted ML-DSA-65 public key file (hex-encoded). Never trust a key embedded in the report.
    #[arg(long)]
    public_key: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExposureArg {
    Internet,
    Partner,
    Internal,
    DeadCode,
}

impl From<ExposureArg> for Exposure {
    fn from(value: ExposureArg) -> Self {
        match value {
            ExposureArg::Internet => Self::Internet,
            ExposureArg::Partner => Self::Partner,
            ExposureArg::Internal => Self::Internal,
            ExposureArg::DeadCode => Self::DeadCode,
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(io::stderr)
        .init();

    let result = match Cli::parse().command {
        Command::Scan(args) => scan(args).map(|()| ExitCode::SUCCESS),
        Command::Ci(args) => ci(args),
        Command::Keygen(args) => keygen(args).map(|()| ExitCode::SUCCESS),
        Command::Sign(args) => sign_cmd(args).map(|()| ExitCode::SUCCESS),
        Command::Verify(args) => verify_cmd(args),
    };

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

struct ScanSummary {
    source_files_scanned: u64,
    binary_files_scanned: u64,
    config_files_scanned: u64,
    failures: Vec<CollectionFailure>,
}

fn run_scan(target: &Path, policy: &ScanPolicyArgs) -> Result<(Bom, ScanSummary)> {
    validate_policy_args(policy)?;
    let source_collector =
        SourceCollector::from_embedded_rules().context("failed to initialize source collector")?;
    let scan_options = ScanOptions { max_file_bytes: policy.max_file_bytes };
    info!(target = %target.display(), "starting offline scan");
    let mut result = source_collector
        .collect(target, &scan_options)
        .context("source collection failed")?;
    let source_files_scanned = result.files_scanned;

    let binary_result = BinaryCollector
        .collect(target, &scan_options)
        .context("binary collection failed")?;
    let binary_files_scanned = binary_result.files_scanned;
    result.observations.extend(binary_result.observations);
    result.failures.extend(binary_result.failures);

    let config_result = ConfigCollector::new()
        .context("failed to initialize configuration collector")?
        .collect(target, &scan_options)
        .context("configuration collection failed")?;
    let config_files_scanned = config_result.files_scanned;
    result.observations.extend(config_result.observations);
    result.failures.extend(config_result.failures);

    let assets = normalize(result.observations);
    let classifier =
        DataClassifier::from_embedded_policy().context("failed to initialize data classifier")?;
    let mut classifications = assets
        .iter()
        .map(|asset| (asset.id.clone(), classifier.classify(asset, Some(policy.data_lifetime_years))))
        .collect::<BTreeMap<_, _>>();
    let exposure: Exposure = policy.exposure.into();
    let graph = CryptoGraph::build(&assets, &classifications, exposure.weight());

    let assessed = assets
        .into_iter()
        .map(|asset| {
            let graph_context = graph
                .asset_context(&asset.id)
                .expect("every normalized asset is represented in the graph");
            let classification = classifications
                .remove(&asset.id)
                .expect("every normalized asset is classified");
            let context = RiskContext {
                data_secrecy_lifetime_years: graph_context.secrecy_lifetime_years,
                exposure,
                assessment_year: policy.assessment_year,
                q_day_year: policy.q_day_year,
                agility: infer_agility(&asset),
            };
            let risk = assess(&asset, context);
            AssessedAsset {
                asset,
                risk,
                context: AssetContext {
                    protected_data_ids: graph_context.protected_data_ids,
                    classifications: graph_context.classifications,
                    business_criticality: graph_context.business_criticality,
                    reachable_from: graph_context.reachable_from,
                    classifier_rule: classification.rule_id,
                    classifier_confidence: classification.confidence,
                    classifier_explanation: classification.explanation,
                },
            }
        })
        .collect::<Vec<_>>();

    let bom = build_bom(assessed);
    Ok((
        bom,
        ScanSummary {
            source_files_scanned,
            binary_files_scanned,
            config_files_scanned,
            failures: result.failures,
        },
    ))
}

fn scan(args: ScanArgs) -> Result<()> {
    let (mut bom, summary) = run_scan(&args.target, &args.policy)?;
    let asset_count = bom.components.len();
    let urgent_count = bom.components.iter().filter(|item| item.lattice.mosca_urgent).count();
    let broken_count = bom.components.iter().filter(|item| item.lattice.broken_now).count();

    if let Some(private_key_path) = &args.sign_with {
        let public_key_path = args
            .public_key
            .as_ref()
            .expect("clap enforces --public-key alongside --sign-with");
        let private_key = read_hex_file(private_key_path)?;
        let public_key = read_hex_file(public_key_path)?;
        signing::sign_bom(&mut bom, &private_key, &public_key)
            .map_err(|error| anyhow!("failed to sign CBOM: {error}"))?;
    }

    let json = to_pretty_json(&bom).context("failed to serialize CBOM")?;
    if args.output.as_os_str() == "-" {
        io::stdout().write_all(json.as_bytes()).context("failed to write CBOM to stdout")?;
    } else {
        write_report(&args.output, json.as_bytes())?;
    }

    if !args.quiet {
        eprintln!(
            "LATTICE scan complete: {} source files, {} binaries, and {} configs scanned; {} assets, {} Mosca-urgent, {} broken today, {} recoverable file errors",
            summary.source_files_scanned,
            summary.binary_files_scanned,
            summary.config_files_scanned,
            asset_count,
            urgent_count,
            broken_count,
            summary.failures.len(),
        );
        print_failures(&summary.failures);
    }
    Ok(())
}

fn ci(args: CiArgs) -> Result<ExitCode> {
    let (current_bom, summary) = match run_scan(&args.target, &args.policy) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("scan error: {error:?}");
            return Ok(ExitCode::from(EXIT_SCAN_ERROR));
        }
    };

    let baseline_bytes = match fs::read_to_string(&args.baseline) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("scan error: failed to read baseline {}: {error}", args.baseline.display());
            return Ok(ExitCode::from(EXIT_SCAN_ERROR));
        }
    };
    let baseline_bom: Bom = match serde_json::from_str(&baseline_bytes) {
        Ok(bom) => bom,
        Err(error) => {
            eprintln!("scan error: baseline {} is not a valid CBOM: {error}", args.baseline.display());
            return Ok(ExitCode::from(EXIT_SCAN_ERROR));
        }
    };

    if let Some(trusted_key_path) = &args.trusted_public_key {
        let trusted_key = read_hex_file(trusted_key_path)?;
        if let Err(error) = signing::verify_bom(&baseline_bom, &trusted_key) {
            eprintln!("verification failure: baseline signature is not valid: {error}");
            return Ok(ExitCode::from(EXIT_VERIFICATION_FAILURE));
        }
        eprintln!("baseline signature verified against {}", trusted_key_path.display());
    }

    if let Some(output_path) = &args.output {
        let json = to_pretty_json(&current_bom).context("failed to serialize CBOM")?;
        write_report(output_path, json.as_bytes())?;
    }

    let regressions = find_regressions(&baseline_bom.components, &current_bom.components);
    print_failures(&summary.failures);

    if regressions.is_empty() {
        eprintln!(
            "lattice ci: clean. {} assets compared against baseline {}.",
            current_bom.components.len(),
            args.baseline.display()
        );
        Ok(ExitCode::from(EXIT_CLEAN))
    } else {
        eprintln!("lattice ci: {} policy regression(s) found:", regressions.len());
        for regression in &regressions {
            eprintln!(
                "  NEW {} ({}, primitive {}): quantumBreakability={:.2} brokenNow={} evidenceGrade={:?} at {}",
                regression.bom_ref,
                regression.name,
                regression.primitive,
                regression.quantum_breakability,
                regression.broken_now,
                regression.evidence_grade,
                regression.first_location,
            );
        }
        Ok(ExitCode::from(EXIT_POLICY_REGRESSION))
    }
}

struct Regression {
    bom_ref: String,
    name: String,
    primitive: String,
    quantum_breakability: f64,
    broken_now: bool,
    evidence_grade: lattice_core::EvidenceGrade,
    first_location: String,
}

/// A regression is newly observed cryptography, absent from the baseline, that is already
/// broken today or breakable by a sufficiently capable quantum adversary (QB >= 0.5).
fn find_regressions(baseline: &[CryptoComponent], current: &[CryptoComponent]) -> Vec<Regression> {
    let baseline_refs: BTreeSet<&str> = baseline.iter().map(|item| item.bom_ref.as_str()).collect();
    let mut regressions = current
        .iter()
        .filter(|item| !baseline_refs.contains(item.bom_ref.as_str()))
        .filter(|item| item.lattice.broken_now || item.lattice.quantum_breakability >= 0.5)
        .map(|item| Regression {
            bom_ref: item.bom_ref.clone(),
            name: item.name.clone(),
            primitive: item.crypto_properties.algorithm_properties.primitive.clone(),
            quantum_breakability: item.lattice.quantum_breakability,
            broken_now: item.lattice.broken_now,
            evidence_grade: item.lattice.evidence_grade,
            first_location: item
                .evidence
                .occurrences
                .first()
                .map_or_else(|| "unknown".to_owned(), |occurrence| occurrence.location.clone()),
        })
        .collect::<Vec<_>>();
    regressions.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));
    regressions
}

fn keygen(args: KeygenArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("failed to create {}", args.output_dir.display()))?;
    let (public_key, private_key) =
        signing::generate_keypair().map_err(|error| anyhow!("key generation failed: {error}"))?;

    let public_path = args.output_dir.join("lattice.ml-dsa65.pub");
    let private_path = args.output_dir.join("lattice.ml-dsa65.key");
    fs::write(&public_path, hex::encode(public_key))
        .with_context(|| format!("failed to write {}", public_path.display()))?;
    fs::write(&private_path, hex::encode(private_key))
        .with_context(|| format!("failed to write {}", private_path.display()))?;

    eprintln!("Generated ML-DSA-65 keypair:");
    eprintln!("  public key:  {}", public_path.display());
    eprintln!("  private key: {} (keep this offline and access-controlled)", private_path.display());
    Ok(())
}

fn sign_cmd(args: SignArgs) -> Result<()> {
    let contents = fs::read_to_string(&args.report)
        .with_context(|| format!("failed to read {}", args.report.display()))?;
    let mut bom: Bom = serde_json::from_str(&contents)
        .with_context(|| format!("{} is not a valid CBOM", args.report.display()))?;

    let private_key = read_hex_file(&args.private_key)?;
    let public_key = read_hex_file(&args.public_key)?;
    signing::sign_bom(&mut bom, &private_key, &public_key)
        .map_err(|error| anyhow!("failed to sign CBOM: {error}"))?;

    let json = to_pretty_json(&bom).context("failed to serialize signed CBOM")?;
    write_report(&args.report, json.as_bytes())?;
    eprintln!("Signed {} with ML-DSA-65.", args.report.display());
    Ok(())
}

fn verify_cmd(args: VerifyArgs) -> Result<ExitCode> {
    let contents = fs::read_to_string(&args.report)
        .with_context(|| format!("failed to read {}", args.report.display()))?;
    let bom: Bom = serde_json::from_str(&contents)
        .with_context(|| format!("{} is not a valid CBOM", args.report.display()))?;
    let trusted_key = read_hex_file(&args.public_key)?;

    match signing::verify_bom(&bom, &trusted_key) {
        Ok(()) => {
            eprintln!("OK: {} verifies against {}.", args.report.display(), args.public_key.display());
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            eprintln!("FAILED: {} does not verify: {error}", args.report.display());
            let code = match error {
                SigningError::MissingSignature
                | SigningError::ChainBroken(_)
                | SigningError::SignatureInvalid
                | SigningError::MalformedSignatureEncoding => EXIT_VERIFICATION_FAILURE,
                _ => EXIT_SCAN_ERROR,
            };
            Ok(ExitCode::from(code))
        }
    }
}

fn validate_policy_args(policy: &ScanPolicyArgs) -> Result<()> {
    if policy.data_lifetime_years < 0.0 || !policy.data_lifetime_years.is_finite() {
        bail!("--data-lifetime-years must be a finite, non-negative number");
    }
    if policy.q_day_year < policy.assessment_year {
        bail!("--q-day-year cannot be earlier than --assessment-year");
    }
    if policy.max_file_bytes == 0 {
        bail!("--max-file-bytes must be greater than zero");
    }
    Ok(())
}

fn infer_agility(asset: &CryptoAsset) -> AgilityFactors {
    let tokens = asset
        .evidence
        .iter()
        .map(|evidence| evidence.matched_token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let provider_interface = tokens.iter().any(|token| {
        token.contains("evp_")
            || token.contains("getinstance")
            || token.contains("aesgcm")
            || token.contains("chacha20poly1305")
    });
    let negotiation_layer = tokens.iter().any(|token| token.contains("tls") || token.contains("ssl"));
    let dependency_pqc_ready = matches!(
        asset.algorithm.family.to_ascii_uppercase().as_str(),
        "ML-KEM" | "ML-DSA" | "SLH-DSA"
    );
    AgilityFactors {
        provider_interface,
        config_driven: false,
        negotiation_layer,
        centralized: asset.locations.len() == 1,
        dependency_pqc_ready,
    }
}

fn print_failures(failures: &[CollectionFailure]) {
    if failures.is_empty() {
        return;
    }
    eprintln!("Partial-result warnings:");
    for failure in failures.iter().take(10) {
        eprintln!("  {}: {}", failure.path, failure.reason);
    }
    if failures.len() > 10 {
        eprintln!("  ... and {} more", failures.len() - 10);
    }
}

fn read_hex_file(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    hex::decode(contents.trim())
        .with_context(|| format!("{} does not contain valid hex-encoded key material", path.display()))
}

fn write_report(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .with_context(|| format!("failed to write temporary report {}", temporary.display()))?;
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace existing report {}", path.display()))?;
    }
    fs::rename(&temporary, path)
        .with_context(|| format!("failed to finalize report {}", path.display()))?;
    Ok(())
}
