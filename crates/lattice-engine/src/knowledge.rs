//! Signed knowledge bundles.
//!
//! The algorithm catalogue, library PQC knowledge, detection rules and risk policy change more
//! often than the code. A bundle carries all four, versioned and numbered, so an air-gapped
//! installation can be updated by carrying one file in:
//!
//! * **Signed.** A detached ML-DSA-65 signature under the context `lattice-knowledge-v1`,
//!   verified against a public key the operator supplies. Nothing inside the bundle is trusted to
//!   vouch for itself.
//! * **Validated whole.** Every file must parse and be internally consistent, and the rules must
//!   compile against the bundle's own catalogue, before anything is activated.
//! * **Monotonic.** Each bundle carries a sequence number. Installation refuses anything not newer
//!   than what is installed, and activation refuses anything not newer than the knowledge compiled
//!   into the binary, so neither an old bundle nor an old binary's data can roll knowledge back.
//! * **Fail closed.** A bundle that is present but does not verify stops the run: scanning with
//!   knowledge nobody vouched for would be worse than scanning with none.
//!
//! Activation happens once, at startup, before any lookup; a process never mixes two catalogues.

use lattice_cbom::signing::{self, BlobSignature, SigningError};
use lattice_core::policy::Policy;
use lattice_core::{KNOWLEDGE_SEQUENCE, Registry};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

pub const FORMAT: &str = "lattice-knowledge/1";
pub const CONTEXT: &str = "lattice-knowledge-v1";
/// The installed bundle and its signature inside a knowledge directory.
pub const INSTALLED: &str = "knowledge.bundle.json";
pub const INSTALLED_SIGNATURE: &str = "knowledge.bundle.json.sig.json";
/// Bundles are small text; anything larger is refused before parsing.
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("{path}: {reason}")]
    Io { path: String, reason: String },
    #[error("not a LATTICE knowledge bundle: {0}")]
    Format(String),
    #[error("bundle file {file} is invalid: {reason}")]
    Invalid { file: &'static str, reason: String },
    #[error("bundle signature: {0}")]
    Signature(#[from] SigningError),
    #[error(
        "bundle #{offered} is not newer than the installed bundle #{installed}; refusing to roll back"
    )]
    Rollback { installed: u64, offered: u64 },
    #[error(
        "bundle #{offered} is not newer than the knowledge compiled into this binary (#{compiled}); refusing to downgrade"
    )]
    Outdated { compiled: u64, offered: u64 },
    #[error("a knowledge bundle is installed in {0} but no trusted key was given to verify it")]
    MissingKey(String),
    #[error("could not activate the bundle: {0}")]
    Activation(String),
}

/// The bundle document: four files as text, with their provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    /// The algorithm catalogue's version.
    pub version: String,
    /// Monotonic across all bundles from the same publisher.
    pub sequence: u64,
    pub created: String,
    pub algorithms: String,
    pub libraries: String,
    pub policy: String,
    pub rules: String,
}

/// A bundle whose files all parse and agree with each other.
pub struct Validated {
    pub bundle: Bundle,
    registry: Registry,
    policy: Policy,
}

/// What an activated or installed bundle is, for reports and status output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleInfo {
    pub version: String,
    pub sequence: u64,
    pub created: String,
    pub key_id: String,
    pub rules_version: String,
    pub policy_version: String,
}

static ACTIVE_BUNDLE: OnceLock<BundleInfo> = OnceLock::new();

/// The bundle activated in this process, if any.
pub fn active_bundle() -> Option<&'static BundleInfo> {
    ACTIVE_BUNDLE.get()
}

fn read(path: &Path) -> Result<Vec<u8>, KnowledgeError> {
    let io = |reason: String| KnowledgeError::Io {
        path: path.display().to_string(),
        reason,
    };
    let size = std::fs::metadata(path)
        .map_err(|e| io(e.to_string()))?
        .len();
    if size > MAX_BUNDLE_BYTES {
        return Err(io(format!(
            "{size} bytes; bundles are under {MAX_BUNDLE_BYTES}"
        )));
    }
    std::fs::read(path).map_err(|e| io(e.to_string()))
}

fn read_text(path: &Path) -> Result<String, KnowledgeError> {
    String::from_utf8(read(path)?).map_err(|_| KnowledgeError::Io {
        path: path.display().to_string(),
        reason: "not UTF-8".into(),
    })
}

/// The detached signature's path for a bundle file.
pub fn signature_path(bundle: &Path) -> PathBuf {
    let mut name = bundle
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sig.json");
    bundle.with_file_name(name)
}

/// Checks every file of a bundle, without activating anything.
pub fn validate(bundle: Bundle) -> Result<Validated, KnowledgeError> {
    if bundle.format != FORMAT {
        return Err(KnowledgeError::Format(format!(
            "format `{}`, expected `{FORMAT}`",
            bundle.format
        )));
    }
    if bundle.sequence == 0 {
        return Err(KnowledgeError::Format("sequence must be positive".into()));
    }
    let invalid =
        |file: &'static str| move |reason: String| KnowledgeError::Invalid { file, reason };
    let registry = Registry::from_toml(&bundle.algorithms)
        .map_err(|e| invalid("algorithms")(e.to_string()))?;
    if registry.version() != bundle.version {
        return Err(invalid("algorithms")(format!(
            "catalogue version {} does not match the bundle version {}",
            registry.version(),
            bundle.version
        )));
    }
    let policy = Policy::from_toml(&bundle.policy).map_err(|e| invalid("policy")(e.to_string()))?;
    lattice_collectors::binary::validate_libraries(&bundle.libraries)
        .map_err(invalid("libraries"))?;
    lattice_collectors::source::rules::RuleSet::from_toml_with(&bundle.rules, &registry)
        .map_err(|e| invalid("rules")(e.to_string()))?;
    Ok(Validated {
        bundle,
        registry,
        policy,
    })
}

/// Builds a bundle from a knowledge directory (`algorithms.toml`, `libraries.toml`,
/// `policy.toml`) and a rules file, validating it. Returns the serialised bundle.
pub fn pack(
    knowledge_dir: &Path,
    rules: &Path,
    sequence: u64,
    timestamp: i64,
) -> Result<(Vec<u8>, Bundle), KnowledgeError> {
    let algorithms = read_text(&knowledge_dir.join("algorithms.toml"))?;
    let version = Registry::from_toml(&algorithms)
        .map_err(|e| KnowledgeError::Invalid {
            file: "algorithms",
            reason: e.to_string(),
        })?
        .version()
        .to_owned();
    let bundle = Bundle {
        format: FORMAT.into(),
        version,
        sequence,
        created: lattice_core::rfc3339(timestamp),
        algorithms,
        libraries: read_text(&knowledge_dir.join("libraries.toml"))?,
        policy: read_text(&knowledge_dir.join("policy.toml"))?,
        rules: read_text(rules)?,
    };
    let validated = validate(bundle)?;
    let mut bytes = serde_json::to_vec_pretty(&validated.bundle).expect("bundles serialise");
    bytes.push(b'\n');
    Ok((bytes, validated.bundle))
}

/// Signs serialised bundle bytes.
pub fn sign(
    bytes: &[u8],
    private_key: &[u8],
    public_key: &[u8],
) -> Result<BlobSignature, KnowledgeError> {
    Ok(signing::sign_blob(bytes, CONTEXT, private_key, public_key)?)
}

/// Verifies a bundle and its detached signature against a trusted key, then validates it.
pub fn verify(
    bytes: &[u8],
    signature: &BlobSignature,
    trusted_key: &[u8],
) -> Result<Validated, KnowledgeError> {
    signing::verify_blob(bytes, signature, CONTEXT, trusted_key)?;
    let bundle: Bundle =
        serde_json::from_slice(bytes).map_err(|e| KnowledgeError::Format(e.to_string()))?;
    validate(bundle)
}

fn load(
    bundle: &Path,
    signature: &Path,
    trusted_key: &[u8],
) -> Result<(Validated, String), KnowledgeError> {
    let bytes = read(bundle)?;
    let signature: BlobSignature = serde_json::from_slice(&read(signature)?)
        .map_err(|e| KnowledgeError::Format(format!("signature file: {e}")))?;
    let key_id = signature.key_id.clone();
    Ok((verify(&bytes, &signature, trusted_key)?, key_id))
}

fn info(validated: &Validated, key_id: String) -> BundleInfo {
    let rules_version = toml::from_str::<toml::Value>(&validated.bundle.rules)
        .ok()
        .and_then(|v| v.get("version").and_then(|v| v.as_str().map(str::to_owned)))
        .unwrap_or_else(|| "unknown".into());
    BundleInfo {
        version: validated.bundle.version.clone(),
        sequence: validated.bundle.sequence,
        created: validated.bundle.created.clone(),
        key_id,
        rules_version,
        policy_version: validated.policy.version.clone(),
    }
}

/// The installed bundle's sequence, read without verification (for rollback checks only).
fn installed_sequence(dir: &Path) -> Option<u64> {
    let bytes = read(&dir.join(INSTALLED)).ok()?;
    serde_json::from_slice::<Bundle>(&bytes)
        .ok()
        .map(|b| b.sequence)
}

/// Verifies a bundle and installs it into `dir`, refusing anything not newer than what is
/// installed or compiled in.
pub fn install(
    bundle: &Path,
    signature: &Path,
    trusted_key: &[u8],
    dir: &Path,
) -> Result<BundleInfo, KnowledgeError> {
    let (validated, key_id) = load(bundle, signature, trusted_key)?;
    let offered = validated.bundle.sequence;
    if offered <= KNOWLEDGE_SEQUENCE {
        return Err(KnowledgeError::Outdated {
            compiled: KNOWLEDGE_SEQUENCE,
            offered,
        });
    }
    if let Some(installed) = installed_sequence(dir)
        && offered <= installed
    {
        return Err(KnowledgeError::Rollback { installed, offered });
    }
    let io = |path: &Path, e: std::io::Error| KnowledgeError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    };
    std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    // signature first, bundle last: a reader never sees a new bundle with an old signature
    for (source, name) in [(signature, INSTALLED_SIGNATURE), (bundle, INSTALLED)] {
        let target = dir.join(name);
        let temporary = dir.join(format!(".{name}.tmp"));
        std::fs::copy(source, &temporary).map_err(|e| io(&temporary, e))?;
        std::fs::rename(&temporary, &target).map_err(|e| io(&target, e))?;
    }
    Ok(info(&validated, key_id))
}

/// Activates the bundle installed in `dir`, if there is one. Must run before anything consults
/// the catalogue, the rules, the library knowledge or the default policy.
pub fn activate(
    dir: &Path,
    trusted_key: Option<&[u8]>,
) -> Result<Option<&'static BundleInfo>, KnowledgeError> {
    let bundle = dir.join(INSTALLED);
    if !bundle.exists() {
        return Ok(None);
    }
    let trusted_key =
        trusted_key.ok_or_else(|| KnowledgeError::MissingKey(dir.display().to_string()))?;
    let (validated, key_id) = load(&bundle, &dir.join(INSTALLED_SIGNATURE), trusted_key)?;
    let offered = validated.bundle.sequence;
    if offered <= KNOWLEDGE_SEQUENCE {
        return Err(KnowledgeError::Outdated {
            compiled: KNOWLEDGE_SEQUENCE,
            offered,
        });
    }
    let bundle_info = info(&validated, key_id);
    let Validated {
        bundle,
        registry,
        policy,
    } = validated;
    let activation = |e: String| KnowledgeError::Activation(e);
    // the catalogue first: the rules compile against it
    Registry::activate(registry).map_err(|e| activation(e.to_string()))?;
    Policy::activate(policy).map_err(|e| activation(e.to_string()))?;
    lattice_collectors::binary::activate_libraries(&bundle.libraries).map_err(activation)?;
    lattice_collectors::source::rules::activate(bundle.rules)
        .map_err(|e| activation(e.to_string()))?;
    Ok(Some(ACTIVE_BUNDLE.get_or_init(|| bundle_info)))
}

/// The bundle installed in `dir`, verified when a trusted key is given.
pub fn status(
    dir: &Path,
    trusted_key: Option<&[u8]>,
) -> Result<Option<(BundleInfo, bool)>, KnowledgeError> {
    let bundle = dir.join(INSTALLED);
    if !bundle.exists() {
        return Ok(None);
    }
    match trusted_key {
        Some(key) => {
            let (validated, key_id) = load(&bundle, &dir.join(INSTALLED_SIGNATURE), key)?;
            Ok(Some((info(&validated, key_id), true)))
        }
        None => {
            let parsed: Bundle = serde_json::from_slice(&read(&bundle)?)
                .map_err(|e| KnowledgeError::Format(e.to_string()))?;
            let key_id =
                serde_json::from_slice::<BlobSignature>(&read(&dir.join(INSTALLED_SIGNATURE))?)
                    .map(|s| s.key_id)
                    .unwrap_or_default();
            let validated = validate(parsed)?;
            Ok(Some((info(&validated, key_id), false)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn packed(sequence: u64) -> (Vec<u8>, Bundle) {
        pack(
            &repository().join("knowledge"),
            &repository().join("rules/source.toml"),
            sequence,
            1_790_121_600,
        )
        .unwrap()
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn packing_validates_and_records_the_catalogue_version() {
        let (bytes, bundle) = packed(2);
        assert_eq!(bundle.format, FORMAT);
        assert_eq!(bundle.version, Registry::compiled().version());
        assert_eq!(bundle.created, "2026-09-23T00:00:00Z");
        let reparsed: Bundle = serde_json::from_slice(&bytes).unwrap();
        assert!(validate(reparsed).is_ok());
    }

    #[test]
    fn invalid_contents_are_rejected_by_file() {
        let (_, bundle) = packed(2);
        let broken = |change: fn(&mut Bundle)| {
            let mut b = bundle.clone();
            change(&mut b);
            validate(b).err().unwrap()
        };
        assert!(matches!(
            broken(|b| b.policy = b
                .policy
                .replace("provider_interface = 40", "provider_interface = 41")),
            KnowledgeError::Invalid { file: "policy", .. }
        ));
        assert!(matches!(
            broken(|b| b.libraries.push_str(
                "\n[[library]]\nname = \"x\"\npattern = '('\npqc_since = \"any\"\nbasis = \"b\"\n"
            )),
            KnowledgeError::Invalid {
                file: "libraries",
                ..
            }
        ));
        assert!(matches!(
            broken(|b| b.algorithms = "not toml [".into()),
            KnowledgeError::Invalid {
                file: "algorithms",
                ..
            }
        ));
        assert!(matches!(
            broken(|b| b.version = "1999.01.1".into()),
            KnowledgeError::Invalid {
                file: "algorithms",
                ..
            }
        ));
        assert!(matches!(
            broken(|b| b.sequence = 0),
            KnowledgeError::Format(_)
        ));
        assert!(matches!(
            broken(|b| b.format = "other/1".into()),
            KnowledgeError::Format(_)
        ));
    }

    #[test]
    fn installation_verifies_and_refuses_rollback() {
        let keys = signing::generate_keypair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("installed");
        let publish = |sequence: u64| {
            let (bytes, _) = packed(sequence);
            let signature = sign(&bytes, &keys.private_key, &keys.public_key).unwrap();
            let bundle = write(dir.path(), &format!("k{sequence}.bundle.json"), &bytes);
            write(
                dir.path(),
                &format!("k{sequence}.bundle.json.sig.json"),
                &serde_json::to_vec(&signature).unwrap(),
            );
            bundle
        };

        let third = publish(3);
        let info = install(
            &third,
            &signature_path(&third),
            &keys.public_key,
            &installed,
        )
        .unwrap();
        assert_eq!(
            (info.sequence, info.key_id.clone()),
            (3, signing::key_id(&keys.public_key))
        );
        let (installed_info, verified) =
            status(&installed, Some(&keys.public_key)).unwrap().unwrap();
        assert!(verified);
        assert_eq!(installed_info.sequence, 3);

        let second = publish(2);
        assert!(matches!(
            install(
                &second,
                &signature_path(&second),
                &keys.public_key,
                &installed
            ),
            Err(KnowledgeError::Rollback {
                installed: 3,
                offered: 2
            })
        ));
        let replay = publish(3);
        assert!(matches!(
            install(
                &replay,
                &signature_path(&replay),
                &keys.public_key,
                &installed
            ),
            Err(KnowledgeError::Rollback { .. })
        ));
        let compiled = publish(KNOWLEDGE_SEQUENCE);
        assert!(matches!(
            install(
                &compiled,
                &signature_path(&compiled),
                &keys.public_key,
                &installed
            ),
            Err(KnowledgeError::Outdated { .. })
        ));

        // a tampered bundle never installs
        let tampered = publish(4);
        let text = std::fs::read_to_string(&tampered)
            .unwrap()
            .replace("provider_interface = 40", "provider_interface = 30");
        std::fs::write(&tampered, text).unwrap();
        assert!(matches!(
            install(
                &tampered,
                &signature_path(&tampered),
                &keys.public_key,
                &installed
            ),
            Err(KnowledgeError::Signature(SigningError::ContentAltered))
        ));
        // nor one signed by another key
        let other = signing::generate_keypair().unwrap();
        let fifth = publish(5);
        assert!(matches!(
            install(
                &fifth,
                &signature_path(&fifth),
                &other.public_key,
                &installed
            ),
            Err(KnowledgeError::Signature(SigningError::WrongKey { .. }))
        ));
        // status can describe it unverified, but activating it without a trusted key is an
        // error, never a silent fallback to compiled-in knowledge
        assert!(matches!(status(&installed, None), Ok(Some((_, false)))));
        assert!(matches!(
            activate(&installed, None),
            Err(KnowledgeError::MissingKey(_))
        ));
    }
}
