//! Confinement of the LATTICE process itself.
//!
//! LATTICE parses hostile input: source trees, binaries, certificates, archives and packet
//! captures from systems it does not trust. The parsers are memory-safe Rust with size and time
//! bounds, but defence in depth assumes a parser bug anyway and limits what a compromised process
//! could do. Once every input the command needs is known, [`apply`] confines the process on Linux
//! with two independent kernel mechanisms:
//!
//! * **Landlock** (filesystem): the scan targets become read-only, the output locations are the
//!   only writable places, and nothing else on the machine can be opened.
//! * **seccomp** (system calls): no new sockets (no network, outbound or inbound, beyond a
//!   listener opened before confinement), no program execution, no ptrace or cross-process
//!   memory access, no mounts, namespaces, kernel modules, BPF or keyrings.
//!
//! Both apply to every thread and are irreversible for the life of the process. Where the kernel
//! or platform lacks a mechanism the [`Report`] says so; in [`Mode::Required`] that is an error.

use serde::Serialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// No confinement.
    Off,
    /// Confine with whatever the kernel supports, and report what that was.
    BestEffort,
    /// Refuse to run unless both the filesystem and the system-call layer are enforced.
    Required,
}

/// What the process may still touch after confinement.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Files and directories that stay readable (the scan targets, the cockpit files).
    pub read: Vec<PathBuf>,
    /// Directories that stay writable (report destinations, the server's data directory).
    pub write: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "kebab-case")]
pub enum Layer {
    Enforced,
    /// Enforced, but the kernel's Landlock ABI lacks some of the rights LATTICE restricts.
    Partial(String),
    Unavailable(String),
    Off,
}

impl Layer {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Enforced | Self::Partial(_))
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Enforced => "enforced".into(),
            Self::Partial(detail) => format!("partially enforced ({detail})"),
            Self::Unavailable(detail) => format!("unavailable ({detail})"),
            Self::Off => "off".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub mode: Mode,
    pub filesystem: Layer,
    pub syscalls: Layer,
}

impl Report {
    pub fn summary(&self) -> String {
        format!(
            "filesystem {}, system calls {}",
            self.filesystem.describe(),
            self.syscalls.describe()
        )
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox required but {layer} confinement is {state}")]
    NotEnforced { layer: &'static str, state: String },
    #[error("sandbox path {path}: {reason}")]
    Path { path: String, reason: String },
    #[error("could not apply the {layer} sandbox: {reason}")]
    Apply { layer: &'static str, reason: String },
}

/// Confines the current process. Call it after every input is open and every output location
/// exists, and before touching untrusted content.
pub fn apply(plan: &Plan, mode: Mode) -> Result<Report, SandboxError> {
    if mode == Mode::Off {
        return Ok(Report {
            mode,
            filesystem: Layer::Off,
            syscalls: Layer::Off,
        });
    }
    let (filesystem, syscalls) = platform::apply(plan)?;
    let report = Report {
        mode,
        filesystem,
        syscalls,
    };
    if mode == Mode::Required {
        for (layer, state) in [
            ("filesystem", &report.filesystem),
            ("system-call", &report.syscalls),
        ] {
            if !state.is_active() {
                return Err(SandboxError::NotEnforced {
                    layer,
                    state: state.describe(),
                });
            }
        }
    }
    Ok(report)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Layer, Plan, SandboxError};
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    /// The newest Landlock ABI LATTICE knows; older kernels get the subset they support.
    const ABI_LATEST: ABI = ABI::V5;

    pub fn apply(plan: &Plan) -> Result<(Layer, Layer), SandboxError> {
        // Landlock first: restricting self also sets no_new_privs, which seccomp requires.
        let filesystem = landlock(plan)?;
        let syscalls = seccomp()?;
        Ok((filesystem, syscalls))
    }

    fn landlock(plan: &Plan) -> Result<Layer, SandboxError> {
        for path in plan.read.iter().chain(&plan.write) {
            if !path.exists() {
                return Err(SandboxError::Path {
                    path: path.display().to_string(),
                    reason: "does not exist".into(),
                });
            }
        }
        let apply = || -> Result<RulesetStatus, landlock::RulesetError> {
            let status = Ruleset::default()
                .set_compatibility(CompatLevel::BestEffort)
                .handle_access(AccessFs::from_all(ABI_LATEST))?
                .create()?
                .no_new_privs(true)
                .add_rules(path_beneath_rules(
                    &plan.read,
                    AccessFs::from_read(ABI_LATEST),
                ))?
                .add_rules(path_beneath_rules(
                    &plan.write,
                    AccessFs::from_all(ABI_LATEST),
                ))?
                .restrict_self()?;
            Ok(status.ruleset)
        };
        match apply() {
            Ok(RulesetStatus::FullyEnforced) => Ok(Layer::Enforced),
            Ok(RulesetStatus::PartiallyEnforced) => Ok(Layer::Partial(
                "the kernel's Landlock ABI predates some restricted rights".into(),
            )),
            Ok(RulesetStatus::NotEnforced) => Ok(Layer::Unavailable(
                "Landlock is not enabled in this kernel".into(),
            )),
            Err(error) => Err(SandboxError::Apply {
                layer: "filesystem",
                reason: error.to_string(),
            }),
        }
    }

    /// System calls a scanner or the server never needs. Denied with EPERM, so a compromised
    /// parser gets an error rather than a capability.
    fn denied() -> Vec<i64> {
        let calls = vec![
            // network: no new sockets of any family (a listener opened before confinement
            // keeps working, since accept does not create a socket through this call)
            libc::SYS_socket,
            // running other programs
            libc::SYS_execve,
            libc::SYS_execveat,
            // other processes
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_getfd,
            // mounts, namespaces and root changes
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            // the kernel itself
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_personality,
        ];
        // port I/O and file-based kexec exist only on x86_64
        #[cfg(target_arch = "x86_64")]
        let calls = [
            calls,
            vec![libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_kexec_file_load],
        ]
        .concat();
        calls
    }

    fn seccomp() -> Result<Layer, SandboxError> {
        let error = |reason: String| SandboxError::Apply {
            layer: "system-call",
            reason,
        };
        let arch =
            TargetArch::try_from(std::env::consts::ARCH).map_err(|e| error(format!("{e:?}")))?;
        let rules: BTreeMap<i64, Vec<SeccompRule>> = denied()
            .into_iter()
            .map(|call| (call, Vec::new()))
            .collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            arch,
        )
        .map_err(|e| error(e.to_string()))?;
        let program: BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| error(e.to_string()))?;
        seccompiler::apply_filter_all_threads(&program).map_err(|e| error(e.to_string()))?;
        Ok(Layer::Enforced)
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{Layer, Plan, SandboxError};

    pub fn apply(_plan: &Plan) -> Result<(Layer, Layer), SandboxError> {
        let reason = format!("not implemented on {}", std::env::consts::OS);
        Ok((
            Layer::Unavailable(reason.clone()),
            Layer::Unavailable(reason),
        ))
    }
}
