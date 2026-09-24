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
//!
//! On Windows, an unprivileged process cannot confine its own filesystem or network access
//! (that takes an AppContainer relaunch or administrator rights), but it can apply process
//! mitigation policies: no child processes, no dynamically generated code, no images from remote
//! shares or low-integrity files, no legacy extension points. Those are applied and reported as a
//! partial system-call layer; the filesystem layer is reported unavailable, so `required`
//! refuses to run there.
//!
//! Landlock attaches rules to inodes, and some filesystems do not keep inodes stable across
//! lookups: on 9p (the filesystem WSL uses for Windows drives) a confined process is denied even
//! the paths it was granted. Such paths are detected before confinement and Landlock is skipped,
//! with the reason reported. After confinement every readable root is checked, so a filesystem
//! that misbehaves in a way not detected up front fails loudly instead of yielding an empty scan.

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
    /// Capabilities the enforced layers take away, one by one, so a partial layer is exact.
    pub denies: Denied,
}

/// What confinement has taken away from the process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Denied {
    /// New sockets: no connection can be opened.
    pub network: bool,
    /// Running other programs.
    pub execution: bool,
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
            denies: Denied::default(),
        });
    }
    let (filesystem, syscalls, denies) = platform::apply(plan)?;
    let report = Report {
        mode,
        filesystem,
        syscalls,
        denies,
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
    use super::{Denied, Layer, Plan, SandboxError};
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    use std::path::Path;

    /// The newest Landlock ABI LATTICE knows; older kernels get the subset they support.
    const ABI_LATEST: ABI = ABI::V5;

    /// `statfs` magic of 9p (v9fs), where Landlock path rules do not hold.
    const V9FS_MAGIC: i64 = 0x0102_1997;

    pub fn apply(plan: &Plan) -> Result<(Layer, Layer, Denied), SandboxError> {
        let filesystem = landlock(plan)?;
        let syscalls = seccomp()?;
        if filesystem.is_active() {
            check_readable(plan)?;
        }
        let denies = Denied {
            network: syscalls.is_active(),
            execution: syscalls.is_active(),
        };
        Ok((filesystem, syscalls, denies))
    }

    /// A filesystem Landlock cannot confine correctly, if `path` is on one.
    fn unsupported_filesystem(path: &Path) -> Option<&'static str> {
        let kind = rustix::fs::statfs(path).ok()?.f_type;
        #[allow(clippy::unnecessary_cast)] // f_type's width varies by architecture
        (kind as i64 == V9FS_MAGIC).then_some("9p")
    }

    /// Every readable root must still be readable once confined.
    fn check_readable(plan: &Plan) -> Result<(), SandboxError> {
        for path in &plan.read {
            let readable = if path.is_dir() {
                std::fs::read_dir(path).map(|_| ())
            } else {
                std::fs::File::open(path).map(|_| ())
            };
            if let Err(error) = readable {
                return Err(SandboxError::Apply {
                    layer: "filesystem",
                    reason: format!(
                        "Landlock denies {} on this filesystem ({}); move it to a local \
                         filesystem or run with --sandbox off",
                        path.display(),
                        error.kind()
                    ),
                });
            }
        }
        Ok(())
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
        if let Some((path, kind)) = plan
            .read
            .iter()
            .chain(&plan.write)
            .find_map(|path| unsupported_filesystem(path).map(|kind| (path, kind)))
        {
            return Ok(Layer::Unavailable(format!(
                "{} is on {kind}, which Landlock cannot confine",
                path.display()
            )));
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
        // seccomp needs no_new_privs; Landlock sets it too, but may have been skipped
        rustix::thread::set_no_new_privs(true)
            .map_err(|e| error(format!("could not set no_new_privs: {e}")))?;
        seccompiler::apply_filter_all_threads(&program).map_err(|e| error(e.to_string()))?;
        Ok(Layer::Enforced)
    }
}

/// Process mitigation policies. The only unsafe code in LATTICE: four calls of one documented
/// Win32 function, each passing a single DWORD of flags.
#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use super::{Denied, Layer, Plan, SandboxError};
    use std::ffi::c_void;

    // PROCESS_MITIGATION_POLICY values (winnt.h)
    const DYNAMIC_CODE: i32 = 2;
    const EXTENSION_POINT_DISABLE: i32 = 6;
    const IMAGE_LOAD: i32 = 10;
    const CHILD_PROCESS: i32 = 13;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetProcessMitigationPolicy(policy: i32, buffer: *const c_void, length: usize) -> i32;
    }

    /// Applies one policy whose structure is a single DWORD of flags.
    fn set(policy: i32, flags: u32) -> bool {
        // SAFETY: each policy used here is a one-DWORD structure (PROCESS_MITIGATION_*_POLICY),
        // and `flags` is a valid, aligned u32 for the duration of the call.
        unsafe {
            SetProcessMitigationPolicy(
                policy,
                (&raw const flags).cast::<c_void>(),
                std::mem::size_of::<u32>(),
            ) != 0
        }
    }

    pub fn apply(_plan: &Plan) -> Result<(Layer, Layer, Denied), SandboxError> {
        // NoChildProcessCreation; ProhibitDynamicCode; NoRemoteImages | NoLowMandatoryLabelImages;
        // DisableExtensionPoints
        let children = set(CHILD_PROCESS, 0b1);
        let applied = [
            (children, "no child processes"),
            (set(DYNAMIC_CODE, 0b1), "no dynamic code"),
            (set(IMAGE_LOAD, 0b11), "no remote or low-integrity images"),
            (
                set(EXTENSION_POINT_DISABLE, 0b1),
                "no legacy extension points",
            ),
        ];
        let names: Vec<&str> = applied
            .iter()
            .filter(|(ok, _)| *ok)
            .map(|(_, name)| *name)
            .collect();
        let syscalls = if names.is_empty() {
            Layer::Unavailable("process mitigation policies were refused".into())
        } else {
            Layer::Partial(format!(
                "Windows process mitigations: {}; the network is not restricted",
                names.join(", ")
            ))
        };
        Ok((
            Layer::Unavailable(
                "Windows offers no unprivileged filesystem confinement of a running process".into(),
            ),
            syscalls,
            Denied {
                network: false,
                execution: children,
            },
        ))
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::{Denied, Layer, Plan, SandboxError};

    pub fn apply(_plan: &Plan) -> Result<(Layer, Layer, Denied), SandboxError> {
        let reason = format!("not implemented on {}", std::env::consts::OS);
        Ok((
            Layer::Unavailable(reason.clone()),
            Layer::Unavailable(reason),
            Denied::default(),
        ))
    }
}
