//! The privileged part: uprobes through tracefs, in a private trace instance.

use crate::{Aggregator, Options, Probe, TraceError, definition, parse};
use lattice_collectors::trace::Trace;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Per-CPU buffer for the private instance, in KiB.
const BUFFER_KIB: &str = "8192";

fn tracefs_root() -> Result<PathBuf, TraceError> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"].map(PathBuf::from) {
        match fs::metadata(root.join("uprobe_events")) {
            Ok(_) => return Ok(root),
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                return Err(TraceError::Privilege(format!(
                    "{}: {error}",
                    root.display()
                )));
            }
            Err(_) => {}
        }
    }
    Err(TraceError::Tracefs(
        "tracefs with uprobe support is not mounted (mount -t tracefs nodev /sys/kernel/tracing)"
            .into(),
    ))
}

fn write(path: &Path, content: &str) -> Result<(), TraceError> {
    fs::write(path, content).map_err(|e| describe(path, e))
}

fn describe(path: &Path, error: std::io::Error) -> TraceError {
    if error.kind() == ErrorKind::PermissionDenied {
        TraceError::Privilege(format!("{}: {error}", path.display()))
    } else {
        TraceError::Tracefs(format!("{}: {error}", path.display()))
    }
}

/// Everything this recording created, removed again when dropped: on success, on error and when
/// the recording is interrupted.
struct Session {
    root: PathBuf,
    group: String,
    instance: PathBuf,
    instance_created: bool,
    defined: Vec<String>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.instance_created {
            let _ = fs::write(
                self.instance
                    .join("events")
                    .join(&self.group)
                    .join("enable"),
                "0",
            );
            let _ = fs::remove_dir(&self.instance);
        }
        if let Ok(mut events) = OpenOptions::new()
            .append(true)
            .open(self.root.join("uprobe_events"))
        {
            for event in &self.defined {
                let _ = events.write_all(format!("-:{}/{event}\n", self.group).as_bytes());
            }
        }
    }
}

fn executable(pid: u32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let text = path.display().to_string();
    Some(text.trim_end_matches(" (deleted)").to_owned())
}

pub(crate) fn record(
    options: &Options,
    probes: Vec<Probe>,
    stop: &(dyn Fn() -> bool + Sync),
) -> Result<(Trace, u64), TraceError> {
    if probes.is_empty() {
        return Err(TraceError::NoLibrary);
    }

    let root = tracefs_root()?;
    let group = format!("lattice_{}", std::process::id());
    let mut session = Session {
        instance: root.join("instances").join(&group),
        root: root.clone(),
        group: group.clone(),
        instance_created: false,
        defined: Vec::new(),
    };

    // define every probe; one the kernel rejects is skipped, not fatal
    let uprobe_events = root.join("uprobe_events");
    let mut events = OpenOptions::new()
        .append(true)
        .open(&uprobe_events)
        .map_err(|e| describe(&uprobe_events, e))?;
    let mut rejected = 0u64;
    for (index, probe) in probes.iter().enumerate() {
        let name = format!("p{index}");
        let line = definition(&group, &name, probe)?;
        match events.write_all(format!("{line}\n").as_bytes()) {
            Ok(()) => session.defined.push(name),
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                return Err(describe(&uprobe_events, error));
            }
            Err(error) => {
                tracing::debug!(%line, %error, "uprobe rejected");
                rejected += 1;
            }
        }
    }
    drop(events);
    if session.defined.is_empty() {
        return Err(TraceError::Tracefs("the kernel accepted no uprobe".into()));
    }

    fs::create_dir(&session.instance).map_err(|e| describe(&session.instance, e))?;
    session.instance_created = true;
    let _ = fs::write(session.instance.join("buffer_size_kb"), BUFFER_KIB);
    let events_dir = session.instance.join("events").join(&group);
    for (index, probe) in probes.iter().enumerate() {
        if let Some((_, value)) = probe.only_when
            && session.defined.contains(&format!("p{index}"))
        {
            write(
                &events_dir.join(format!("p{index}")).join("filter"),
                &format!("cmd == {value}"),
            )?;
        }
    }
    // enable one by one: a probe the kernel cannot arm (a binary on a filesystem without uprobe
    // support) is skipped, never allowed to stop the others
    let mut enabled = 0usize;
    for name in &session.defined {
        match fs::write(events_dir.join(name).join("enable"), "1") {
            Ok(()) => enabled += 1,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => {
                return Err(describe(&events_dir, error));
            }
            Err(error) => {
                tracing::debug!(event = %name, %error, "uprobe could not be enabled");
                rejected += 1;
            }
        }
    }
    if enabled == 0 {
        return Err(TraceError::Tracefs("the kernel enabled no uprobe".into()));
    }
    let started_at = SystemTime::now();

    let pipe_path = session.instance.join("trace_pipe");
    let mut pipe: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&pipe_path)
        .map_err(|e| describe(&pipe_path, e))?;
    let mut aggregator = Aggregator::new(probes, options.max_distinct);
    let mut buffer = vec![0u8; 1 << 16];
    let mut pending = String::new();
    let begun = Instant::now();
    let mut drain = |pipe: &mut File, aggregator: &mut Aggregator| -> Result<bool, TraceError> {
        match pipe.read(&mut buffer) {
            Ok(0) => Ok(false),
            Ok(read) => {
                pending.push_str(&String::from_utf8_lossy(&buffer[..read]));
                while let Some(end) = pending.find('\n') {
                    let line: String = pending.drain(..=end).collect();
                    if let Some(parsed) = parse::parse(line.trim_end()) {
                        aggregator.add(&parsed, executable);
                    }
                }
                Ok(true)
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => Ok(true),
            Err(error) => Err(describe(&pipe_path, error)),
        }
    };
    while begun.elapsed() < options.duration && !stop() {
        if !drain(&mut pipe, &mut aggregator)? {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // stop producing, then take what is still buffered
    let recorded = begun.elapsed();
    let _ = fs::write(events_dir.join("enable"), "0");
    while drain(&mut pipe, &mut aggregator)? {}
    drop(pipe);
    drop(session);

    let seconds = started_at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let dropped = aggregator.dropped + rejected;
    Ok((
        aggregator.finish(lattice_core::rfc3339(seconds), recorded.as_secs()),
        dropped,
    ))
}
