//! Isolation for code that parses hostile input.
//!
//! Rust rules out memory-safety bugs, but a parser can still panic on malformed input or spend
//! unbounded time on a crafted one. [`isolate`] contains both: a panic becomes an `Err` for that
//! artefact, and a [`Deadline`] lets long-running parsers (tree-sitter, decompression) abandon
//! work cooperatively. OS-level confinement of the whole scan process (seccomp, Landlock) is
//! applied separately by the binary, see `lattice-cli`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// A point in time after which a parser should give up.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    pub fn after(timeout: Duration) -> Self {
        Self {
            at: Instant::now() + timeout,
        }
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }

    /// `Err` with a uniform message once the deadline has passed.
    pub fn check(&self) -> Result<(), String> {
        if self.expired() {
            Err("parse exceeded its time budget; abandoned".into())
        } else {
            Ok(())
        }
    }
}

/// Runs `work` with a deadline, converting a panic into a recoverable error.
pub fn isolate<T>(
    timeout: Duration,
    work: impl FnOnce(&Deadline) -> Result<T, String>,
) -> Result<T, String> {
    let deadline = Deadline::after(timeout);
    match catch_unwind(AssertUnwindSafe(|| work(&deadline))) {
        Ok(result) => result,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".into());
            // Keep the message short: it may echo attacker-controlled input.
            let detail: String = detail.chars().take(160).collect();
            Err(format!("collector panicked and was isolated: {detail}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panics_become_errors() {
        let result: Result<(), String> = isolate(Duration::from_secs(1), |_| panic!("boom"));
        assert!(result.unwrap_err().contains("boom"));
    }

    #[test]
    fn deadlines_expire() {
        let result: Result<(), String> =
            isolate(Duration::from_millis(0), |deadline| deadline.check());
        assert!(result.is_err());
    }
}
