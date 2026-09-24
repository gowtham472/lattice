//! Lines from a tracefs `trace_pipe`:
//!
//! ```text
//!           nginx-4211    [002] ..... 81234.567890: p7: (0x7f3a2c1b2e40) value="AES-256-GCM"
//!           nginx-4211    [002] ..... 81234.567901: p9: (0x7f3a2c0e1000 <- 0x7f3a2c1b0000)
//! ```
//!
//! Return probes print the caller and the function: `(caller <- function)`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The kernel's command name (at most 15 characters).
    pub command: String,
    pub pid: u32,
    pub event: String,
    pub fields: BTreeMap<String, String>,
}

pub fn parse(line: &str) -> Option<Line> {
    static HEADER: OnceLock<regex::Regex> = OnceLock::new();
    static FIELD: OnceLock<regex::Regex> = OnceLock::new();
    let header = HEADER.get_or_init(|| {
        regex::Regex::new(
            r"^\s*(?P<command>.*?)-(?P<pid>\d+)\s+(?:\(\s*[\d-]+\)\s+)?\[\d+\]\s+(?:\S+\s+)?\d+\.\d+:\s+(?P<event>\w+):\s+\(0x[0-9a-fA-F]+(?:\s*<-\s*0x[0-9a-fA-F]+)?\)(?P<rest>.*)$",
        )
        .expect("valid pattern")
    });
    let field =
        FIELD.get_or_init(|| regex::Regex::new(r#"(\w+)=("[^"]*"|\S+)"#).expect("valid pattern"));
    let captures = header.captures(line)?;
    let fields = field
        .captures_iter(&captures["rest"])
        .map(|c| (c[1].to_owned(), c[2].trim_matches('"').to_owned()))
        .collect();
    Some(Line {
        command: captures["command"].trim().to_owned(),
        pid: captures["pid"].parse().ok()?,
        event: captures["event"].to_owned(),
        fields,
    })
}
