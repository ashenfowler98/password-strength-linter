//! Streaming checks for a list of candidate passwords, one per line.
//!
//! The whole point is that `lint` never holds more than one line in memory
//! at a time, so it can walk a multi-gigabyte password list on a laptop.

pub mod rules;

use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub line: usize,
    pub severity: Severity,
    pub message: String,
}

/// Runs every rule against a single password and returns what it found.
///
/// The password itself is never included in a `Finding` — callers print
/// line numbers and rule names, not the input, so a linter run doesn't
/// itself become a new place secrets leak into.
pub fn check_line(line: usize, password: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    rules::check_length(line, password, &mut findings);
    rules::check_character_classes(line, password, &mut findings);
    rules::check_common_password(line, password, &mut findings);
    rules::check_repeated_run(line, password, &mut findings);
    rules::check_sequential_run(line, password, &mut findings);
    findings
}

/// Reads `reader` line by line, writing one report line per finding to
/// `out`, and returns the total number of findings.
///
/// Uses a single reusable buffer and `BufRead::read_line` so memory use
/// stays flat regardless of how many lines the input has.
pub fn lint<R: BufRead, W: Write>(mut reader: R, mut out: W) -> io::Result<usize> {
    let mut buf = String::new();
    let mut line_no = 0usize;
    let mut total_findings = 0usize;

    loop {
        buf.clear();
        let bytes_read = reader.read_line(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        line_no += 1;

        let password = buf.trim_end_matches(['\n', '\r']);
        if password.is_empty() {
            continue;
        }

        for finding in check_line(line_no, password) {
            let tag = match finding.severity {
                Severity::Warn => "warn",
                Severity::Info => "info",
            };
            writeln!(out, "{}: [{}] {}", finding.line, tag, finding.message)?;
            total_findings += 1;
        }
    }

    Ok(total_findings)
}
