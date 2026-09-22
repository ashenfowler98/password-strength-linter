//! Individual rules. Each one takes a line number and a password and
//! appends zero or more `Finding`s to the caller's buffer.

use crate::{Finding, Severity};

const MIN_LENGTH: usize = 12;
const REPEAT_RUN_THRESHOLD: usize = 4;
const SEQUENCE_RUN_THRESHOLD: usize = 4;

// Small, well-known passwords worth flagging outright. Not an attempt at
// a real breach-corpus check — that belongs in a later, file-backed rule.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "123456",
    "123456789",
    "12345678",
    "1234567",
    "12345",
    "1q2w3e4r",
    "qazwsx",
    "qwerty",
    "abc123",
    "111111",
    "123123",
    "000000",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "iloveyou",
    "master",
    "sunshine",
    "princess",
    "trustno1",
    "shadow",
    "superman",
    "batman",
    "starwars",
    "michael",
];

pub fn check_length(line: usize, password: &str, findings: &mut Vec<Finding>) {
    let len = password.chars().count();
    if len < MIN_LENGTH {
        findings.push(Finding {
            line,
            severity: Severity::Warn,
            message: format!("too short ({len} < {MIN_LENGTH} characters)"),
        });
    }
}

pub fn check_character_classes(line: usize, password: &str, findings: &mut Vec<Finding>) {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if !c.is_whitespace() {
            has_symbol = true;
        }
    }

    if !has_lower {
        findings.push(Finding {
            line,
            severity: Severity::Warn,
            message: "missing a lowercase letter".to_string(),
        });
    }
    if !has_upper {
        findings.push(Finding {
            line,
            severity: Severity::Warn,
            message: "missing an uppercase letter".to_string(),
        });
    }
    if !has_digit {
        findings.push(Finding {
            line,
            severity: Severity::Warn,
            message: "missing a digit".to_string(),
        });
    }
    if !has_symbol {
        findings.push(Finding {
            line,
            severity: Severity::Info,
            message: "missing a symbol".to_string(),
        });
    }
}

pub fn check_common_password(line: usize, password: &str, findings: &mut Vec<Finding>) {
    let lower = password.to_ascii_lowercase();
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        findings.push(Finding {
            line,
            severity: Severity::Warn,
            message: "matches a well-known common password".to_string(),
        });
    }
}

/// Flags runs of the same character (`"aaaa"`) at the threshold length,
/// once per run rather than once per repeated character.
pub fn check_repeated_run(line: usize, password: &str, findings: &mut Vec<Finding>) {
    let chars: Vec<char> = password.chars().collect();
    let mut run_len = 1usize;

    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            run_len += 1;
            if run_len == REPEAT_RUN_THRESHOLD {
                findings.push(Finding {
                    line,
                    severity: Severity::Warn,
                    message: format!(
                        "contains a repeated character run ('{}' x{run_len})",
                        chars[i]
                    ),
                });
            }
        } else {
            run_len = 1;
        }
    }
}

/// Flags ascending or descending runs of consecutive ASCII code points,
/// e.g. "abcd" or "4321", which cover both letter and digit keyboard runs.
pub fn check_sequential_run(line: usize, password: &str, findings: &mut Vec<Finding>) {
    let bytes: Vec<u8> = password.bytes().collect();
    if bytes.len() < SEQUENCE_RUN_THRESHOLD {
        return;
    }

    let mut ascending = 1usize;
    let mut descending = 1usize;

    for i in 1..bytes.len() {
        // Cast to i32 so there is no risk of u8 overflow on comparison.
        let prev = bytes[i - 1].to_ascii_lowercase() as i32;
        let cur = bytes[i].to_ascii_lowercase() as i32;

        ascending = if cur == prev + 1 { ascending + 1 } else { 1 };
        descending = if prev == cur + 1 { descending + 1 } else { 1 };

        if ascending == SEQUENCE_RUN_THRESHOLD || descending == SEQUENCE_RUN_THRESHOLD {
            findings.push(Finding {
                line,
                severity: Severity::Warn,
                message: "contains a sequential run (e.g. \"abcd\" or \"4321\")".to_string(),
            });
            ascending = 1;
            descending = 1;
        }
    }
}
