use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {value}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Target {
    Local,
    Ssh(String),
}

impl Target {
    pub fn label(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Ssh(destination) => destination,
        }
    }
}

impl FromStr for Target {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "local" {
            return Ok(Self::Local);
        }
        if value.is_empty() || value.starts_with('-') || value.chars().any(char::is_whitespace) {
            return Err(
                "target must be 'local' or an OpenSSH destination such as user@host".into(),
            );
        }
        Ok(Self::Ssh(value.to_owned()))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub command: &'static str,
    pub output: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanError {
    pub probe: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u8,
    pub scanner_version: &'static str,
    pub target: String,
    pub duration_ms: u128,
    pub probes_run: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
}

impl ScanReport {
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }
}
