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
pub struct HostCapabilities {
    pub root: Option<bool>,
    pub sudo_present: bool,
    pub tools: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub capabilities: HostCapabilities,
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
pub struct Observation {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub partial: Option<String>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub collection_limits: Vec<String>,
    pub evidence_budget_exceeded: bool,
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
    pub scan_id: String,
    pub started_at: u64,
    pub completed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_pack: Option<ProbePackInfo>,
    pub target: String,
    pub host: Option<HostInfo>,
    pub duration_ms: u128,
    pub probes_run: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<Observation>,
    pub errors: Vec<ScanError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProbePackInfo {
    pub schema_version: u8,
    pub id: String,
    pub version: String,
    pub signer: String,
}

impl ScanReport {
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }
}

/// Truncate collected evidence to at most `limit` bytes without ever splitting
/// a UTF-8 code point (`String::truncate` panics on a non-boundary index).
pub fn truncate_evidence(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut cut = limit;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    value.truncate(cut);
    value.push_str("\n[truncated]");
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_utf8_boundaries() {
        let truncated = truncate_evidence("é".repeat(10), 3);
        assert!(truncated.starts_with('é'));
        assert!(truncated.ends_with("[truncated]"));
    }

    #[test]
    fn truncation_leaves_short_values_untouched() {
        assert_eq!(truncate_evidence("ok".into(), 16), "ok");
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Info < Severity::Low);
    }
}
