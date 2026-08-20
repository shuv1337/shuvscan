use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::Path,
};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    model::ProbePackInfo,
    probes::{BUILTINS, Probe},
};

const SCHEMA_VERSION: u8 = 1;
const MAX_PACK_BYTES: usize = 64 * 1024;
const PUBLIC_KEY_HEX_BYTES: usize = 64;
const SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    id: String,
    version: String,
    signer: String,
    probes: Vec<String>,
}

#[derive(Debug)]
pub struct VerifiedPack {
    pub info: ProbePackInfo,
    pub probes: Vec<Probe>,
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("could not read probe pack: {0}")]
    ReadPack(#[source] std::io::Error),
    #[error("probe pack exceeds the {MAX_PACK_BYTES}-byte limit")]
    TooLarge,
    #[error("could not read probe pack signature: {0}")]
    ReadSignature(#[source] std::io::Error),
    #[error("could not read trusted probe pack key: {0}")]
    ReadKey(#[source] std::io::Error),
    #[error("trusted probe pack key must be exactly 64 hexadecimal characters")]
    InvalidKey,
    #[error("probe pack signature must be exactly 128 hexadecimal characters")]
    InvalidSignature,
    #[error("probe pack signature verification failed")]
    VerificationFailed,
    #[error("probe pack is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("unsupported probe pack schema version {0}")]
    UnsupportedSchema(u8),
    #[error("invalid probe pack {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("probe pack contains duplicate probe ID {0}")]
    DuplicateProbe(String),
    #[error("probe pack references unknown probe ID {0}")]
    UnknownProbe(String),
}

pub fn load(
    manifest_path: &Path,
    signature_path: &Path,
    trusted_key_path: &Path,
) -> Result<VerifiedPack, PackError> {
    let source = read_bounded(manifest_path, MAX_PACK_BYTES).map_err(|error| {
        if error.kind() == io::ErrorKind::FileTooLarge {
            PackError::TooLarge
        } else {
            PackError::ReadPack(error)
        }
    })?;
    let signature = read_hex_text(
        signature_path,
        SIGNATURE_HEX_BYTES + 2,
        PackError::ReadSignature,
        || PackError::InvalidSignature,
    )?;
    let trusted_key = read_hex_text(
        trusted_key_path,
        PUBLIC_KEY_HEX_BYTES + 2,
        PackError::ReadKey,
        || PackError::InvalidKey,
    )?;
    verify_and_parse(&source, &signature, &trusted_key)
}

fn verify_and_parse(
    source: &[u8],
    signature: &str,
    trusted_key: &str,
) -> Result<VerifiedPack, PackError> {
    let key_bytes: [u8; 32] = decode_hex(trusted_key.trim())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PackError::InvalidKey)?;
    let signature_bytes: [u8; 64] = decode_hex(signature.trim())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PackError::InvalidSignature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| PackError::InvalidKey)?;
    key.verify_strict(source, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| PackError::VerificationFailed)?;

    let manifest: Manifest = serde_json::from_slice(source).map_err(PackError::InvalidJson)?;
    validate(manifest)
}

fn validate(manifest: Manifest) -> Result<VerifiedPack, PackError> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(PackError::UnsupportedSchema(manifest.schema_version));
    }
    validate_identifier("id", &manifest.id, 128, false)?;
    validate_identifier("version", &manifest.version, 64, true)?;
    validate_identifier("signer", &manifest.signer, 128, false)?;
    if manifest.probes.is_empty() {
        return Err(PackError::InvalidField {
            field: "probes",
            reason: "must contain at least one probe ID",
        });
    }

    let mut seen = BTreeSet::new();
    let mut probes = Vec::with_capacity(manifest.probes.len());
    for id in manifest.probes {
        if !seen.insert(id.clone()) {
            return Err(PackError::DuplicateProbe(id));
        }
        let probe = BUILTINS
            .iter()
            .find(|probe| probe.id == id)
            .copied()
            .ok_or(PackError::UnknownProbe(id))?;
        probes.push(probe);
    }

    Ok(VerifiedPack {
        info: ProbePackInfo {
            schema_version: manifest.schema_version,
            id: manifest.id,
            version: manifest.version,
            signer: manifest.signer,
        },
        probes,
    })
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_len: usize,
    allow_plus: bool,
) -> Result<(), PackError> {
    let mut chars = value.chars();
    let valid = value.len() <= max_len
        && chars
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-')
                || (allow_plus && character == '+')
        });
    if valid {
        Ok(())
    } else {
        Err(PackError::InvalidField {
            field,
            reason: "must start with an ASCII letter or digit and contain only supported identifier characters",
        })
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let read_limit = u64::try_from(limit)
        .map_err(|_| io::Error::other("file size limit does not fit u64"))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("file exceeds the {limit}-byte limit"),
        ));
    }
    Ok(bytes)
}

fn read_hex_text(
    path: &Path,
    limit: usize,
    read_error: fn(io::Error) -> PackError,
    invalid_error: fn() -> PackError,
) -> Result<String, PackError> {
    let bytes = read_bounded(path, limit).map_err(|error| {
        if error.kind() == io::ErrorKind::FileTooLarge {
            invalid_error()
        } else {
            read_error(error)
        }
    })?;
    String::from_utf8(bytes).map_err(|_| invalid_error())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn signed(source: &[u8]) -> (String, String) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(source);
        (
            encode_hex(&signature.to_bytes()),
            encode_hex(key.verifying_key().as_bytes()),
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn verified_manifest_resolves_builtin_probe_order() {
        let source = br#"{
            "schema_version": 1,
            "id": "org.example.baseline",
            "version": "1.2.0",
            "signer": "example-security",
            "probes": ["SHUV-KERN-002", "SHUV-AUTH-001"]
        }"#;
        let (signature, key) = signed(source);
        let pack = verify_and_parse(source, &signature, &key).unwrap();

        assert_eq!(pack.info.id, "org.example.baseline");
        assert_eq!(pack.info.schema_version, 1);
        assert_eq!(pack.probes.len(), 2);
        assert_eq!(pack.probes[0].id, "SHUV-KERN-002");
        assert_eq!(pack.probes[1].id, "SHUV-AUTH-001");
    }

    #[test]
    fn tampered_manifest_fails_before_parsing() {
        let original = br#"{"not":"the final manifest"}"#;
        let (signature, key) = signed(original);
        let error = verify_and_parse(b"not json", &signature, &key).unwrap_err();

        assert!(matches!(error, PackError::VerificationFailed));
    }

    #[test]
    fn schema_rejects_unknown_duplicate_and_executable_fields() {
        for source in [
            br#"{"schema_version":1,"id":"test","version":"1","signer":"test","probes":["UNKNOWN"]}"#.as_slice(),
            br#"{"schema_version":1,"id":"test","version":"1","signer":"test","probes":["SHUV-AUTH-001","SHUV-AUTH-001"]}"#.as_slice(),
            br#"{"schema_version":1,"id":"test","version":"1","signer":"test","probes":["SHUV-AUTH-001"],"script":"id"}"#.as_slice(),
        ] {
            let (signature, key) = signed(source);
            assert!(verify_and_parse(source, &signature, &key).is_err());
        }
    }

    #[test]
    fn published_schema_tracks_runtime_limits() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../docs/probe-pack.schema.json")).unwrap();

        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            SCHEMA_VERSION
        );
        assert_eq!(schema["properties"]["id"]["maxLength"], 128);
        assert_eq!(schema["properties"]["version"]["maxLength"], 64);
        assert_eq!(schema["properties"]["signer"]["maxLength"], 128);
        assert_eq!(schema["properties"]["probes"]["minItems"], 1);
        assert_eq!(schema["properties"]["probes"]["uniqueItems"], true);
        assert_eq!(
            schema["properties"]["probes"]["items"]["pattern"],
            "^SHUV-[A-Z0-9]+(?:-[A-Z0-9]+)*-[0-9]{3}$"
        );
        for probe in BUILTINS {
            let parts = probe.id.split('-').collect::<Vec<_>>();
            assert!(
                parts.len() >= 3
                    && parts[0] == "SHUV"
                    && parts[1..parts.len() - 1].iter().all(|part| !part.is_empty()
                        && part.chars().all(|character| character.is_ascii_uppercase()
                            || character.is_ascii_digit()))
                    && parts.last().is_some_and(|suffix| {
                        suffix.len() == 3
                            && suffix.chars().all(|character| character.is_ascii_digit())
                    }),
                "built-in id does not match the published schema: {}",
                probe.id
            );
        }
    }
}
