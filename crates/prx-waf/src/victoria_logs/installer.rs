//! `VictoriaLogs` binary installer.
//!
//! Responsible for guaranteeing that a verified `victoria-logs` binary is
//! present at `VictoriaLogsConfig::binary_path` before [`super::sidecar`]
//! tries to spawn it.
//!
//! The binary is downloaded once from the upstream GitHub release, verified
//! against the SHA-256 published alongside the archive, extracted, and atomically
//! moved into place.  The unverified archive is **never** executed.

use std::path::{Path, PathBuf};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tracing::info;

use waf_common::config::VictoriaLogsConfig;

/// Make sure a usable `victoria-logs` binary exists at `cfg.binary_path`.
///
/// * If the file already exists, returns immediately.
/// * If `cfg.auto_install` is `false`, returns an error so the operator can
///   provision the binary out-of-band before retrying.
/// * Otherwise downloads, verifies, and installs the upstream binary.
pub async fn ensure_binary(cfg: &VictoriaLogsConfig) -> anyhow::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }

    let binary_path = Path::new(&cfg.binary_path);
    if binary_path.exists() {
        info!(path = %binary_path.display(), "VictoriaLogs binary present, skipping install");
        return Ok(());
    }

    if !cfg.auto_install {
        anyhow::bail!(
            "VictoriaLogs is enabled but binary is missing at '{}' and auto_install = false. \
             Provision the binary manually or set victoria_logs.auto_install = true.",
            cfg.binary_path
        );
    }

    let parent = binary_path.parent().with_context(|| {
        format!(
            "victoria_logs.binary_path '{}' has no parent directory",
            cfg.binary_path
        )
    })?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create parent dir '{}'", parent.display()))?;

    let target = detect_target()?;
    let archive_filename = format!(
        "victoria-logs-{os}-{arch}-{version}.tar.gz",
        version = cfg.version,
        os = target.os,
        arch = target.arch,
    );
    let archive_url = format!(
        "https://github.com/VictoriaMetrics/VictoriaLogs/releases/download/{version}/{archive_filename}",
        version = cfg.version,
    );
    // Upstream publishes a per-archive `<archive>_checksums.txt` (NOT
    // `<archive>.sha256`) containing one shasum row per shipped artefact —
    // the archive itself plus the extracted `victoria-logs-prod` binary.
    let checksum_url = format!(
        "https://github.com/VictoriaMetrics/VictoriaLogs/releases/download/\
         {version}/victoria-logs-{os}-{arch}-{version}_checksums.txt",
        version = cfg.version,
        os = target.os,
        arch = target.arch,
    );

    info!(url = %archive_url, "Downloading VictoriaLogs archive");
    let archive_bytes = http_get_bytes(&archive_url)
        .await
        .with_context(|| format!("download archive from '{archive_url}'"))?;

    info!(url = %checksum_url, "Downloading VictoriaLogs checksum");
    let checksum_text = http_get_text(&checksum_url)
        .await
        .with_context(|| format!("download checksum from '{checksum_url}'"))?;
    let expected_sha256 = parse_sha256_file(&checksum_text, &archive_filename)?;

    let actual_sha256 = sha256_hex(&archive_bytes);
    if !actual_sha256.eq_ignore_ascii_case(&expected_sha256) {
        anyhow::bail!("VictoriaLogs archive SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}");
    }
    info!(sha256 = %actual_sha256, "VictoriaLogs archive checksum verified");

    let staging = parent.join(".victoria-logs-staging");
    if staging.exists() {
        tokio::fs::remove_dir_all(&staging)
            .await
            .with_context(|| format!("clean stale staging dir '{}'", staging.display()))?;
    }
    tokio::fs::create_dir_all(&staging)
        .await
        .with_context(|| format!("create staging dir '{}'", staging.display()))?;

    let archive_path = staging.join("victoria-logs.tar.gz");
    tokio::fs::write(&archive_path, &archive_bytes)
        .await
        .with_context(|| format!("write archive to '{}'", archive_path.display()))?;

    extract_tar_gz(&archive_path, &staging)
        .await
        .with_context(|| format!("extract archive '{}'", archive_path.display()))?;

    let extracted_binary = find_extracted_binary(&staging)?;
    info!(from = %extracted_binary.display(), to = %binary_path.display(), "Installing VictoriaLogs binary");
    tokio::fs::rename(&extracted_binary, binary_path)
        .await
        .with_context(|| format!("move binary into '{}'", binary_path.display()))?;

    set_executable(binary_path)
        .await
        .with_context(|| format!("chmod +x '{}'", binary_path.display()))?;

    if let Err(e) = tokio::fs::remove_dir_all(&staging).await {
        tracing::warn!(error = %e, dir = %staging.display(), "Failed to clean staging dir");
    }

    info!(path = %binary_path.display(), "VictoriaLogs install complete");
    Ok(())
}

/// Resolve the upstream artefact name fragments for the running platform.
struct Target {
    os: &'static str,
    arch: &'static str,
}

fn detect_target() -> anyhow::Result<Target> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => anyhow::bail!(
            "VictoriaLogs auto-install is unsupported on OS '{other}' — provision the binary manually \
             and set auto_install = false"
        ),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => anyhow::bail!(
            "VictoriaLogs auto-install is unsupported on architecture '{other}' — provision the binary manually \
             and set auto_install = false"
        ),
    };
    Ok(Target { os, arch })
}

async fn http_get_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .with_context(|| format!("HTTP GET '{url}'"))?
        .error_for_status()
        .with_context(|| format!("non-2xx response from '{url}'"))?;
    let bytes = resp.bytes().await.context("read response bytes")?;
    Ok(bytes.to_vec())
}

async fn http_get_text(url: &str) -> anyhow::Result<String> {
    let resp = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .with_context(|| format!("HTTP GET '{url}'"))?
        .error_for_status()
        .with_context(|| format!("non-2xx response from '{url}'"))?;
    resp.text().await.context("read response text")
}

/// Standard `<sha256>  <filename>` shasum format. Tolerant of whitespace,
/// the optional `*` binary marker, and multi-row files (the upstream
/// `_checksums.txt` lists both the archive and the extracted binary).
///
/// Returns the hash of the row whose filename equals `expected_filename`.
fn parse_sha256_file(text: &str, expected_filename: &str) -> anyhow::Result<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hex_token) = parts.next() else {
            continue;
        };
        let Some(name_token) = parts.next() else {
            continue;
        };
        // Strip the optional `*` shasum binary marker (`abc...  *file.tgz`).
        let filename = name_token.strip_prefix('*').unwrap_or(name_token);
        if filename != expected_filename {
            continue;
        }
        if hex_token.len() != 64 || !hex_token.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("checksum row for '{expected_filename}' has invalid SHA-256 token: '{hex_token}'");
        }
        return Ok(hex_token.to_ascii_lowercase());
    }
    anyhow::bail!("checksum file does not contain a row for '{expected_filename}'");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Extract a `.tar.gz` archive using the system `tar` binary.
///
/// We delegate to `tar` rather than pulling in a Rust gzip + tar
/// implementation so the dep surface stays small. On Linux/macOS hosts that
/// the installer supports, `tar` is part of the base userspace.
async fn extract_tar_gz(archive: &Path, dest: &Path) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("tar")
        .args([
            "-xzf",
            archive.to_str().context("archive path is not valid UTF-8")?,
            "-C",
            dest.to_str().context("dest path is not valid UTF-8")?,
        ])
        .status()
        .await
        .context("spawn `tar` to extract archive")?;
    if !status.success() {
        anyhow::bail!("`tar -xzf` failed with status {status}");
    }
    Ok(())
}

/// Locate the extracted `victoria-logs` binary inside the staging directory.
///
/// Upstream archives contain a single executable named `victoria-logs-prod`
/// (or `victoria-logs` in older releases). The walk depth is intentionally
/// tiny (≤ 2 levels) — the archive layout is well-known.
fn find_extracted_binary(staging: &Path) -> anyhow::Result<PathBuf> {
    const CANDIDATES: &[&str] = &["victoria-logs-prod", "victoria-logs"];
    for entry in std::fs::read_dir(staging).with_context(|| format!("read staging dir '{}'", staging.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && CANDIDATES.iter().any(|c| name.starts_with(c))
        {
            return Ok(path);
        }
        if path.is_dir() {
            for sub in std::fs::read_dir(&path).with_context(|| format!("read '{}'", path.display()))? {
                let sub = sub?;
                let sub_path = sub.path();
                if sub_path.is_file()
                    && let Some(name) = sub_path.file_name().and_then(|n| n.to_str())
                    && CANDIDATES.iter().any(|c| name.starts_with(c))
                {
                    return Ok(sub_path);
                }
            }
        }
    }
    anyhow::bail!(
        "could not find an extracted `victoria-logs` binary inside '{}'",
        staging.display()
    )
}

#[cfg(unix)]
async fn set_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = tokio::fs::metadata(path).await?.permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(path, perms).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_shasum_format() {
        let text = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  \
                    victoria-logs-linux-amd64-v1.0.0.tar.gz\n";
        let got = parse_sha256_file(text, "victoria-logs-linux-amd64-v1.0.0.tar.gz").unwrap();
        assert_eq!(got, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    }

    /// Real upstream checksum file ships with two rows — the archive row
    /// AND the extracted `victoria-logs-prod` binary row. We must pick
    /// the archive row regardless of order.
    #[test]
    fn picks_archive_row_from_multiline_checksums() {
        let text = "fc9a429a59460cf3ade58547303a64b7a5ea663033da31e3e66a3f819b260994  victoria-logs-prod\n\
                    eb59aee1472a4c6b81e43de7f3fb822e1da974f23e9b954911c109d34e2e4e84  victoria-logs-linux-arm64-v1.50.0.tar.gz\n";
        let got = parse_sha256_file(text, "victoria-logs-linux-arm64-v1.50.0.tar.gz").unwrap();
        assert_eq!(got, "eb59aee1472a4c6b81e43de7f3fb822e1da974f23e9b954911c109d34e2e4e84");
    }

    #[test]
    fn tolerates_binary_marker_prefix() {
        let text = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 *file.tgz\n";
        let got = parse_sha256_file(text, "file.tgz").unwrap();
        assert_eq!(got, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn rejects_invalid_hex_token() {
        let bad = "ZZZZ_not_hex  victoria-logs.tar.gz\n";
        assert!(parse_sha256_file(bad, "victoria-logs.tar.gz").is_err());
    }

    #[test]
    fn rejects_missing_filename_row() {
        let text = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  other-file.tgz\n";
        assert!(parse_sha256_file(text, "victoria-logs.tar.gz").is_err());
    }

    #[test]
    fn rejects_empty_checksum() {
        assert!(parse_sha256_file("", "any.tgz").is_err());
        assert!(parse_sha256_file("\n\n\n", "any.tgz").is_err());
    }

    #[test]
    fn sha256_hex_round_trips_known_vector() {
        let hash = sha256_hex(b"abc");
        assert_eq!(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
