//! Self-upgrade via the official sh.qntx.fun installer (`kobe upgrade`).
//!
//! **Naming:** the primary subcommand is `upgrade` (replace this binary with a
//! newer release). `update` is an alias. This matches tools like Deno/Bun
//! (`upgrade`) rather than apt's split of `update` (refresh indexes) vs
//! `upgrade` (install packages).
//!
//! Reuses the same install path as:
//! - `curl -fsSL https://sh.qntx.fun/kobe | sh` (Unix)
//! - `irm https://sh.qntx.fun/kobe/ps | iex` (Windows)
//!
//! Cargo-installed binaries are not overwritten; users are directed to
//! `cargo install kobe-cli --force` instead.

use std::process::Command;

use clap::Args;
use serde::Serialize;

use crate::output;

/// GitHub repository for releases / installer substitution.
const REPO: &str = "qntx/kobe";
/// Official install endpoint (Unix shell).
#[cfg(not(windows))]
const INSTALL_SH_URL: &str = "https://sh.qntx.fun/kobe";
/// Official install endpoint (PowerShell).
#[cfg(windows)]
const INSTALL_PS_URL: &str = "https://sh.qntx.fun/kobe/ps";

/// Upgrade the `kobe` CLI binary in place (`kobe upgrade` / `kobe update`).
#[derive(Args, Debug)]
pub(crate) struct UpdateCommand {
    /// Only report whether a newer release is available; do not install.
    #[arg(long)]
    check: bool,

    /// Re-run the installer even when already on the latest version.
    #[arg(long)]
    force: bool,
}

/// Structured result for `--json`.
#[derive(Debug, Serialize)]
#[non_exhaustive]
struct UpdateOutput {
    current: String,
    latest: String,
    update_available: bool,
    action: &'static str,
    message: String,
}

impl UpdateCommand {
    pub(crate) fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        let current = env!("CARGO_PKG_VERSION").to_owned();
        let latest = fetch_latest_version()?;
        let update_available = is_newer(&latest, &current);

        if self.check {
            let action = if update_available {
                "update_available"
            } else {
                "up_to_date"
            };
            let message = if update_available {
                format!("kobe {latest} is available (current {current})")
            } else {
                format!("kobe {current} is up to date")
            };
            return emit(
                json,
                &UpdateOutput {
                    current,
                    latest,
                    update_available,
                    action,
                    message,
                },
            );
        }

        if !update_available && !self.force {
            let message = format!("kobe {current} is already the latest version");
            return emit(
                json,
                &UpdateOutput {
                    current,
                    latest,
                    update_available: false,
                    action: "noop",
                    message,
                },
            );
        }

        if is_cargo_install()? {
            let message = format!(
                "this binary looks cargo-installed; run: cargo install kobe-cli --force --version {latest}"
            );
            if json {
                return emit(
                    json,
                    &UpdateOutput {
                        current,
                        latest,
                        update_available,
                        action: "cargo_redirect",
                        message,
                    },
                );
            }
            eprintln!("{message}");
            return Ok(());
        }

        if !json {
            #[cfg(not(windows))]
            let endpoint = INSTALL_SH_URL;
            #[cfg(windows)]
            let endpoint = INSTALL_PS_URL;
            if update_available {
                println!("Updating kobe {current} → {latest} via {endpoint} …");
            } else {
                println!("Reinstalling kobe {current} via installer (--force) …");
            }
        }

        run_official_installer()?;

        emit(
            json,
            &UpdateOutput {
                current,
                latest: latest.clone(),
                update_available,
                action: "updated",
                message: format!(
                    "installer finished; run `kobe --version` to confirm (target {latest})"
                ),
            },
        )
    }
}

fn emit(json: bool, out: &UpdateOutput) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        output::print_json(out)?;
    } else {
        println!("{}", out.message);
    }
    Ok(())
}

/// Fetch latest release tag from GitHub (no `v` prefix).
fn fetch_latest_version() -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = http_get(&url)?;
    parse_latest_tag(&body).ok_or_else(|| {
        "failed to parse latest version from GitHub (network error or rate limited)".into()
    })
}

/// Pull `"tag_name":"vX.Y.Z"` without a full JSON dependency beyond string scan.
fn parse_latest_tag(body: &str) -> Option<String> {
    const KEY: &str = "\"tag_name\"";
    let i = body.find(KEY)?;
    let after = body.get(i + KEY.len()..)?;
    let colon = after.find(':')?;
    let rest = after.get(colon + 1..)?;
    let start_q = rest.find('"')?;
    let rest = rest.get(start_q + 1..)?;
    let end_q = rest.find('"')?;
    let tag = rest.get(..end_q)?;
    Some(tag.trim_start_matches('v').to_owned())
}

/// True when `latest` is strictly greater than `current` (numeric semver triples).
fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => latest != current,
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    // Ignore pre-release suffix on patch if present (e.g. 3.0.0-rc.1 → fail → string cmp).
    if parts.next().is_some() {
        // more than 3 components — only accept pure X.Y.Z
        return None;
    }
    Some((major, minor, patch))
}

fn http_get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Prefer curl/wget so we match the installer toolchain and avoid HTTP crates.
    if command_exists("curl") {
        let out = Command::new("curl")
            .args([
                "-fsSL",
                "-A",
                "kobe-update",
                "-H",
                "Accept: application/vnd.github+json",
                url,
            ])
            .output()?;
        if out.status.success() {
            return Ok(String::from_utf8(out.stdout)?);
        }
        return Err(format!(
            "curl failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    if command_exists("wget") {
        let out = Command::new("wget")
            .args(["-q", "--user-agent=kobe-update", "-O-", url])
            .output()?;
        if out.status.success() {
            return Ok(String::from_utf8(out.stdout)?);
        }
        return Err(format!(
            "wget failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Err("curl or wget is required for `kobe upgrade`".into())
}

fn command_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn is_cargo_install() -> Result<bool, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let s = exe.to_string_lossy();
    Ok(s.contains(".cargo/bin") || s.contains(".cargo\\bin"))
}

fn run_official_installer() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &format!("irm {INSTALL_PS_URL} | iex"),
            ])
            .status()?;
        if !status.success() {
            return Err(format!("installer exited with {status}").into());
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        // Pipe curl into sh — same entrypoint as README install instructions.
        if !command_exists("curl") {
            return Err("curl is required to run the official installer".into());
        }
        if !command_exists("sh") {
            return Err("sh is required to run the official installer".into());
        }
        let status = Command::new("sh")
            .args(["-c", &format!("curl -fsSL {INSTALL_SH_URL} | sh")])
            .status()?;
        if !status.success() {
            return Err(format!("installer exited with {status}").into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tag_from_github_payload() {
        let body = r#"{"url":"...","tag_name":"v3.0.0","name":"v3.0.0"}"#;
        assert_eq!(parse_latest_tag(body).as_deref(), Some("3.0.0"));
    }

    #[test]
    fn parse_tag_without_v_prefix() {
        let body = r#"{"tag_name": "3.1.0"}"#;
        assert_eq!(parse_latest_tag(body).as_deref(), Some("3.1.0"));
    }

    #[test]
    fn semver_newer() {
        assert!(is_newer("3.0.1", "3.0.0"));
        assert!(is_newer("3.1.0", "3.0.9"));
        assert!(is_newer("4.0.0", "3.9.9"));
        assert!(!is_newer("3.0.0", "3.0.0"));
        assert!(!is_newer("2.9.9", "3.0.0"));
    }
}
