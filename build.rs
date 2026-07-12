//! Embed the git commit hash into the binary so `decoyrail --version`
//! reports `<pkg version> (<short hash>[-dirty])`. Falls back to the bare
//! package version when built outside a git checkout (e.g. from a tarball).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let full = match git(&["rev-parse", "--short=9", "HEAD"]) {
        Some(hash) => {
            let dirty = git(&["status", "--porcelain"]).is_some();
            let suffix = if dirty { "-dirty" } else { "" };
            format!("{version} ({hash}{suffix})")
        }
        None => version.to_string(),
    };
    println!("cargo:rustc-env=DECOYRAIL_VERSION={full}");

    // Rebuild when the checked-out commit changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed=.git/{head}");
    }
}
