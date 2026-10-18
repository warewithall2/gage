//! Stamp the build with the commit it came from.
//!
//! `ctx --version` has to answer "which ctx is this" exactly, because the
//! journal freezes verdicts at the moment they are computed and "a ctx
//! upgrade changed what a verdict means" is one of the explanations an
//! auditor must be able to rule out. A version number alone cannot do that
//! between releases.
fn main() {
    let rev = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    // A dirty tree is said out loud. A binary built from uncommitted changes
    // is not the commit it names, and that is exactly when someone is
    // debugging and most needs to know.
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    println!(
        "cargo:rustc-env=CTX_BUILD_REV={rev}{}",
        if dirty { "-dirty" } else { "" }
    );
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
