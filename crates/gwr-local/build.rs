//! Records the release source commit and compiler identity at compile time.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[path = "src/source_commit.rs"]
mod source_commit;

use source_commit::{parse_source_commit, SOURCE_COMMIT_VARIABLE};

fn main() {
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT_VARIABLE}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/source_commit.rs");
    let raw = match env::var(SOURCE_COMMIT_VARIABLE) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            eprintln!("gwr-local: {SOURCE_COMMIT_VARIABLE} is not valid UTF-8");
            std::process::exit(1);
        }
    };
    let commit = match parse_source_commit(raw.as_deref()) {
        Ok(commit) => commit.map(str::to_owned),
        Err(diagnostic) => {
            eprintln!("gwr-local: {diagnostic}");
            std::process::exit(1);
        }
    };
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let rustc_version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    let generated = format!(
        "pub const SOURCE_COMMIT: Option<&str> = {commit:?};\n\
         pub const RUSTC_VERSION: &str = {rustc_version:?};\n\
         pub const TARGET: &str = {target:?};\n\
         pub const CARGO_PROFILE: &str = {profile:?};\n"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo provides OUT_DIR"));
    fs::write(out.join("build_identity.rs"), generated).expect("write build identity");
}
