//! Embed only identities explicitly supplied by the builder.

use std::{env, fs, path::PathBuf, process::Command};

#[path = "src/build_identity_input.rs"]
mod input;

fn main() {
    for name in ["DOCKET_SOURCE_COMMIT", "DOCKET_BUILD_IDENTITY", "RUSTC"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/build_identity_input.rs");
    let read = |name| match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be UTF-8"),
    };
    let source = read("DOCKET_SOURCE_COMMIT");
    let source = input::source_commit(source.as_deref()).expect("invalid source identity");
    let build = read("DOCKET_BUILD_IDENTITY");
    let build = input::build_identity(build.as_deref()).expect("invalid build identity");
    let rustc = Command::new(env::var_os("RUSTC").expect("Cargo supplies RUSTC"))
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|version| version.trim().to_owned());
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo supplies CARGO_PKG_VERSION");
    let version = format!("{version} ({})", source.unwrap_or("source unavailable"));
    let generated = format!(
        "pub const SOURCE_COMMIT: Option<&str> = {source:?};\n\
         pub const BUILD_ID: Option<&str> = {build:?};\n\
         pub const RUSTC: Option<&str> = {rustc:?};\n\
         pub const TARGET: &str = {target:?};\n\
         pub const VERSION_STRING: &str = {version:?};\n"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::write(out.join("build_identity.rs"), generated).expect("write build identity");
}
