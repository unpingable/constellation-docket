//! Executable identity: `--version` and `--build-info`, answered from
//! compile-time constants before any state, configuration or stdin is read.

use serde::Serialize;

pub use crate::source_commit::{parse_source_commit, SOURCE_COMMIT_VARIABLE};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

pub use generated::{CARGO_PROFILE, RUSTC_VERSION, SOURCE_COMMIT, TARGET};

/// Closed schema of the `--build-info` document.
pub const BUILD_INFO_SCHEMA: &str = "docket.build-info/v1";
/// Workspace version compiled into every Docket executable.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub schema: &'static str,
    pub component: &'static str,
    pub version: &'static str,
    /// Full commit recorded by release automation through
    /// `DOCKET_SOURCE_COMMIT`; `null` for an ordinary development build.
    pub source_commit: Option<&'static str>,
    pub cargo_profile: &'static str,
    pub debug_assertions: bool,
    pub rustc: &'static str,
    pub target: &'static str,
}

impl BuildInfo {
    pub fn current(component: &'static str) -> Self {
        Self {
            schema: BUILD_INFO_SCHEMA,
            component,
            version: VERSION,
            source_commit: SOURCE_COMMIT,
            cargo_profile: CARGO_PROFILE,
            debug_assertions: cfg!(debug_assertions),
            rustc: RUSTC_VERSION,
            target: TARGET,
        }
    }
}

/// One line: component, version and the full source commit (or
/// `unrecorded` for a development build).
pub fn version_line(component: &str) -> String {
    format!(
        "{component} {VERSION} {}",
        SOURCE_COMMIT.unwrap_or("unrecorded")
    )
}

/// Answers `--version` or `--build-info` when it is the only argument.
/// Returns `true` when the request was answered and the caller must exit.
pub fn answer_identity_request(component: &'static str, args: &[String]) -> bool {
    match args {
        [flag] if flag == "--version" => {
            println!("{}", version_line(component));
            true
        }
        [flag] if flag == "--build-info" => {
            let document = serde_json::to_string(&BuildInfo::current(component))
                .expect("build information serializes");
            println!("{document}");
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_is_closed_and_carries_the_recorded_commit() {
        let value = serde_json::to_value(BuildInfo::current("docket")).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 8);
        assert_eq!(value["schema"], BUILD_INFO_SCHEMA);
        assert_eq!(value["component"], "docket");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["source_commit"].as_str(), SOURCE_COMMIT);
        assert_eq!(value["debug_assertions"], cfg!(debug_assertions));
    }

    #[test]
    fn version_line_names_component_version_and_commit() {
        let line = version_line("docket-local-standing-resolver");
        let expected_commit = SOURCE_COMMIT.unwrap_or("unrecorded");
        assert_eq!(
            line,
            format!(
                "docket-local-standing-resolver {} {expected_commit}",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn source_commit_accepts_only_a_full_lowercase_commit_id() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_source_commit(None), Ok(None));
        assert_eq!(parse_source_commit(Some("")), Ok(None));
        assert_eq!(parse_source_commit(Some(commit)), Ok(Some(commit)));
        for rejected in [
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789ABCDEF0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456g",
            " 0123456789abcdef0123456789abcdef01234567",
            "4dd448f",
        ] {
            assert!(parse_source_commit(Some(rejected)).is_err(), "{rejected}");
        }
    }

    #[test]
    fn only_a_sole_identity_flag_is_answered() {
        for args in [
            vec![],
            vec!["--version".to_owned(), "extra".to_owned()],
            vec!["governed-loop".to_owned(), "--version".to_owned()],
            vec!["--help".to_owned()],
        ] {
            assert!(!answer_identity_request("docket", &args), "{args:?}");
        }
    }
}
