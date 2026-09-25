// Shared by build.rs (through #[path]) and the library, so the build-time
// acceptance rule and the unit tests exercise one function.

/// Environment variable release automation sets at compile time.
pub const SOURCE_COMMIT_VARIABLE: &str = "DOCKET_SOURCE_COMMIT";

/// Accept the variable unset or empty (no recorded commit) or as exactly 40
/// lowercase hexadecimal characters; refuse every other value.
pub fn parse_source_commit(value: Option<&str>) -> Result<Option<&str>, String> {
    match value {
        None | Some("") => Ok(None),
        Some(commit)
            if commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            Ok(Some(commit))
        }
        Some(commit) => Err(format!(
            "{SOURCE_COMMIT_VARIABLE} must be a full 40-character lowercase git commit id, \
             got {commit:?}"
        )),
    }
}
