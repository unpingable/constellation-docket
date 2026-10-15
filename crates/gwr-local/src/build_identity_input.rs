//! Validation shared by the build script and its tests.

pub fn source_commit(value: Option<&str>) -> Result<Option<&str>, &'static str> {
    match value {
        None | Some("") => Ok(None),
        Some(value)
            if value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(Some(value))
        }
        Some(_) => Err("DOCKET_SOURCE_COMMIT must be a full lowercase 40-digit commit"),
    }
}

pub fn build_identity(value: Option<&str>) -> Result<Option<&str>, &'static str> {
    match value {
        None | Some("") => Ok(None),
        Some(value) if value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic()) => {
            Ok(Some(value))
        }
        Some(_) => Err("DOCKET_BUILD_IDENTITY must be 1..256 printable ASCII bytes without spaces"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_identity_stays_unknown_and_malformed_identity_is_rejected() {
        assert_eq!(source_commit(None), Ok(None));
        assert_eq!(source_commit(Some("")), Ok(None));
        assert_eq!(build_identity(None), Ok(None));
        assert_eq!(build_identity(Some("")), Ok(None));
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(source_commit(Some(commit)), Ok(Some(commit)));
        assert_eq!(build_identity(Some("jammy-001")), Ok(Some("jammy-001")));
        for value in [
            "HEAD",
            "0123456",
            &commit.to_uppercase(),
            &format!("{commit}\n"),
        ] {
            assert!(source_commit(Some(value)).is_err(), "{value:?}");
        }
        for value in [
            "two words",
            "line\nbreak",
            "nonascii-\u{e9}",
            &"x".repeat(257),
        ] {
            assert!(build_identity(Some(value)).is_err(), "{value:?}");
        }
    }
}
