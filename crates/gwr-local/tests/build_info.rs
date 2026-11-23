use std::process::{Command, Stdio};

fn binaries() -> [(&'static str, &'static str); 3] {
    [
        ("docket", env!("CARGO_BIN_EXE_docket")),
        (
            "docket-standing-resolver",
            env!("CARGO_BIN_EXE_docket-standing-resolver"),
        ),
        (
            "docket-standing-grant-resolver",
            env!("CARGO_BIN_EXE_docket-standing-grant-resolver"),
        ),
    ]
}

#[test]
fn packaged_binaries_report_identity_before_enrollment_stdin_or_state_access() {
    for (name, binary) in binaries() {
        let output = Command::new(binary)
            .arg("--build-info")
            .current_dir("/")
            .env_clear()
            .env("DOCKET_SOURCE_COMMIT", "not-a-runtime-override")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(output.stderr.is_empty(), "{name}: {output:?}");
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(info["component"], name);
        assert_eq!(
            info["source_commit"].as_str(),
            gwr_local::build_info::SOURCE_COMMIT
        );
        assert_eq!(info["build_id"].as_str(), gwr_local::build_info::BUILD_ID);
        assert_eq!(info["debug_assertions"], cfg!(debug_assertions));
        for flag in ["--version", "-V"] {
            let output = Command::new(binary)
                .arg(flag)
                .current_dir("/")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(output.status.success(), "{name} {flag}: {output:?}");
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("{name} {}\n", gwr_local::build_info::VERSION_STRING)
            );
        }
    }
}

#[test]
fn identity_option_with_extra_arguments_cannot_skip_normal_validation() {
    for (name, binary) in binaries() {
        let output = Command::new(binary)
            .args(["--build-info", "extra"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name}: {output:?}");
        assert!(output.stdout.is_empty(), "{name}: {output:?}");
    }
}
