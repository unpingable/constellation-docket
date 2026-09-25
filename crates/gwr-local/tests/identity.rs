//! Every shipped executable answers `--version` and `--build-info` without
//! state, configuration or stdin.

use std::process::{Command, Stdio};

const BINARIES: [(&str, &str); 2] = [
    ("docket", env!("CARGO_BIN_EXE_docket")),
    (
        "docket-local-standing-resolver",
        env!("CARGO_BIN_EXE_docket-local-standing-resolver"),
    ),
];

fn run(program: &str, flag: &str) -> (String, String) {
    let output = Command::new(program)
        .arg(flag)
        .stdin(Stdio::null())
        .output()
        .expect("run identity probe");
    assert!(output.status.success(), "{program} {flag} failed");
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn version_and_build_info_agree_for_every_shipped_binary() {
    let recorded = option_env!("DOCKET_SOURCE_COMMIT").filter(|value| !value.is_empty());
    for (component, program) in BINARIES {
        let (version, stderr) = run(program, "--version");
        assert!(stderr.is_empty());
        let commit = recorded.unwrap_or("unrecorded");
        assert_eq!(
            version,
            format!("{component} {} {commit}\n", env!("CARGO_PKG_VERSION"))
        );
        let (info, stderr) = run(program, "--build-info");
        assert!(stderr.is_empty());
        let value: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(value["schema"], "docket.build-info/v1");
        assert_eq!(value["component"], component);
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["source_commit"].as_str(), recorded);
        assert!(value["rustc"].as_str().unwrap().starts_with("rustc "));
    }
}
