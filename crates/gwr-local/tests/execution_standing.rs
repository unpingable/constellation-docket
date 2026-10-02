use gwr_local::execution_standing::{project, OwnerStandingProjectionV1, StandingEnrollmentV1};
use gwr_runtime::governed_loop::{ExecutionStandingRequestV1, ExecutionStandingStatusV1};
#[test]
fn owner_projection_preserves_exact_bindings_and_refuses_noncurrent_or_substituted_authority() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/execution-standing-v1.json")).unwrap();
    let request: ExecutionStandingRequestV1 =
        serde_json::from_value(vector["request"].clone()).unwrap();
    let enrollment = StandingEnrollmentV1 {
        schema: "docket.execution-standing-enrollment/v1".into(),
        principal: "release-operator".into(),
        projection: "/etc/constellation-m2/standing.json".into(),
    };
    let owner = OwnerStandingProjectionV1 {
        schema: "docket.owner-execution-standing-projection/v1".into(),
        principal: enrollment.principal.clone(),
        generation: "one".into(),
        resolution: serde_json::from_value(vector["resolution"].clone()).unwrap(),
    };
    assert_eq!(
        project(&enrollment, &owner, &request).unwrap(),
        owner.resolution
    );
    for status in [
        ExecutionStandingStatusV1::Absent,
        ExecutionStandingStatusV1::Revoked,
        ExecutionStandingStatusV1::Superseded,
        ExecutionStandingStatusV1::Expired,
    ] {
        let mut changed = owner.clone();
        changed.resolution.status = status;
        assert!(project(&enrollment, &changed, &request).is_err());
    }
    let mut changed = owner.clone();
    changed.principal = "other-owner".into();
    assert!(project(&enrollment, &changed, &request).is_err());
    for field in [
        "issuance",
        "campaign",
        "occurrence",
        "subject",
        "scope",
        "execution_standing",
    ] {
        let mut value = serde_json::to_value(&owner).unwrap();
        value["resolution"][field] = serde_json::json!(request.issuance.spend);
        let changed = serde_json::from_value(value).unwrap();
        assert!(project(&enrollment, &changed, &request).is_err(), "{field}");
    }
    for now in [99, 200] {
        let mut changed = request.clone();
        changed.now_unix_ms = now;
        assert!(project(&enrollment, &owner, &changed).is_err());
    }
}
#[test]
fn unenrolled_cli_refuses_without_emitting_standing() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_docket-standing-resolver"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}
