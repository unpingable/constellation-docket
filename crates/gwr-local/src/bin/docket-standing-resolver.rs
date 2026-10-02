//! No-argument owner-enrolled resolver for the current governed-loop port.
use gwr_local::execution_standing::{
    project, read_bounded, read_owner_file, OwnerStandingProjectionV1, StandingEnrollmentV1,
};
use gwr_runtime::governed_loop::ExecutionStandingRequestV1;
fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("standing-resolver-takes-no-arguments".into());
    }
    let executable = std::fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    let enrollment_path = executable.with_file_name("docket-standing-resolver.enrollment.json");
    let enrollment: StandingEnrollmentV1 =
        serde_json::from_slice(&read_owner_file(&enrollment_path)?).map_err(|e| e.to_string())?;
    let request: ExecutionStandingRequestV1 =
        serde_json::from_slice(&read_bounded(std::io::stdin())?).map_err(|e| e.to_string())?;
    // Reopen on every acceptance: revocation/currentness belong to the owner snapshot.
    let owner: OwnerStandingProjectionV1 =
        serde_json::from_slice(&read_owner_file(&enrollment.projection)?)
            .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&project(&enrollment, &owner, &request)?)
            .map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("execution-standing refused: {error}");
        std::process::exit(2);
    }
}
