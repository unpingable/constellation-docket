//! No-argument resolver deriving one execution standing per presented AG
//! issuance from the owner-enrolled bounded grant. It never writes the grant.
use gwr_local::execution_standing::{read_bounded, OwnerTrust};
use gwr_local::execution_standing_grant::{derive_standing, enrollment_beside};
use gwr_runtime::governed_loop::ExecutionStandingRequestV1;
fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("standing-resolver-takes-no-arguments".into());
    }
    let trust = OwnerTrust::root();
    let executable = std::fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    let enrollment = enrollment_beside(&executable, &trust)?;
    let request: ExecutionStandingRequestV1 =
        serde_json::from_slice(&read_bounded(std::io::stdin())?).map_err(|e| e.to_string())?;
    // Reread the grant, revocation reference and use journal on every acceptance.
    let resolution = derive_standing(&enrollment, &trust, &request)?;
    println!(
        "{}",
        serde_json::to_string(&resolution).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("execution-standing refused: {error}");
        std::process::exit(2);
    }
}
