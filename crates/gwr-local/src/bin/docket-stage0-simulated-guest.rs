//! Experimental fixed-function simulated guest process.

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = gwr_local::stage0_guest::proxy::run_simulator(&arguments) {
        if gwr_local::stage0_guest::proxy::is_injected_process_death(&error) {
            std::process::exit(86);
        }
        eprintln!("{error}");
        std::process::exit(64);
    }
}
