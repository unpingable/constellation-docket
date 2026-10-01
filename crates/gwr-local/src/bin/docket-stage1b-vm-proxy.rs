//! Experimental fixed-profile Stage-1B VM-backed executor entrypoint.

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = gwr_local::stage1b_vm::run_proxy(&arguments) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
