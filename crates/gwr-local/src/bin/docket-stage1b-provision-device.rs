use gwr_local::stage1b_vm::device::provision;
use std::path::Path;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [output] = arguments.as_slice() else {
        eprintln!("stage1b-device-provision-usage: OUTPUT");
        std::process::exit(2);
    };
    match provision(Path::new(output)) {
        Ok(identity) => {
            println!("device_id={}", identity.id);
            println!("backing_identity={}", identity.backing);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
