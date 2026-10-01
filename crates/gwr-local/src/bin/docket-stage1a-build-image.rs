use gwr_local::stage1a_vm::build::{build_guest, QualificationFaultV1};
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [output] = arguments.as_slice() else {
        return Err("stage1a-image-builder-usage: OUTPUT".to_owned());
    };
    let built = build_guest(Path::new(output), QualificationFaultV1::None)?;
    println!("guest_build={}", built.guest_build);
    println!("image_build={}", built.image_build);
    println!("rustc_identity={}", built.rustc_identity);
    Ok(())
}
