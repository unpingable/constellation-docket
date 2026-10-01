fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = gwr_local::stage1d_session::run(&arguments) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
