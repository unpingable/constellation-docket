//! Resolver process used behind a measured zero-argument deployment launcher.

use gwr_local::local_execution_standing::{read_config, resolve};
use gwr_runtime::governed_loop::ExecutionStandingRequestV1;
use std::io::Read as _;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("refused/error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [flag, value] = args.as_slice() else {
        return Err(
            "usage: docket-local-standing-resolver --config ABSOLUTE_PATH | --config-fd 3"
                .to_owned(),
        );
    };
    let path = if flag == "--config" {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("local-standing-config-path-not-absolute".to_owned());
        }
        path
    } else if flag == "--config-fd" && value == "3" {
        PathBuf::from("/proc/self/fd/3")
    } else {
        return Err("local-standing-resolver-arguments".to_owned());
    };
    let config = read_config(&path)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("local-standing-request-read:{e}"))?;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err("local-standing-request-size".to_owned());
    }
    let request: ExecutionStandingRequestV1 =
        serde_json::from_slice(&bytes).map_err(|e| format!("local-standing-request:{e}"))?;
    let response = resolve(&config.state_database, &config.operator, &request)?;
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|e| format!("local-standing-response:{e}"))?
    );
    Ok(())
}
