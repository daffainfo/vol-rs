//! The `vol` command line tool.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::process::ExitCode;

/// A symbol file is hundreds of thousands of small allocations and a scan is a
/// steady stream of larger ones, which is exactly the workload a general
/// purpose allocator handles least well.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    match vol_rs::cli::run_cli(&argv) {
        Ok(code) => ExitCode::from(code as u8),
        // A requirement the run could not meet has already been described in
        // full, so all that is left to say is which ones they were.
        Err(vol_rs::VolatilityError::Unsatisfied(paths)) => {
            let listed: Vec<String> = paths.iter().map(|path| format!("'{path}'")).collect();
            eprintln!(
                "Unable to validate the plugin requirements: [{}]",
                listed.join(", ")
            );
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(1)
        }
    }
}
