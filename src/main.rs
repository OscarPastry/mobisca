use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Mobile SDK Supply-Chain Risk Scanner
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an APK file for SDK risks
    Scan {
        /// Path to the APK file
        #[arg(value_name = "APK_PATH")]
        apk_path: PathBuf,

        /// Output format in JSON
        #[arg(long)]
        json: bool,
    },
    /// Diff two APKs for supply-chain risk drift
    Diff {
        /// Path to the baseline APK file
        #[arg(long, value_name = "BASELINE_APK")]
        baseline: PathBuf,

        /// Path to the current APK file
        #[arg(long, value_name = "CURRENT_APK")]
        current: PathBuf,

        /// Output format in JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { apk_path, json } => {
            println!("hello");
            println!("Scanning APK at: {:?}", apk_path);
            if *json {
                println!("(JSON output mode enabled)");
            }
        }
        Commands::Diff {
            baseline,
            current,
            json,
        } => {
            println!("hello");
            println!(
                "Diffing baseline: {:?} against current: {:?}",
                baseline, current
            );
            if *json {
                println!("(JSON output mode enabled)");
            }
        }
    }

    Ok(())
}
