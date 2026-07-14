use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod scanner;
mod models;

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

        /// Optional GitHub Personal Access Token to avoid API rate limits
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,
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

        /// Optional GitHub Personal Access Token to avoid API rate limits
        #[arg(long, env = "GITHUB_TOKEN")]
        github_token: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { apk_path, json, github_token } => {
            println!("Scanning APK at: {:?}", apk_path);
            if *json {
                println!("(JSON output mode enabled)");
            }
            if let Some(_) = github_token {
                println!("(GitHub token provided for elevated rate limits)");
            }

            scanner::process_apk(apk_path)?;
        }
        Commands::Diff {
            baseline,
            current,
            json,
            github_token,
        } => {
            println!(
                "Diffing baseline: {:?} against current: {:?}",
                baseline, current
            );
            if *json {
                println!("(JSON output mode enabled)");
            }
            if let Some(_) = github_token {
                println!("(GitHub token provided for elevated rate limits)");
            }
        }
    }

    Ok(())
}
