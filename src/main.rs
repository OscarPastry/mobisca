use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod scanner;
mod models;
mod osv;
mod github;
mod permissions;
mod elf_triage;
mod network;

/// Mobile SDK Supply-Chain Risk Scanner
#[derive(Parser)]
#[command(name = "mobisca", author, version, about, long_about = None)]
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
            let profile = scanner::scan_apk(apk_path, github_token.as_ref())?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                println!("Scanning APK at: {:?}", apk_path);
                if let Some(_) = github_token {
                    println!("(GitHub token provided for elevated rate limits)");
                }
                print_report(&profile);
            }
        }
        Commands::Diff {
            baseline,
            current,
            json,
            github_token,
        } => {
            let baseline_profile = scanner::scan_apk(baseline, github_token.as_ref())?;
            let current_profile = scanner::scan_apk(current, github_token.as_ref())?;
            
            if *json {
                let report = build_diff_report(&baseline_profile, &current_profile);
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Diffing baseline: {:?} against current: {:?}", baseline, current);
                if let Some(_) = github_token {
                    println!("(GitHub token provided for elevated rate limits)");
                }
                print_diff_report(&baseline_profile, &current_profile);
            }
        }
    }

    Ok(())
}

fn print_report(profile: &crate::models::AppRiskProfile) {
    println!("\n=== Composite Risk Scores ===");
    if profile.sdks.is_empty() {
        println!("No known SDKs detected.");
    } else {
        for sdk in &profile.sdks {
            println!("- {} (Score: {}/100)", sdk.name, sdk.risk_score);
            if !sdk.cves.is_empty() { println!("    * CVEs: {}", sdk.cves.len()); }
            if sdk.maintenance_status != crate::models::MaintenanceStatus::Active && sdk.maintenance_status != crate::models::MaintenanceStatus::Unknown {
                println!("    * Health: {:?}", sdk.maintenance_status);
            }
            if !sdk.permission_creep_flags.is_empty() { println!("    * Scope Creep: {} flags", sdk.permission_creep_flags.len()); }
            if !sdk.suspicious_binary_imports.is_empty() || !sdk.packed_binaries.is_empty() { println!("    * Native Binary Risks Detected"); }
            if !sdk.malicious_endpoints.is_empty() { println!("    * Malicious Endpoints: {}", sdk.malicious_endpoints.len()); }
        }
    }
    if !profile.global_malicious_endpoints.is_empty() {
        println!("\n[!] Blocklisted Endpoints found globally: {:?}", profile.global_malicious_endpoints);
    }
    
    println!("-----------------------------");
    println!("Overall App Risk Score: {}/100", profile.total_risk_score);
    println!("=============================\n");
}

fn print_diff_report(baseline: &crate::models::AppRiskProfile, current: &crate::models::AppRiskProfile) {
    println!("\n=== Supply-Chain Drift Report ===");
    println!("Baseline: {}", baseline.app_path);
    println!("Current:  {}", current.app_path);
    println!("---------------------------------");
    
    use std::collections::HashSet;
    let b_sdks: HashSet<_> = baseline.sdks.iter().map(|s| s.name.clone()).collect();
    let c_sdks: HashSet<_> = current.sdks.iter().map(|s| s.name.clone()).collect();
    
    let added: Vec<_> = c_sdks.difference(&b_sdks).collect();
    let removed: Vec<_> = b_sdks.difference(&c_sdks).collect();
    
    if !added.is_empty() {
        println!("[!] Newly Added SDKs:");
        for s in &added { println!("  + {}", s); }
    }
    if !removed.is_empty() {
        println!("[i] Removed SDKs:");
        for s in &removed { println!("  - {}", s); }
    }
    
    let mut drift_found = false;
    for c_sdk in &current.sdks {
        if let Some(b_sdk) = baseline.sdks.iter().find(|s| s.name == c_sdk.name) {
            if c_sdk.risk_score > b_sdk.risk_score {
                println!("[!] Risk Increased for {}: {} -> {}", c_sdk.name, b_sdk.risk_score, c_sdk.risk_score);
                drift_found = true;
            } else if c_sdk.risk_score < b_sdk.risk_score {
                println!("[i] Risk Decreased for {}: {} -> {}", c_sdk.name, b_sdk.risk_score, c_sdk.risk_score);
                drift_found = true;
            }
        }
    }
    
    let b_perms: HashSet<_> = baseline.global_permissions.iter().cloned().collect();
    let c_perms: HashSet<_> = current.global_permissions.iter().cloned().collect();
    let added_perms: Vec<_> = c_perms.difference(&b_perms).collect();
    if !added_perms.is_empty() {
        println!("\n[!] New Sensitive Permissions Requested:");
        for p in &added_perms { println!("  + {}", p); }
    }
    
    if added.is_empty() && removed.is_empty() && !drift_found && added_perms.is_empty() {
        println!("No supply-chain risk drift detected.");
    }
    println!("=================================\n");
}

fn build_diff_report(baseline: &crate::models::AppRiskProfile, current: &crate::models::AppRiskProfile) -> crate::models::DiffReport {
    use std::collections::HashSet;
    let b_sdks: HashSet<_> = baseline.sdks.iter().map(|s| s.name.clone()).collect();
    let c_sdks: HashSet<_> = current.sdks.iter().map(|s| s.name.clone()).collect();
    
    let added_sdks = c_sdks.difference(&b_sdks).cloned().collect();
    let removed_sdks = b_sdks.difference(&c_sdks).cloned().collect();
    
    let mut risk_score_changes = Vec::new();
    for c_sdk in &current.sdks {
        if let Some(b_sdk) = baseline.sdks.iter().find(|s| s.name == c_sdk.name) {
            if c_sdk.risk_score != b_sdk.risk_score {
                risk_score_changes.push(crate::models::RiskDrift {
                    sdk_name: c_sdk.name.clone(),
                    baseline_score: b_sdk.risk_score,
                    current_score: c_sdk.risk_score,
                });
            }
        }
    }
    
    let b_perms: HashSet<_> = baseline.global_permissions.iter().cloned().collect();
    let c_perms: HashSet<_> = current.global_permissions.iter().cloned().collect();
    let added_sensitive_permissions = c_perms.difference(&b_perms).cloned().collect();

    crate::models::DiffReport {
        baseline_apk: baseline.app_path.clone(),
        current_apk: current.app_path.clone(),
        added_sdks,
        removed_sdks,
        risk_score_changes,
        added_sensitive_permissions,
    }
}
