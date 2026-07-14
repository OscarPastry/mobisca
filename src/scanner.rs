use std::fs::File;
use std::io::Read;
use std::path::Path;
use anyhow::{Context, Result};
use zip::ZipArchive;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct SdkDef {
    pub namespace: String,
    pub name: String,
    pub vendor: String,
    pub category: String,
    pub github_repo: Option<String>,
    pub maven_package: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SdksConfig {
    pub sdks: Vec<SdkDef>,
}

pub fn process_apk(apk_path: &Path, github_token: Option<&String>) -> Result<()> {
    println!("Extracting and parsing APK: {:?}", apk_path);

    // 1. Load SDK definitions
    let sdks_json = std::fs::read_to_string("sdks.json")
        .context("Failed to read sdks.json seed file")?;
    let config: SdksConfig = serde_json::from_str(&sdks_json)
        .context("Failed to parse sdks.json")?;
    let mut found_sdks = std::collections::HashSet::new();

    // 2. Parse AXML
    match rusty_axml::parse_from_apk(apk_path) {
        Ok(_) => println!("Successfully parsed AndroidManifest.xml!"),
        Err(e) => println!("Warning: Failed to parse AXML: {:?}", e),
    }

    // 3. Unzip and scan .dex files for namespaces
    let file = File::open(apk_path).context("Failed to open APK file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read ZIP archive")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name().ends_with(".dex") {
            let mut dex_bytes = Vec::new();
            file.read_to_end(&mut dex_bytes)?;
            
            // Fast binary scan for MVP: convert to lossy string and check for namespace matches
            let dex_str = String::from_utf8_lossy(&dex_bytes);
            
            for sdk in &config.sdks {
                let dot_namespace = &sdk.namespace;
                let slash_namespace = sdk.namespace.replace(".", "/");
                
                // Match either formatting pattern typically found in DEX strings
                if dex_str.contains(dot_namespace) || dex_str.contains(&slash_namespace) {
                    found_sdks.insert(sdk.name.clone());
                }
            }
        }
    }
    
    println!("\n--- Detected SDKs & CVEs ---");
    if found_sdks.is_empty() {
        println!("No known SDKs detected.");
    } else {
        for sdk_name in found_sdks {
            let sdk = config.sdks.iter().find(|s| s.name == sdk_name).unwrap();
            let mut cves_text = String::new();
            
            if let Some(pkg) = &sdk.maven_package {
                let cves = crate::osv::lookup_vulnerabilities(pkg);
                if !cves.is_empty() {
                    cves_text = format!(" [{} known CVEs]", cves.len());
                }
            }
            
            let mut health_text = String::new();
            if let Some(repo) = &sdk.github_repo {
                let health = crate::github::check_health(repo, github_token);
                health_text = format!(" [Health: {:?}]", health);
            }

            println!("- {}{}{} (Namespace: {})", sdk.name, cves_text, health_text, sdk.namespace);
        }
    }
    println!("----------------------------");

    Ok(())
}
