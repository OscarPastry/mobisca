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

    // 1. Load SDK definitions and blocklist
    let sdks_json = std::fs::read_to_string("sdks.json")
        .context("Failed to read sdks.json seed file")?;
    let config: SdksConfig = serde_json::from_str(&sdks_json)
        .context("Failed to parse sdks.json")?;
    let mut found_sdks = std::collections::HashSet::new();
    
    let blocklist = crate::network::load_blocklist();
    let mut global_urls = std::collections::HashSet::new();
    let mut global_ips = std::collections::HashSet::new();

    // 2. Parse AXML (ensure it's valid)
    match rusty_axml::parse_from_apk(apk_path) {
        Ok(_) => println!("Successfully parsed AndroidManifest.xml!"),
        Err(e) => println!("Warning: Failed to parse AXML: {:?}", e),
    }

    let mut file = File::open(apk_path).context("Failed to open APK file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read ZIP archive")?;

    // 2.5 Extract App Permissions from AndroidManifest.xml
    let mut manifest_bytes = Vec::new();
    if let Ok(mut manifest_file) = archive.by_name("AndroidManifest.xml") {
        manifest_file.read_to_end(&mut manifest_bytes)?;
    }
    let app_permissions = crate::permissions::get_sensitive_permissions_in_app(&manifest_bytes);
    if !app_permissions.is_empty() {
        println!("App requests {} sensitive permissions.", app_permissions.len());
    }
    
    let (axml_urls, axml_ips) = crate::network::extract_network_strings(&manifest_bytes);
    global_urls.extend(axml_urls);
    global_ips.extend(axml_ips);

    let mut elf_triage_results = Vec::new();

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
            
            let (dex_urls, dex_ips) = crate::network::extract_network_strings(&dex_bytes);
            global_urls.extend(dex_urls);
            global_ips.extend(dex_ips);
        } else if file.name().ends_with(".so") && file.name().contains("lib/") {
            let mut so_bytes = Vec::new();
            file.read_to_end(&mut so_bytes)?;
            if let Some(res) = crate::elf_triage::triage_elf(file.name().to_string(), &so_bytes) {
                elf_triage_results.push(res);
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
            
            let creep_flags = crate::permissions::check_scope_creep(&sdk.category, &app_permissions);
            let mut creep_text = String::new();
            if !creep_flags.is_empty() {
                creep_text = format!(" [Scope Creep: {} flags]", creep_flags.len());
            }

            println!("- {}{}{}{} (Namespace: {})", sdk.name, cves_text, health_text, creep_text, sdk.namespace);
        }
    }
    println!("----------------------------");

    println!("\n--- Native Binary (.so) Triage ---");
    if elf_triage_results.is_empty() {
        println!("No native libraries found.");
    } else {
        for res in elf_triage_results {
            println!("File: {}", res.file_name);
            if !res.suspicious_imports.is_empty() {
                println!("  [!] Suspicious Imports: {:?}", res.suspicious_imports);
            }
            if !res.high_entropy_sections.is_empty() {
                println!("  [!] High Entropy Sections (Packed?): {:?}", res.high_entropy_sections);
            }
            if !res.extracted_urls.is_empty() || !res.extracted_ips.is_empty() {
                println!("  [i] Extracted {} URLs, {} IPs", res.extracted_urls.len(), res.extracted_ips.len());
            }
            
            let urls_set = res.extracted_urls.iter().cloned().collect();
            let ips_set = res.extracted_ips.iter().cloned().collect();
            let flagged = crate::network::check_against_blocklist(&urls_set, &ips_set, &blocklist);
            if !flagged.is_empty() {
                println!("  [!] Blocklisted Endpoints in binary: {:?}", flagged);
            }
        }
    }
    println!("----------------------------------");

    println!("\n--- Global Network Endpoints ---");
    let flagged_global = crate::network::check_against_blocklist(&global_urls, &global_ips, &blocklist);
    if !flagged_global.is_empty() {
        println!("[!] Blocklisted Endpoints found in DEX/Manifest: {:?}", flagged_global);
    } else {
        println!("Extracted {} URLs and {} IPs globally, none on blocklist.", global_urls.len(), global_ips.len());
    }
    println!("--------------------------------");

    Ok(())
}
