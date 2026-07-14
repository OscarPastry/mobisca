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

use crate::models::{AppRiskProfile, RiskConfig, SdkRiskProfile};

pub fn scan_apk(apk_path: &Path, github_token: Option<&String>) -> Result<AppRiskProfile> {
    // 1. Load configs
    let sdks_json = std::fs::read_to_string("sdks.json")
        .context("Failed to read sdks.json seed file")?;
    let config: SdksConfig = serde_json::from_str(&sdks_json)
        .context("Failed to parse sdks.json")?;
        
    let risk_config_str = std::fs::read_to_string("risk_config.toml")
        .unwrap_or_else(|_| "[weights]\ncve_critical_weight=40\n".to_string());
    let risk_config: RiskConfig = toml::from_str(&risk_config_str)
        .context("Failed to parse risk_config.toml")?;
    let mut found_sdks = std::collections::HashSet::new();
    
    let blocklist = crate::network::load_blocklist();
    let mut global_urls = std::collections::HashSet::new();
    let mut global_ips = std::collections::HashSet::new();

    // 2. Parse AXML (ensure it's valid)
    let _ = rusty_axml::parse_from_apk(apk_path);

    let mut file = File::open(apk_path).context("Failed to open APK file")?;
    let mut archive = ZipArchive::new(file).context("Failed to read ZIP archive")?;

    // 2.5 Extract App Permissions from AndroidManifest.xml
    let mut manifest_bytes = Vec::new();
    if let Ok(mut manifest_file) = archive.by_name("AndroidManifest.xml") {
        manifest_file.read_to_end(&mut manifest_bytes)?;
    }
    let app_permissions = crate::permissions::get_sensitive_permissions_in_app(&manifest_bytes);
    
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
    
    let mut app_profile = AppRiskProfile::new(
        apk_path.to_string_lossy().to_string(), 
        Vec::new(),
        app_permissions.iter().cloned().collect(),
        Vec::new() // Placeholder, updated later
    );
    
    for sdk_name in found_sdks {
        let sdk_def = config.sdks.iter().find(|s| s.name == sdk_name).unwrap();
        let mut profile = SdkRiskProfile::new(
            sdk_def.name.clone(),
            sdk_def.vendor.clone(),
            sdk_def.namespace.clone(),
        );
        
        if let Some(pkg) = &sdk_def.maven_package {
            profile.cves = crate::osv::lookup_vulnerabilities(pkg);
        }
        if let Some(repo) = &sdk_def.github_repo {
            profile.maintenance_status = crate::github::check_health(repo, github_token);
        }
        
        profile.permission_creep_flags = crate::permissions::check_scope_creep(&sdk_def.category, &app_permissions);
        
        // For MVP, we attribute native binary flags based on naming heuristic
        for res in &elf_triage_results {
            let name_lower = res.file_name.to_lowercase();
            let vendor_lower = sdk_def.vendor.to_lowercase();
            if name_lower.contains(&vendor_lower) || name_lower.contains(&sdk_def.name.to_lowercase()) {
                profile.suspicious_binary_imports.extend(res.suspicious_imports.clone());
                profile.packed_binaries.extend(res.high_entropy_sections.clone());
                
                let urls_set = res.extracted_urls.iter().cloned().collect();
                let ips_set = res.extracted_ips.iter().cloned().collect();
                let flagged = crate::network::check_against_blocklist(&urls_set, &ips_set, &blocklist);
                profile.malicious_endpoints.extend(flagged);
            }
        }
        
        profile.calculate_score(&risk_config);
        app_profile.sdks.push(profile);
    }
    
    let flagged_global = crate::network::check_against_blocklist(&global_urls, &global_ips, &blocklist);
    
    // Recalculate App score
    app_profile = AppRiskProfile::new(
        apk_path.to_string_lossy().to_string(), 
        app_profile.sdks,
        app_profile.global_permissions,
        flagged_global
    );

    Ok(app_profile)
}
