use crate::models::CveSignal;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const CACHE_FILE: &str = "osv_cache.json";

#[derive(Debug, Serialize, Deserialize, Default)]
struct OsvCache {
    entries: HashMap<String, Vec<CveSignal>>,
}

pub fn lookup_vulnerabilities(maven_package: &str) -> Vec<CveSignal> {
    let mut cache = load_cache();

    if let Some(cves) = cache.entries.get(maven_package) {
        return cves.clone();
    }

    // Query OSV if not cached
    let cves = match query_osv_api(maven_package) {
        Ok(results) => results,
        Err(e) => {
            println!("Failed to query OSV for {}: {}", maven_package, e);
            Vec::new()
        }
    };

    cache.entries.insert(maven_package.to_string(), cves.clone());
    save_cache(&cache);

    cves
}

fn query_osv_api(maven_package: &str) -> Result<Vec<CveSignal>> {
    let url = "https://api.osv.dev/v1/query";
    let body = serde_json::json!({
        "package": {
            "name": maven_package,
            "ecosystem": "Maven"
        }
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let res = client.post(url).json(&body).send()?;
    
    if !res.status().is_success() {
        return Err(anyhow::anyhow!("OSV API returned status: {}", res.status()));
    }
    
    let json_resp: serde_json::Value = res.json()?;
    let mut signals = Vec::new();

    if let Some(vulns) = json_resp.get("vulns").and_then(|v| v.as_array()) {
        for vuln in vulns {
            let id = vuln.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN").to_string();
            
            // Try to extract severity (often in database_specific)
            let mut severity = "MEDIUM".to_string(); // default
            if let Some(db_specific) = vuln.get("database_specific") {
                if let Some(sev) = db_specific.get("severity").and_then(|s| s.as_str()) {
                    severity = sev.to_uppercase();
                }
            }
            
            signals.push(CveSignal { id, severity });
        }
    }

    Ok(signals)
}

fn load_cache() -> OsvCache {
    if Path::new(CACHE_FILE).exists() {
        if let Ok(content) = fs::read_to_string(CACHE_FILE) {
            if let Ok(cache) = serde_json::from_str(&content) {
                return cache;
            }
        }
    }
    OsvCache::default()
}

fn save_cache(cache: &OsvCache) {
    if let Ok(content) = serde_json::to_string_pretty(cache) {
        let _ = fs::write(CACHE_FILE, content);
    }
}
