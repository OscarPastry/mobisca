use crate::models::MaintenanceStatus;
use anyhow::Result;

pub fn check_health(repo: &str, token: Option<&String>) -> MaintenanceStatus {
    match query_github_repo(repo, token) {
        Ok(status) => status,
        Err(e) => {
            println!("  [!] Failed to query GitHub for {}: {}", repo, e);
            MaintenanceStatus::Unknown
        }
    }
}

fn query_github_repo(repo: &str, token: Option<&String>) -> Result<MaintenanceStatus> {
    let url = format!("https://api.github.com/repos/{}", repo);

    let client = reqwest::blocking::Client::builder()
        .user_agent("mobile-risk-scanner/0.1.0")
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut request = client.get(&url);
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let res = request.send()?;
    if !res.status().is_success() {
        return Err(anyhow::anyhow!(
            "GitHub API returned status: {}",
            res.status()
        ));
    }

    let json_resp: serde_json::Value = res.json()?;

    if let Some(pushed_at_str) = json_resp.get("pushed_at").and_then(|v| v.as_str()) {
        // ponytail: fast lexicographical date check avoids `chrono` bloat. Upgrade path: standard libs or explicit chrono if timezone math needed.
        let current_year = 2026; // hardcoded for MVP ease, could use std::time
        let pushed_year: i32 = pushed_at_str[0..4].parse().unwrap_or(0);
        
        if current_year - pushed_year >= 2 {
            return Ok(MaintenanceStatus::Abandoned);
        } else if current_year - pushed_year == 1 {
            return Ok(MaintenanceStatus::Stale);
        } else {
            return Ok(MaintenanceStatus::Active);
        }
    }

    Ok(MaintenanceStatus::Unknown)
}
