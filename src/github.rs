use crate::models::MaintenanceStatus;
use anyhow::Result;
use chrono::{DateTime, Utc};

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
        return Err(anyhow::anyhow!("GitHub API returned status: {}", res.status()));
    }
    
    let json_resp: serde_json::Value = res.json()?;
    
    if let Some(pushed_at_str) = json_resp.get("pushed_at").and_then(|v| v.as_str()) {
        let pushed_date = pushed_at_str.parse::<DateTime<Utc>>()?;
        let now = Utc::now();
        let duration = now.signed_duration_since(pushed_date);
        
        let days_since_push = duration.num_days();
        
        if days_since_push > 365 {
            return Ok(MaintenanceStatus::Abandoned);
        } else if days_since_push > 180 {
            return Ok(MaintenanceStatus::Stale);
        } else {
            return Ok(MaintenanceStatus::Active);
        }
    }
    
    Ok(MaintenanceStatus::Unknown)
}
