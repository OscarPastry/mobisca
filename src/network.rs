use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
struct BlocklistConfig {
    domains: Vec<String>,
}

pub fn load_blocklist() -> HashSet<String> {
    let content = std::fs::read_to_string("blocklist.json").unwrap_or_default();
    if content.is_empty() {
        return HashSet::new();
    }
    if let Ok(config) = serde_json::from_str::<BlocklistConfig>(&content) {
        return config.domains.into_iter().collect();
    }
    HashSet::new()
}

pub fn extract_network_strings(data: &[u8]) -> (HashSet<String>, HashSet<String>) {
    static URL_REGEX: OnceLock<Regex> = OnceLock::new();
    static IP_REGEX: OnceLock<Regex> = OnceLock::new();

    let url_regex = URL_REGEX.get_or_init(|| {
        Regex::new(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/[a-zA-Z0-9.-]*)*").unwrap()
    });
    let ip_regex = IP_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap()
    });

    let mut urls = HashSet::new();
    let mut ips = HashSet::new();

    let text = String::from_utf8_lossy(data);

    for cap in url_regex.captures_iter(&text) {
        urls.insert(cap[0].to_string());
    }

    for cap in ip_regex.captures_iter(&text) {
        let ip = &cap[0];
        // Filter obvious false positives
        if !ip.starts_with("0.") && !ip.starts_with("255.") && !ip.starts_with("127.") {
            ips.insert(ip.to_string());
        }
    }

    (urls, ips)
}

pub fn check_against_blocklist(
    urls: &HashSet<String>,
    ips: &HashSet<String>,
    blocklist: &HashSet<String>,
) -> Vec<String> {
    let mut flagged = Vec::new();
    for url in urls {
        for bad_domain in blocklist {
            if url.contains(bad_domain) {
                flagged.push(url.clone());
                break;
            }
        }
    }
    for ip in ips {
        if blocklist.contains(ip) {
            flagged.push(ip.clone());
        }
    }
    flagged
}
