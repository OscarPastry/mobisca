use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct RiskWeights {
    pub cve_critical_weight: u32,
    pub cve_high_weight: u32,
    pub cve_medium_weight: u32,
    pub cve_low_weight: u32,
    pub abandoned_sdk_weight: u32,
    pub stale_sdk_weight: u32,
    pub permission_creep_weight: u32,
    pub suspicious_binary_import_weight: u32,
    pub packed_binary_weight: u32,
    pub malicious_network_endpoint_weight: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RiskConfig {
    pub weights: RiskWeights,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            weights: RiskWeights {
                cve_critical_weight: 40,
                cve_high_weight: 20,
                cve_medium_weight: 10,
                cve_low_weight: 5,
                abandoned_sdk_weight: 30,
                stale_sdk_weight: 15,
                permission_creep_weight: 25,
                suspicious_binary_import_weight: 20,
                packed_binary_weight: 20,
                malicious_network_endpoint_weight: 50,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CveSignal {
    pub id: String,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MaintenanceStatus {
    Active,
    Stale,     // No commits in 6-12 months
    Abandoned, // No commits in 12+ months
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SdkRiskProfile {
    pub name: String,
    pub vendor: String,
    pub namespace: String,

    // Extracted signals (Features 2.2 - 2.6)
    pub cves: Vec<CveSignal>,
    pub maintenance_status: MaintenanceStatus,
    pub permission_creep_flags: Vec<String>,
    pub suspicious_binary_imports: Vec<String>,
    pub packed_binaries: Vec<String>,
    pub malicious_endpoints: Vec<String>,

    // Composite final calculated score (0-100+)
    pub risk_score: u32,
}

impl SdkRiskProfile {
    pub fn new(name: String, vendor: String, namespace: String) -> Self {
        Self {
            name,
            vendor,
            namespace,
            cves: Vec::new(),
            maintenance_status: MaintenanceStatus::Unknown,
            permission_creep_flags: Vec::new(),
            suspicious_binary_imports: Vec::new(),
            packed_binaries: Vec::new(),
            malicious_endpoints: Vec::new(),
            risk_score: 0,
        }
    }

    /// Calculates and applies the risk score based on the given configuration.
    pub fn calculate_score(&mut self, config: &RiskConfig) {
        let mut score = 0;

        for cve in &self.cves {
            score += match cve.severity.to_lowercase().as_str() {
                "critical" => config.weights.cve_critical_weight,
                "high" => config.weights.cve_high_weight,
                "medium" | "moderate" => config.weights.cve_medium_weight,
                "low" => config.weights.cve_low_weight,
                _ => config.weights.cve_medium_weight,
            };
        }

        match self.maintenance_status {
            MaintenanceStatus::Abandoned => score += config.weights.abandoned_sdk_weight,
            MaintenanceStatus::Stale => score += config.weights.stale_sdk_weight,
            _ => {}
        }

        score += self.permission_creep_flags.len() as u32 * config.weights.permission_creep_weight;
        score += self.suspicious_binary_imports.len() as u32
            * config.weights.suspicious_binary_import_weight;
        score += self.packed_binaries.len() as u32 * config.weights.packed_binary_weight;
        score += self.malicious_endpoints.len() as u32
            * config.weights.malicious_network_endpoint_weight;

        // Cap at 100 for normalization, or allow it to exceed depending on design preference.
        // For MVP, capping at 100 makes it a clean percentage.
        self.risk_score = score.min(100);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppRiskProfile {
    pub app_path: String,
    pub sdks: Vec<SdkRiskProfile>,
    pub total_risk_score: u32,
    pub global_permissions: Vec<String>,
    pub global_malicious_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct RiskDrift {
    pub sdk_name: String,
    pub baseline_score: u32,
    pub current_score: u32,
}

#[derive(Debug, Serialize, Clone)]
pub struct DiffReport {
    pub baseline_apk: String,
    pub current_apk: String,
    pub added_sdks: Vec<String>,
    pub removed_sdks: Vec<String>,
    pub risk_score_changes: Vec<RiskDrift>,
    pub added_sensitive_permissions: Vec<String>,
}

impl AppRiskProfile {
    pub fn new(
        app_path: String,
        sdks: Vec<SdkRiskProfile>,
        global_permissions: Vec<String>,
        global_malicious_endpoints: Vec<String>,
    ) -> Self {
        // App score could be average of SDKs, or max, or simple sum.
        // A simple max risk score across all SDKs highlights the weakest link.
        let total_risk_score = sdks.iter().map(|s| s.risk_score).max().unwrap_or(0);

        Self {
            app_path,
            sdks,
            total_risk_score,
            global_permissions,
            global_malicious_endpoints,
        }
    }
}
