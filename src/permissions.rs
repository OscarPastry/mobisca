use std::collections::HashSet;

const SENSITIVE_PERMISSIONS: &[&str] = &[
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
];

pub fn get_sensitive_permissions_in_app(manifest_bytes: &[u8]) -> HashSet<String> {
    let mut found = HashSet::new();
    
    // Convert binary XML to lossy string to extract string pool entries
    let raw_text_utf8 = String::from_utf8_lossy(manifest_bytes);
    
    // Also convert to UTF-16LE lossy since AXML often uses it for strings
    let u16_chars: Vec<u16> = manifest_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let raw_text_utf16 = String::from_utf16_lossy(&u16_chars);
    
    for &perm in SENSITIVE_PERMISSIONS {
        if raw_text_utf8.contains(perm) || raw_text_utf16.contains(perm) {
            found.insert(perm.to_string());
        }
    }
    
    found
}

pub fn check_scope_creep(category: &str, app_permissions: &HashSet<String>) -> Vec<String> {
    let mut flags = Vec::new();

    // Mapping of SDK category -> permissions that might be reasonably justified
    let mut allowed_sensitive = HashSet::new();
    
    match category {
        "Ads" => {
            // Ads sometimes request location, though highly scrutinized
            allowed_sensitive.insert("android.permission.ACCESS_COARSE_LOCATION");
            allowed_sensitive.insert("android.permission.ACCESS_FINE_LOCATION");
        }
        "Analytics" | "Analytics/Backend" => {
            // Usually just internet/network state, no sensitive ones
        }
        "Crash Reporting" => {
            // Usually just internet/network state
        }
        "Networking" => {
            // Just network
        }
        "Platform" => {
            // e.g. Google Play Services may need location or phone state
            allowed_sensitive.insert("android.permission.ACCESS_COARSE_LOCATION");
            allowed_sensitive.insert("android.permission.ACCESS_FINE_LOCATION");
            allowed_sensitive.insert("android.permission.READ_PHONE_STATE");
        }
        _ => {}
    }

    // Flag any sensitive app permission that this SDK category does not justify
    for perm in app_permissions {
        if !allowed_sensitive.contains(perm.as_str()) {
            flags.push(format!("App requests {} which is unjustified for an SDK in '{}' category", perm, category));
        }
    }

    flags
}
