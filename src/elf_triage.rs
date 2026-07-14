use goblin::Object;
use std::collections::HashSet;

#[derive(Debug)]
pub struct ElfTriageResult {
    pub file_name: String,
    pub suspicious_imports: Vec<String>,
    pub high_entropy_sections: Vec<String>,
    pub extracted_urls: Vec<String>,
    pub extracted_ips: Vec<String>,
}

const SUSPICIOUS_IMPORTS: &[&str] = &[
    "dlopen", "ptrace", "system", "socket", "connect", "execve",
    "JNI_OnLoad", "FindClass", "GetMethodID",
];

pub fn triage_elf(file_name: String, bytes: &[u8]) -> Option<ElfTriageResult> {
    let mut result = ElfTriageResult {
        file_name,
        suspicious_imports: Vec::new(),
        high_entropy_sections: Vec::new(),
        extracted_urls: Vec::new(),
        extracted_ips: Vec::new(),
    };

    if let Ok(Object::Elf(elf)) = Object::parse(bytes) {
        // 1. Check imported symbols
        let mut imports = HashSet::new();
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                imports.insert(name);
            }
        }
        
        for &suspicious in SUSPICIOUS_IMPORTS {
            if imports.contains(suspicious) {
                result.suspicious_imports.push(suspicious.to_string());
            }
        }

        // 2. Calculate section entropy
        for section in &elf.section_headers {
            if section.sh_type == goblin::elf::section_header::SHT_PROGBITS {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if offset + size <= bytes.len() && size > 1024 {
                        let section_bytes = &bytes[offset..offset + size];
                        let entropy = calculate_entropy(section_bytes);
                        if entropy > 7.5 { // High entropy signal for packing/encryption
                            result.high_entropy_sections.push(name.to_string());
                        }
                    }
                }
            }
        }
    } else {
        return None;
    }

    // 3. Extract network strings (URLs/IPs)
    let (urls, ips) = crate::network::extract_network_strings(bytes);
    result.extracted_urls = urls.into_iter().collect();
    result.extracted_ips = ips.into_iter().collect();

    Some(result)
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}


