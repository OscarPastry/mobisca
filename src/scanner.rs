use std::path::Path;
use anyhow::{Context, Result};

pub fn process_apk(apk_path: &Path) -> Result<()> {
    println!("Extracting and parsing APK: {:?}", apk_path);

    let axml = rusty_axml::parse_from_apk(apk_path).context("Failed to parse AXML from APK")?;
    
    // We will convert it to a string. `Axml` probably implements Display.
    // Or it might have a to_string() or similar method.
    let xml_string = format!("{:#?}", axml);
    
    println!("Successfully parsed AndroidManifest.xml!");
    println!("Manifest preview: {:.200}...", xml_string.trim());
    
    Ok(())
}
