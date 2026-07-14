use std::path::Path;
use rusty_axml::parse_from_apk;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: check_axml <apk>");
        return;
    }
    let apk_path = Path::new(&args[1]);
    let axml = parse_from_apk(apk_path).unwrap();
    
    // Attempt to convert to string using quick-xml or similar if it's available
    // or just inspect it.
    println!("{:#?}", axml);
}
