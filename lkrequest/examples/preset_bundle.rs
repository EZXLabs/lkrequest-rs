//! Export or validate a complete profile document without making requests.

use lkrequest::preset::{self, PresetDocument};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, path] if command == "export" => {
            let document = PresetDocument::from_preset("chrome-157", &preset::chrome_157())?;
            std::fs::write(path, document.to_json_string()?)?;
            println!("Exported {} to {path}", document.name());
        }
        [command, path] if command == "check" => {
            let document = PresetDocument::from_json_file(path)?;
            let name = document.name().to_owned();
            lkrequest::Client::builder()
                .preset(document.into_preset())
                .try_build()?;
            println!("Valid profile: {name}");
        }
        _ => return Err("usage: preset_bundle export|check <path>".into()),
    }
    Ok(())
}
