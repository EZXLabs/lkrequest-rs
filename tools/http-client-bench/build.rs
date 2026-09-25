use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let lock_path = manifest_dir.join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(lock_path).expect("read workspace Cargo.lock");

    for (package, variable) in [
        ("lkrequest", "BENCH_LKREQUEST_VERSION"),
        ("lkh2", "BENCH_LKH2_VERSION"),
        ("hyper", "BENCH_HYPER_VERSION"),
        ("reqwest", "BENCH_REQWEST_VERSION"),
        ("tokio", "BENCH_TOKIO_VERSION"),
    ] {
        let version = package_version(&lock, package)
            .unwrap_or_else(|| panic!("find {package} version in Cargo.lock"));
        println!("cargo:rustc-env={variable}={version}");
    }
}

fn package_version<'a>(lock: &'a str, package: &str) -> Option<&'a str> {
    lock.split("[[package]]").find_map(|section| {
        let mut name = None;
        let mut version = None;
        for line in section.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("name = \"") {
                name = value.strip_suffix('"');
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = value.strip_suffix('"');
            }
        }
        (name == Some(package)).then_some(version).flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_package_version() {
        let lock = r#"
[[package]]
name = "hyper"
version = "1.11.1"
"#;
        assert_eq!(package_version(lock, "hyper"), Some("1.11.1"));
    }
}
