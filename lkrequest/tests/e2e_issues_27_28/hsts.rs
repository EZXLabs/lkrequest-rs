use std::time::Duration;

use lkrequest::{DynamicHsts, HstsPolicy};

#[test]
fn issue27_4_no_include_subdomains_means_exact_host() {
    let hsts = DynamicHsts::new();
    hsts.record_sts("example.test", "max-age=60");
    assert!(hsts.should_upgrade("example.test"));
    assert!(
        !hsts.should_upgrade("sub.example.test"),
        "includeSubDomains was not declared"
    );
}

#[test]
fn issue27_4_dynamic_entry_expires() {
    let hsts = DynamicHsts::new();
    hsts.record_sts("example.test", "max-age=1; includeSubDomains");
    assert!(hsts.should_upgrade("example.test"));
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        !hsts.should_upgrade("example.test"),
        "entry survived max-age=1"
    );
    assert!(!hsts.should_upgrade("sub.example.test"));
}

#[test]
fn control_hsts_include_subdomains_and_explicit_removal() {
    let hsts = DynamicHsts::new();
    hsts.record_sts("example.test", "max-age=60; includeSubDomains");
    assert!(hsts.should_upgrade("sub.example.test"));
    assert!(!hsts.should_upgrade("notexample.test"));
    hsts.record_sts("example.test", "max-age=0");
    assert!(!hsts.should_upgrade("example.test"));
    assert!(!hsts.should_upgrade("sub.example.test"));
}
