// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    nasl::{Loader, test_utils::TestBuilder},
    notus::{HashsumProductLoader, Notus},
};

fn make_test_path(sub_components: &[&str]) -> std::path::PathBuf {
    let mut path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_owned();
    for component in sub_components {
        path = path.join(component);
    }
    path.to_owned()
}

pub fn setup_loader() -> HashsumProductLoader {
    HashsumProductLoader::new(Loader::from_feed_path(make_test_path(&["data", "notus"])))
}

fn setup() -> Arc<Mutex<Notus<HashsumProductLoader>>> {
    let loader = setup_loader();
    Arc::new(Mutex::new(Notus::new(loader, false)))
}

#[test]
fn test_notus() {
    let notus = setup();
    let mut t = TestBuilder::from_notus(notus);

    let mut expected = HashMap::new();
    expected.insert(
        "1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100".to_string(),
        "Vulnerable package:   gitlab-ce\nInstalled version:    gitlab-ce-16.0.1\nFixed version:      < gitlab-ce-16.0.0\nFixed version:      >=gitlab-ce-16.0.7"
            .to_string(),
    );
    expected.insert(
        "1.3.6.1.4.1.25623.1.1.7.2.2023.0988598199100".to_string(),
        "Vulnerable package:   grafana\nInstalled version:    grafana-8.5.23\nFixed version:      >=grafana-8.5.24\n\nVulnerable package:   grafana8\nInstalled version:    grafana8-8.5.23\nFixed version:      >=grafana8-8.5.24"
            .to_string(),
    );

    t.run(r#"notus(product: "debian_10", pkg_list: "gitlab-ce-16.0.1, grafana-8.5.23, grafana8-8.5.23");"#);

    t.check_no_errors();
    let results = t.results();
    assert_eq!(results.len(), 1);
    let result = results[0].as_ref().unwrap();
    match result {
        crate::nasl::NaslValue::Array(items) => {
            let mut actual = HashMap::new();
            for item in items {
                match item {
                    crate::nasl::NaslValue::Dict(dict) => {
                        let oid = match dict.get("oid") {
                            Some(crate::nasl::NaslValue::String(value)) => value.clone(),
                            _ => panic!("Expected string oid in notus result"),
                        };
                        let message = match dict.get("message") {
                            Some(crate::nasl::NaslValue::String(value)) => value.clone(),
                            _ => panic!("Expected string message in notus result"),
                        };
                        actual.insert(oid, message);
                    }
                    _ => panic!("Expected dict items in notus result array"),
                }
            }
            assert_eq!(actual, expected);
        }
        _ => panic!("Expected array result from notus"),
    }
}
