// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {

    use models::{FixedPackage, FixedVersion, Specifier};
    use notus::{error::Error, loader::fs::FSProductLoader, notus::Notus};

    #[test]
    fn test_notus() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = FSProductLoader::new(path.clone()).unwrap();
        let mut notus = Notus::new(loader, false);

        let packages = vec![
            "gitlab-ce-16.0.1".to_string(), // vul
            "bar-7.6.5".to_string(),        // no vul
            "grafana-8.5.25".to_string(),   // no vul
            "grafana8-8.5.23".to_string(),  // vul
            "grafana9-9.4.7".to_string(),   // vul
            "foo-1.2.3".to_string(),        // no vul
        ];

        let results = notus.scan("debian_10", &packages).unwrap();
        assert_eq!(results.len(), 2);

        let result1 = &results["1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100"];
        let result2 = &results["1.3.6.1.4.1.25623.1.1.7.2.2023.0988598199100"];

        assert_eq!(result1.len(), 1);
        let vul_pkg = &result1[0];
        assert_eq!(vul_pkg.name, "gitlab-ce".to_string());
        assert_eq!(vul_pkg.installed_version, "16.0.1".to_string());
        assert!(matches!(
            &vul_pkg.fixed_version,
            FixedVersion::Range { start, end } if start == "16.0.0" && end == "16.0.7"
        ));

        assert_eq!(result2.len(), 2);
        for vul_pkg in result2 {
            match vul_pkg.name.as_str() {
                "grafana8" => {
                    assert_eq!(vul_pkg.installed_version, "8.5.23".to_string());
                    assert!(matches!(
                        &vul_pkg.fixed_version,
                        FixedVersion::Single { version, specifier } if version == "8.5.24" && matches!(specifier, Specifier::GE)
                    ));
                }
                "grafana9" => {
                    assert_eq!(vul_pkg.installed_version, "9.4.7".to_string());
                    assert!(matches!(
                        &vul_pkg.fixed_version,
                        FixedVersion::Range { start, end } if start == "9.4.0" && end == "9.4.9"
                    ));
                }
                _ => panic!("Unexpected vulnerable package: {}", vul_pkg.name),
            }
        }
    }

    #[test]
    fn test_err_package_parse_error() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = FSProductLoader::new(path.clone()).unwrap();
        let mut notus = Notus::new(loader, false);

        let pkg_name = "wepofkewf~.124.sdefpo3-_~s#";

        let packages = vec![pkg_name.to_string()];

        let os = "debian_10";
        assert!(
            matches!(notus.scan(os, &packages).expect_err("Should fail"), Error::PackageParseError(p) if p == pkg_name)
        );
    }

    #[test]
    fn test_err_product_parse_error() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = FSProductLoader::new(path.clone()).unwrap();
        let mut notus = Notus::new(loader, false);

        let packages = vec![];

        let os = "debian_10_product_parse_err";
        assert!(
            matches!(notus.scan(os, &packages).expect_err("Should fail"), Error::VulnerabilityTestParseError(p, FixedPackage::ByRange { name, range }) if p == os && name == "gitlab-ce" && range.start == "?" && range.end == "=" )
        );
    }
}
