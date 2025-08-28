use std::{collections::HashMap, sync::Arc};

use greenbone_scanner_framework::models::{self, FixedVersion, VulnerablePackage};
use tokio::sync::RwLock;

use crate::{
    container_image_scanner::detection::OperatingSystem,
    notus::{HashsumProductLoader, Notus},
};

/// Some products have unique requirements that we have to generate somehow.
///
/// Some examples:
/// - NAME="openEuler" VERSION="24.03 (LTS-SP1)" -> openeuler_24.03_lts_sp1
fn generate_key(architecture: &str, os: &OperatingSystem) -> String {
    let normalize_euler_version = || {
        os.version
            .to_lowercase()
            .trim()
            .replace(" ", "_")
            .replace("(", "")
            .replace(")", "")
            .replace("-", "_")
    };
    let nos = os.name.to_lowercase();

    match (architecture, &nos as &str) {
        (_, "openeuler") => format!("openeuler_{}", normalize_euler_version()),
        (_, name) => format!("{}_{}", name, os.version_id),
    }
}

type NotusResults = HashMap<String, Vec<VulnerablePackage>>;

fn to_result(image: String, results: NotusResults) -> Vec<models::Result> {
    let hostname = Some(image);
    results
        .iter()
        .enumerate()
        .map(|(id, (oid, v))| {
            let messages = v
                .iter()
                .flat_map(|p| {
                    let versions = match &p.fixed_version {
                        FixedVersion::Single { version, specifier } => vec![format!(
                            "Fixed version:      {}{}-{}",
                            specifier, p.name, version
                        )],
                        FixedVersion::Range { start, end } => vec![
                            format!("Fixed version:      <={}-{}", p.name, start),
                            format!("Fixed version:      >={}-{}", p.name, end),
                        ],
                    };
                    let mut result = vec![
                        format!("Vulnerable package: {}", p.name),
                        format!("Installed version:  {}-{}", p.name, p.installed_version),
                    ];
                    result.extend(versions);
                    result
                })
                .collect::<Vec<_>>();
            models::Result {
                id,
                r_type: models::ResultType::Alarm,
                ip_address: None,
                hostname: hostname.clone(),
                oid: Some(oid.clone()),
                port: None,
                protocol: None,
                message: Some(messages.join("\n")),
                detail: None,
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Unexpected response format from Notus.")]
    UnExpectedResponseFormat,
}

type Oz = Notus<HashsumProductLoader>;

pub async fn vulnerabilities(
    products: Arc<RwLock<Oz>>,
    architecture: &str,
    image: String,
    os: &OperatingSystem,
    packages: Vec<String>,
) -> Result<Vec<models::Result>, Error> {
    let mut p = products.write_owned().await;
    let os = generate_key(architecture, os);

    //TODO: here jo
    let result = tokio::task::spawn_blocking(move || p.scan(&os, &packages))
        .await
        .unwrap();
    match result {
        Ok(x) => Ok(to_result(image, x)),
        Err(error) => {
            tracing::warn!(%error, "Unable to get results from Notus.");
            Err(Error::UnExpectedResponseFormat)
        }
    }
    //
    // let request = Request::new(architecture, os, packages);
    // let response = request.send(config).await?;
    // Ok(to_result(image, response))
}

#[cfg(test)]
mod key_generation_tests {
    use crate::container_image_scanner::detection::OperatingSystem;

    #[test]
    fn debian() {
        let os = OperatingSystem {
            name: "debian".to_owned(),
            version: "12 (bookworm)".to_owned(),
            version_id: "12".to_owned(),
        };
        let result = super::generate_key("", &os);
        assert_eq!("debian_12".to_owned(), result);
    }

    #[test]
    fn openeuler() {
        let os = OperatingSystem {
            name: "openEuler".to_owned(),
            version: "24.03 (LTS-SP1)".to_owned(),
            version_id: "24.03".to_owned(),
        };
        let result = super::generate_key("", &os);
        assert_eq!("openeuler_24.03_lts_sp1".to_owned(), result);
    }
}

#[cfg(test)]
mod notus_result_parsing_tests {

    #[test]
    fn parse_range_and_fixed() {
        let json = r#"
        {
            "1.1": [
                {
                    "name": "foo",
                    "installed_version": "1.2.3",
                    "fixed_version": {
                        "start": "1.2.2",
                        "end": "1.2.5"
                    }
                },
                {
                    "name": "bar",
                    "installed_version": "1.2.4",
                    "fixed_version": {
                        "version": "1.2.5",
                        "specifier": ">="
                    }
                }
            ]
        }
        "#;
        let results: super::NotusResults = serde_json::from_str(json).unwrap();
        assert_eq!(results.len(), 1);
        let result = super::to_result("oci://holla/die:waldfee".to_owned(), results);
        insta::assert_ron_snapshot!(result);
    }
}
