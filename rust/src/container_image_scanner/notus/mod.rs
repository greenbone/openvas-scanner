use std::collections::HashMap;

use greenbone_scanner_framework::models;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::container_image_scanner::{Config, detection::OperatingSystem};

/// Some products have unique requirements that we have to generate somehow.
///
/// Some examples:
/// - NAME="openEuler" VERSION="24.03 (LTS-SP1)" -> openeuler_24.03_lts_sp1
pub fn generate_key(architecture: &str, os: &OperatingSystem) -> String {
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

pub type NotusResults = HashMap<String, Vec<VulnerablePackage>>;

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VulnerablePackage {
    pub name: String,
    pub installed_version: String,
    pub fixed_version: FixedVersion,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum FixedVersion {
    Single { version: String, specifier: String },
    Range { start: String, end: String },
}

impl Default for FixedVersion {
    fn default() -> Self {
        Self::Range {
            start: Default::default(),
            end: Default::default(),
        }
    }
}

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
    #[error("Certificate is not available.")]
    CertificateNotAvailabe,
    #[error("Certificate is not a pem file.")]
    CertificateNotPem,
    #[error("Unable to build http client.")]
    UnableToBuildClient,
    #[error("Unable to send packages to Notus.")]
    UnableToSend,
    #[error("Unexpected status code from Notus.")]
    UnExpectedStatusCode,
    #[error("Unexpected response format from Notus.")]
    UnExpectedResponseFormat,
}

struct Request {
    key: String,
    packages: Vec<String>,
}

impl Request {
    pub fn new(architecture: &str, os: &OperatingSystem, packages: Vec<String>) -> Self {
        Self {
            key: generate_key(architecture, os),
            packages,
        }
    }

    pub async fn send(&self, config: &Config) -> Result<NotusResults, Error> {
        let mut client = reqwest::Client::builder();
        if let Some(cert) = config.notus.certificate.as_ref() {
            let bytes = match tokio::fs::read(cert).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error=%e, certificate = ?cert.to_str(), "Not available.");
                    return Err(Error::CertificateNotAvailabe);
                }
            };
            match reqwest::Certificate::from_pem(&bytes) {
                Ok(x) => client = client.add_root_certificate(x),
                Err(e) => {
                    tracing::warn!(error=%e, certificate = ?cert.to_str(), "Not a pem file");
                    return Err(Error::CertificateNotPem);
                }
            }
        }
        let client = match client.build() {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, "Unable to generate client.");
                return Err(Error::UnableToBuildClient);
            }
        };
        let address = format!("{}/{}", config.notus.address, self.key);
        let response = match client.post(&address).json(&self.packages).send().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(address, error=%e, "Unable to send packages to client.");
                return Err(Error::UnableToSend);
            }
        };
        let result = match response.error_for_status() {
            Ok(x) => x,
            Err(e) => match e.status() {
                Some(StatusCode::NOT_FOUND) => {
                    tracing::info!(error=%e, product=self.key, "Not supported by Notus. Returning no vulnerabilities.");
                    return Ok(HashMap::new());
                }
                None | Some(_) => {
                    tracing::warn!(error=%e, "Unable to send packages to client.");
                    return Err(Error::UnExpectedStatusCode);
                }
            },
        };

        let result = match result.json().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, "Unable to parse result.");
                return Err(Error::UnExpectedResponseFormat);
            }
        };

        Ok(result)
    }
}

pub async fn vulnerabilities(
    config: &Config,
    architecture: &str,
    image: String,
    os: &OperatingSystem,
    packages: Vec<String>,
) -> Result<Vec<models::Result>, Error> {
    let request = Request::new(architecture, os, packages);
    let response = request.send(config).await?;
    Ok(to_result(image, response))
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
pub mod notus_fake {
    use std::{fs::File, path::Path};

    use super::NotusResults;

    pub type OsResults = (String, NotusResults);

    pub struct NotusMock {
        pub server: mockito::ServerGuard,
        // the mocks must be stored otherwise the Server will return 501
        _mocks: Vec<mockito::Mock>,
    }

    impl NotusMock {
        pub fn result_mock(
            server: &mut mockito::ServerGuard,
            key: &str,
            result: &NotusResults,
        ) -> Vec<mockito::Mock> {
            vec![
                server
                    .mock("POST", &format!("/notus/{key}") as &str)
                    .with_header("Content-Type", "application/json")
                    .with_body(serde_json::to_string(result).unwrap())
                    .with_status(200)
                    .create(),
            ]
        }

        pub async fn serve(results: &[OsResults]) -> Self {
            let mut server = mockito::Server::new_async().await;
            let _mocks = results
                .iter()
                .flat_map(|(key, response)| Self::result_mock(&mut server, key, response))
                .collect();
            Self { server, _mocks }
        }

        fn read_test_data_dir() -> Vec<(String, NotusResults)> {
            const NOTUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/notus");
            let root = Path::new(NOTUS_DIR);
            std::fs::read_dir(root)
                .unwrap()
                .filter_map(|x| x.ok())
                .map(|x| x.path())
                .filter(|x| x.is_dir())
                .flat_map(|dir| {
                    std::fs::read_dir(&dir)
                        .into_iter()
                        .flat_map(|entries| entries.filter_map(|e| e.ok()))
                        .map(|file_entry| file_entry.path())
                        .filter(|p| p.extension().map_or_else(|| false, |ext| ext == "json"))
                        .map(|json_path| {
                            let os_key = json_path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap()
                                .to_string();
                            let file = File::open(&json_path).unwrap();
                            let content = serde_json::from_reader(file).unwrap();
                            (os_key, content)
                        })
                })
                .collect()
        }

        pub async fn default() -> Self {
            let results = Self::read_test_data_dir();
            Self::serve(&results).await
        }

        pub fn address(&self) -> String {
            self.server.host_with_port()
        }
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
