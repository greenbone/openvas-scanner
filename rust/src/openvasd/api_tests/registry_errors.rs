use std::time::Duration;

use scannerlib::models::{self, Phase, Scan, Status, Target};
use serde::{Deserialize, Serialize};

use super::test_builder::{Snapshottable, Test, WaitForStatusExt};
use crate::container_image_scanner::DockerRegistryV2Mock;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct RegistryResults(Vec<models::Result>);

impl Snapshottable for RegistryResults {
    fn prepare(&mut self) {
        let address = lazy_regex::regex!(r"127\.0\.0\.1:\d+");
        for result in &mut self.0 {
            for value in [&mut result.hostname, &mut result.message]
                .into_iter()
                .flatten()
            {
                *value = address.replace_all(value, "registry").into_owned();
            }
        }
    }
}

fn registry_scan(id: &str, hosts: Vec<String>) -> Scan {
    Scan {
        scan_id: id.into(),
        target: Target {
            hosts,
            ..Default::default()
        },
        scan_preferences: vec![("registry_allow_insecure", "true").into()],
        ..Default::default()
    }
}

#[tokio::test]
async fn registry_errors_are_reported() {
    let t = Test::new("registry_errors")
        .config("cis_registry_errors")
        .await;
    let mut registry = mockito::Server::new_async().await;
    let _auth = registry.mock("GET", "/v2/").with_status(503).create();
    let mut image = DockerRegistryV2Mock::supported_images().remove(0);
    let blob_registry =
        DockerRegistryV2Mock::serve_images(&[image.clone()], &[200, 200, 200, 200, 200, 200, 503])
            .await;
    image.registry = blob_registry.address().into();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable = listener.local_addr().unwrap();
    drop(listener);

    for (id, host) in [
        (
            "auth-503",
            format!("oci://{}/repository:latest", registry.host_with_port()),
        ),
        ("blob-503", image.to_string()),
        ("invalid-image", String::new()),
        ("unreachable-catalog", format!("oci://{unreachable}")),
        (
            "unreachable-repository",
            format!("oci://{unreachable}/repository"),
        ),
        (
            "unreachable-image",
            format!("oci://{unreachable}/repository:latest"),
        ),
    ] {
        let scan = t
            .create_container_image_scan(registry_scan(id, vec![host]))
            .await;
        scan.start().await;
        scan.wait_for(Phase::Succeeded.with_timeout(Duration::from_secs(10)))
            .await
            .body::<Status>()
            .snapshot("status");
        scan.get_results()
            .await
            .body::<RegistryResults>()
            .snapshot("results");
        scan.delete().await;
    }
}

#[tokio::test]
async fn registry_error_does_not_interrupt_other_images() {
    let t = Test::new("mixed_registry_results")
        .config("cis_registry_errors")
        .await;
    let mut registry = mockito::Server::new_async().await;
    let _auth = registry.mock("GET", "/v2/").with_status(503).create();
    let healthy_registry = DockerRegistryV2Mock::serve_default().await;
    let mut hosts = vec![format!("oci://{}", registry.host_with_port())];
    hosts.extend(
        DockerRegistryV2Mock::supported_images()
            .into_iter()
            .map(|mut image| {
                image.registry = healthy_registry.address().into();
                image.to_string()
            }),
    );
    let scan = t
        .create_container_image_scan(registry_scan("mixed", hosts))
        .await;
    scan.start().await;
    scan.wait_for(Phase::Succeeded.with_timeout(Duration::from_secs(10)))
        .await
        .body::<Status>()
        .snapshot("status");
    scan.get_result(0..=0)
        .await
        .body::<RegistryResults>()
        .snapshot("discovery_error");
    scan.delete().await;
}
