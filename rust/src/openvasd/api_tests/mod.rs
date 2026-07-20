// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::BTreeMap, time::Duration};

use greenbone_scanner_framework::models;
use http::{Method, StatusCode};
use scannerlib::models::{Phase, Scan, Status, Target};
use serde_json::Value;
use test_builder::{OpenvasdInstance, Snapshottable, Test, WaitForStatusExt};

mod test_builder;
mod test_scan;

const GET: Method = Method::GET;
const HEAD: Method = Method::HEAD;
const POST: Method = Method::POST;

impl OpenvasdInstance {
    #[cfg(feature = "requires-compose")]
    async fn assert_mtls(&self) {
        self.request(HEAD, "/scans")
            .await
            .assert_status(StatusCode::OK)
            .assert_header("authentication", "mTLS")
            .assert_header("api-version", "1")
            .assert_header_exists("feed-version")
            .assert_header_exists("date");
    }
}

async fn check_head_endpoints(t: &OpenvasdInstance, write_snapshots: bool) {
    for endpoint in [
        "/health/alive",
        "/health/ready",
        "/health/started",
        "/scans",
        "/notus",
    ] {
        t.request(HEAD, endpoint)
            .await
            .assert_status(StatusCode::OK)
            .snapshot_if(write_snapshots);
    }
}

#[tokio::test]
async fn head_endpoints() {
    let t = Test::new("head_endpoints").config("basic").await;
    check_head_endpoints(&t, true).await
}

impl Snapshottable for Vec<BTreeMap<String, Value>> {}

#[tokio::test]
async fn get_scans_preferences() {
    let t = Test::new("get_scans_preferences").config("basic").await;

    let mut body = t
        .request(GET, "/scans/preferences")
        .await
        .assert_status(StatusCode::OK)
        .body::<Vec<BTreeMap<String, Value>>>();

    // The full response body looks ugly, so we extract
    // it as a map to make the snapshot more readable
    // Then we sort by id to have some sort of order
    body.sort_by_key(|entry| entry["id"].to_string());
    body.snapshot("body");
}

async fn notus_test(
    t: &OpenvasdInstance,
    package_name: &str,
    system_name: &str,
    write_get_snapshot: bool,
) {
    t.request(Method::GET, "/notus")
        .await
        .assert_status(StatusCode::OK)
        .snapshot_if(write_get_snapshot);

    t.request(POST, format!("/notus/{}", system_name))
        .json(vec![package_name.to_string()])
        .await
        .assert_status(StatusCode::OK)
        .snapshot();

    t.request(POST, "/notus/not_a_system")
        .json(vec![package_name.to_string()])
        .await
        .assert_status(StatusCode::NOT_FOUND)
        .snapshot();

    check_head_endpoints(t, false).await
}

// Runs against the local notus advisories in
// examples/feed/notus/...
#[tokio::test]
async fn notus() {
    let t = Test::new("notus").config("notus").await;
    notus_test(&t, "man-db-1.1.1", "test", true).await
}

impl Snapshottable for Vec<String> {}

async fn get_vts_test(
    t: &OpenvasdInstance,
    timeout: Duration,
    write_snapshots: bool,
) -> Vec<String> {
    let body = t
        .request(GET, "/vts")
        .wait_for(
            StatusCode::OK
                .with_timeout(timeout)
                .with_intermediate_status(StatusCode::SERVICE_UNAVAILABLE),
        )
        .await
        .assert_status(StatusCode::OK) // DUH
        .body::<Vec<String>>()
        .snapshot_if(write_snapshots, "body");

    check_head_endpoints(t, false).await;
    body
}

// TODO: This test is currently broken and
// we see the plugin_feed_info.inc in the snapshot.
// Fix this.
#[tokio::test]
#[tracing_test::traced_test]
async fn get_vts() {
    let t = Test::new("get_vts").config("basic_feed").await;
    get_vts_test(&t, Duration::from_millis(100), true).await;
}

impl Snapshottable for models::Status {
    fn redactions() -> Vec<String> {
        vec![".start_time".into(), ".end_time".into()]
    }
}

impl Snapshottable for Vec<models::Result> {}

#[tokio::test]
async fn scan_lifecycle() {
    let t = Test::new("scan_lifecycle").config("basic_feed").await;
    let scan = Scan {
        scan_id: "scan-lifecycle".to_string(),
        target: Target {
            hosts: vec!["127.0.0.1".to_string()],
            alive_test_methods: vec![models::AliveTestMethods::ConsiderAlive],
            ..Default::default()
        },
        ..Default::default()
    };

    let scan = t.create_scan(scan).await;
    scan.start().await;
    scan.status().await;
    scan.wait_for(Phase::Succeeded.with_timeout(Duration::from_secs(5)))
        .await
        .body::<Status>()
        .snapshot("status");

    let results = scan.get_results().await.body::<Vec<models::Result>>();
    assert!(results.is_empty());

    scan.get_result(0)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    let empty_range = scan
        .get_result(0..0)
        .await
        .assert_status(StatusCode::OK)
        .body::<Vec<models::Result>>();
    assert_eq!(empty_range.len(), 0);

    scan.delete().await;
    scan.get().await.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "extremely slow"]
async fn container_image_scan_docker_hub_ubuntu_24_04() {
    const IMAGE: &str = "oci://registry-1.docker.io/library/ubuntu:24.04";

    let t = Test::new("container_image_scan_docker_hub_ubuntu_24_04")
        .config("basic")
        .await;
    let scan = Scan {
        scan_id: "container-image-ubuntu-24-04".to_string(),
        target: Target {
            hosts: vec![IMAGE.to_string()],
            ..Default::default()
        },
        ..Default::default()
    };

    let scan = t.create_container_image_scan(scan).await;
    scan.start().await;
    scan.wait_for(Phase::Succeeded.with_timeout(Duration::from_secs(600)))
        .await
        .body::<Status>();
    scan.delete().await;
}

#[cfg(feature = "requires-compose")]
mod requires_compose {
    use std::path::PathBuf;

    use super::*;
    use super::{test_builder::Snapshot, test_scan::TestScan};

    fn read_test_scan(name: &str) -> Scan {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("data/tests/scanner/scans")
            .join(format!("{name}.json"));

        let contents = std::fs::read_to_string(&path).unwrap();
        let mut scan: Scan = serde_json::from_str(&contents).unwrap();
        scan.scan_id = name.to_string();
        scan
    }

    async fn scan_flow(
        scan: &TestScan<'_>,
        timeout: Duration,
        write_status_snapshot: bool,
    ) -> Snapshot<Vec<models::Result>> {
        scan.start().await;
        scan.status().await;
        let status = scan
            .wait_for(Phase::Succeeded.with_timeout(timeout))
            .await
            .body::<Status>()
            .snapshot_if(write_status_snapshot, "status");
        check_host_info(&status);
        scan.get_results().await.body::<Vec<models::Result>>()
    }

    // I am leaving this in here for feature parity with the
    // hurl smoketests for now but if this ever becomes flaky
    // or annoying to maintain we should replace it with better
    // assertions
    fn check_host_info(status: &Status) {
        let host_info = status
            .host_info
            .as_ref()
            .expect("succeeded scan status should include host_info");
        assert!(status.start_time.is_some(), "start_time should be set");
        assert!(status.end_time.is_some(), "end_time should be set");
        assert!(host_info.all > 0, "host_info.all should be greater than 0");
        assert_eq!(host_info.excluded, 0);
        assert_eq!(host_info.dead, 0);
        assert_eq!(host_info.alive, host_info.all);
        assert_eq!(host_info.queued, 0);
        assert_eq!(host_info.finished, host_info.all);
    }

    // I am leaving this in here for feature parity with the
    // hurl smoketests for now but if this ever becomes flaky
    // or annoying to maintain we should replace it with better
    // assertions
    async fn check_scan_results(scan: &TestScan<'_>, results: Snapshot<Vec<models::Result>>) {
        let result_count = results.len();
        assert!(
            result_count > 3,
            "expected more than 3 results, got {result_count}"
        );

        scan.get_result(result_count)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        let empty_range = scan
            .get_result(result_count..result_count)
            .await
            .assert_status(StatusCode::OK)
            .body::<Vec<models::Result>>();
        assert_eq!(empty_range.len(), 0);
        let full_range = scan
            .get_result(0..result_count)
            .await
            .assert_status(StatusCode::OK)
            .body::<Vec<models::Result>>();
        assert_eq!(full_range.len(), result_count);
        let first_two = scan
            .get_result(0..1)
            .await
            .assert_status(StatusCode::OK)
            .body::<Vec<models::Result>>();
        assert_eq!(first_two.len(), 2);
        let result = scan
            .get_result(2)
            .await
            .assert_status(StatusCode::OK)
            .body::<models::Result>();
        assert_eq!(result.id, 2);
    }

    async fn check_scan_flow(scan: &TestScan<'_>, timeout: Duration, write_status_snapshot: bool) {
        let results = scan_flow(scan, timeout, write_status_snapshot).await;
        check_scan_results(scan, results).await;
        scan.delete().await;
        scan.get().await.assert_status(StatusCode::NOT_FOUND);
    }

    #[derive(Clone, Copy)]
    enum ScanEndpoint {
        Default,
        ContainerImage,
    }

    async fn run_full_scan_test(
        test_name: &str,
        scan_name: &str,
        endpoint: ScanEndpoint,
        write_status_snapshot: bool,
    ) {
        let t = Test::new(test_name).config("openvas").await;
        t.assert_mtls().await;
        let scan = read_test_scan(scan_name);
        let scan = match endpoint {
            ScanEndpoint::Default => t.create_scan(scan).await,
            ScanEndpoint::ContainerImage => t.create_container_image_scan(scan).await,
        };

        check_scan_flow(&scan, Duration::from_secs(3600), write_status_snapshot).await;
    }

    // Runs against the full notus advisories in the
    // compose setup.
    #[tokio::test]
    async fn notus() {
        let t = Test::new("notus_compose").config("openvas").await;
        // A full snapshot would be way overkill and not interesting, so we just
        // assert on the status code.
        notus_test(&t, "libzmq3-dev-4.3.0-4+deb10u1", "debian_10", false).await;
    }

    #[tokio::test]
    async fn mtls_head_scans() {
        let t = Test::new("compose_mtls_head_scans").config("openvas").await;
        t.assert_mtls().await;
    }

    // TODO: This test is currently broken and
    // we see the plugin_feed_info.inc in the snapshot.
    // Fix this.
    #[tokio::test]
    async fn get_vts() {
        let t = Test::new("compose_get_vts").config("openvas").await;

        let vts = get_vts_test(&t, Duration::from_secs(1800), false).await;

        assert!(
            vts.len() > 100_000,
            "expected more than 100000 VTs, got {}",
            vts.len()
        );
    }

    #[tokio::test]
    async fn scan_victim_simple_auth_ssh() {
        run_full_scan_test(
            "scan_victim_simple_auth_ssh",
            "victim-simple-auth-ssh",
            ScanEndpoint::Default,
            true,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "extremely slow"]
    async fn scan_victim_discovery() {
        run_full_scan_test(
            "scan_victim_discovery",
            "victim-discovery",
            ScanEndpoint::Default,
            false,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "extremely slow"]
    async fn scan_victim_full_and_fast() {
        run_full_scan_test(
            "scan_victim_full_and_fast",
            "victim-full-and-fast",
            ScanEndpoint::Default,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn container_image_scan_local_registry_full() {
        run_full_scan_test(
            "container_image_scan_local_registry_full",
            "local-registry-full",
            ScanEndpoint::ContainerImage,
            true,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "extremely slow"]
    async fn container_image_scan_local_registry_openeuler() {
        run_full_scan_test(
            "container_image_scan_local_registry_openeuler",
            "local-registry-openeuler",
            ScanEndpoint::ContainerImage,
            false,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "extremely slow"]
    async fn container_scan_local_registry_victim() {
        run_full_scan_test(
            "container_scan_local_registry_victim",
            "local-registry-victim",
            ScanEndpoint::ContainerImage,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn stop_scan_victim_simple_auth_ssh() {
        let t = Test::new("stop_scan_victim_simple_auth_ssh")
            .config("openvas")
            .await;
        t.assert_mtls().await;
        let scan = t
            .create_scan(read_test_scan("victim-simple-auth-ssh"))
            .await;

        scan.start().await;
        scan.wait_for(Phase::Running.with_timeout(Duration::from_secs(240)))
            .await;

        scan.stop().await;
        scan.wait_for(Phase::Stopped.with_timeout(Duration::from_secs(10)))
            .await;

        scan.start().await;
        scan.wait_for(Phase::Running.with_timeout(Duration::from_secs(60)))
            .await;

        scan.stop().await;
        scan.wait_for(Phase::Stopped.with_timeout(Duration::from_secs(10)))
            .await;
        scan.delete().await;
    }
}
