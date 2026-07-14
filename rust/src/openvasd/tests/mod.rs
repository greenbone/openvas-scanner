// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::BTreeMap, time::Duration};

use greenbone_scanner_framework::models;
use http::{Method, StatusCode};
use scannerlib::models::{Phase, Scan, Status, Target};
use serde_json::Value;

use crate::tests::test_builder::{OpenvasdInstance, Snapshottable, Test, WaitForStatusExt};

mod test_builder;

const GET: Method = Method::GET;
const HEAD: Method = Method::HEAD;
const POST: Method = Method::POST;
const DELETE: Method = Method::DELETE;

async fn check_head_endpoints(t: &OpenvasdInstance, write_snapshots: bool) {
    for endpoint in [
        "/health/alive",
        "/health/ready",
        "/health/started",
        "/scans",
        "/notus",
    ] {
        let response = t.request(HEAD, endpoint).await;
        response.assert_status(StatusCode::OK);
        if write_snapshots {
            response.snapshot();
        }
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

    // The full response body looks ugly, so we extract
    // it as a map to make the snapshot more readable
    let mut body = t
        .request(GET, "/scans/preferences")
        .await
        .body::<Vec<BTreeMap<String, Value>>>();
    // Then we sort by id to have some sort of order
    body.sort_by_key(|entry| entry["id"].to_string());
    body.snapshot("body");
}

// Runs against the local notus advisories in
// examples/feed/notus/...
#[tokio::test]
async fn notus() {
    let t = Test::new("notus").config("notus").await;

    t.request(Method::GET, "/notus").await.snapshot();

    t.request(POST, "/notus/test")
        .json(&["man-db-1.1.1"])
        .await
        .assert_status(StatusCode::OK)
        .snapshot();

    t.request(POST, "/notus/not_a_system")
        .json(&["man-db-1.1.1"])
        .await
        .assert_status(StatusCode::NOT_FOUND)
        .snapshot();

    check_head_endpoints(&t, false).await
}

impl Snapshottable for Vec<String> {}

#[tokio::test]
async fn up_and_running() {
    // In compose, the feed/notus paths are the defaults,
    // so we can just use basic.toml
    let t = Test::new("up_and_running").config("basic_feed").await;

    t.request(GET, "/vts")
        .wait_for(
            StatusCode::OK
                .with_timeout(Duration::from_millis(100))
                .with_intermediate_status(StatusCode::SERVICE_UNAVAILABLE),
        )
        .await
        .assert_status(StatusCode::OK) // DUH
        .body::<Vec<String>>()
        .snapshot("body");

    check_head_endpoints(&t, false).await
}

impl Snapshottable for models::Status {
    fn redactions() -> Vec<String> {
        vec![".start_time".into(), ".end_time".into()]
    }
}

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

    // We create the scan
    let scan_id = t
        .request(POST, "/scans")
        .json(scan.clone())
        .await
        .assert_status(StatusCode::CREATED)
        .body_str();

    // Check that after creation, the scan returned
    // from the API is what we'd expect
    let scan_path = format!("/scans/{scan_id}");
    let stored_scan = t
        .request(GET, &scan_path)
        .await
        .assert_status(StatusCode::OK)
        .body::<Scan>();
    assert_eq!(*stored_scan.scan_id, scan.scan_id);

    // Start the scan
    t.request(POST, &scan_path)
        .json(models::ScanAction::from(models::Action::Start))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Check the status of the scan
    let status_path = format!("{scan_path}/status");
    t.request(GET, &status_path)
        .await
        .assert_status(StatusCode::OK);

    t.request(GET, &status_path)
        .wait_for(Phase::Succeeded.with_timeout(Duration::from_secs(5)))
        .await
        .assert_status(StatusCode::OK)
        .body::<Status>()
        .snapshot("status");

    let results_path = format!("{scan_path}/results");
    let results = t
        .request(GET, &results_path)
        .await
        .assert_status(StatusCode::OK)
        .body::<Vec<models::Result>>();
    assert!(results.is_empty());

    t.request(GET, format!("{results_path}/0"))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    let empty_range = t
        .request(GET, format!("{results_path}?range=0-0"))
        .await
        .assert_status(StatusCode::OK)
        .body::<Vec<models::Result>>();
    assert_eq!(empty_range.len(), 0);

    t.request(DELETE, &scan_path)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    t.request(GET, &scan_path)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[cfg(feature = "requires-compose")]
mod requires_compose {
    use std::time::Duration;

    use http::StatusCode;

    use crate::tests::test_builder::WaitForStatusExt;

    use super::*;

    #[tokio::test]
    async fn up_and_running() {
        // In compose, the feed/notus paths are the defaults,
        // so we can just use basic.toml
        let t = Test::new("up_and_running_compose").config("basic").await;

        let vts = t
            .request(GET, "/vts")
            .wait_for(
                StatusCode::OK
                    .with_timeout(Duration::from_secs(1800))
                    .with_intermediate_status(StatusCode::SERVICE_UNAVAILABLE),
            )
            .await
            .assert_status(StatusCode::OK) // DUH
            .body::<Vec<String>>();
        assert!(
            vts.len() > 100_000,
            "expected more than 100000 VTs, got {}",
            vts.len()
        );

        check_head_endpoints(&t, false);
    }

    // Runs against the full notus advisories in the
    // compose setup.
    #[tokio::test]
    async fn notus() {
        let t = Test::new("notus_compose").config("notus_compose").await;

        // A full snapshot would be way overkill and not interesting, so we just
        // assert on the status code.
        t.request(Method::GET, "/notus")
            .await
            .assert_status(StatusCode::OK);

        // Maybe the snapshot of the response here is overkill. Figure out
        // whether this changes a lot. It might be nice to capture some
        // implicit information returned along with the request, so I want to
        // keep it for now, but remove this immediately (or redact) if it becomes
        // flaky or unstable.
        t.request(POST, "/notus/debian_10")
            .json(&["libzmq3-dev-4.3.0-4+deb10u1"])
            .await
            .assert_status(StatusCode::OK)
            .snapshot();

        t.request(POST, "/notus/not_a_system")
            .json(&["libzmq3-dev-4.3.0-4+deb10u1"])
            .await
            .assert_status(StatusCode::NOT_FOUND)
            .snapshot();
    }
}
