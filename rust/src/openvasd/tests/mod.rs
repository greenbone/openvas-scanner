// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;

use http::{Method, StatusCode};
use serde_json::Value;

use crate::tests::test_builder::TestBuilder;

mod test_builder;

const GET: Method = Method::GET;
const HEAD: Method = Method::HEAD;
const POST: Method = Method::POST;

#[tokio::test]
async fn head_endpoints() {
    let t = TestBuilder::new("head_endpoints")
        .config("basic")
        .build()
        .await;

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
            .snapshot();
    }
}

#[tokio::test]
async fn get_scans_preferences() {
    let t = TestBuilder::new("get_scans_preferences")
        .config("basic")
        .build()
        .await;

    // The full response body looks ugly, so we extract
    // it as a map to make the snapshot more readable
    t.request(GET, "/scans/preferences")
        .await
        .custom_snapshot("body", |response| {
            let mut map =
                serde_json::from_str::<Vec<BTreeMap<String, Value>>>(&response.body.clone())
                    .unwrap();
            map.sort_by_key(|entry| entry["id"].to_string());
            map
        });
}

// Runs against the local notus advisories in
// examples/feed/notus/...
#[tokio::test]
async fn notus() {
    let t = TestBuilder::new("notus").config("notus").build().await;

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
}

#[cfg(feature = "requires-compose")]
mod requires_compose {
    use http::StatusCode;

    use super::*;

    // Runs against the full notus advisories in the
    // compose setup.
    #[tokio::test]
    async fn notus() {
        let t = TestBuilder::new("notus_compose")
            .config("notus_compose")
            .build()
            .await;

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
