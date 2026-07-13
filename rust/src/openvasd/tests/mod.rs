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

    t.request(HEAD, "/health/alive").await.snapshot();
    t.request(HEAD, "/health/ready").await.snapshot();
    t.request(HEAD, "/scans").await.snapshot();
    t.request(HEAD, "/notus").await.snapshot();
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

    t.request_json(POST, "/notus/test", &["man-db-1.1.1"])
        .await
        .assert_status(StatusCode::OK)
        .snapshot();

    t.request_json(POST, "/notus/not_a_system", &["man-db-1.1.1"])
        .await
        .assert_status(StatusCode::NOT_FOUND)
        .snapshot();
}
