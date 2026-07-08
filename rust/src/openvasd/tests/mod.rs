// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::BTreeMap;

use http::Method;
use serde_json::Value;

use crate::tests::test_builder::TestBuilder;

mod test_builder;

const GET: Method = Method::GET;
const HEAD: Method = Method::HEAD;

#[tokio::test]
async fn openvasd_starts() -> anyhow::Result<()> {
    let t = TestBuilder::new("openvasd_starts")
        .config("openvasd_starts")
        .build()
        .await?;

    t.request(HEAD, "/health/alive").await.snapshot();
    t.request(HEAD, "/health/ready").await.snapshot();
    t.request(HEAD, "/scans").await.snapshot();
    t.request(HEAD, "/notus").await.snapshot();

    Ok(())
}

#[tokio::test]
async fn get_scans_preferences() -> anyhow::Result<()> {
    let t = TestBuilder::new("get_scans_preferences")
        .config("openvasd_starts")
        .build()
        .await?;

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

    Ok(())
}

#[tokio::test]
async fn get_notus() -> anyhow::Result<()> {
    let t = TestBuilder::new("get_notus")
        .config("notus")
        .build()
        .await?;

    t.request(Method::GET, "/notus").await.snapshot();

    Ok(())
}
