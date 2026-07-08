// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::tests::test_builder::TestBuilder;

mod test_builder;

#[tokio::test]
async fn openvasd_starts() -> anyhow::Result<()> {
    let t = TestBuilder::new("openvasd_starts")
        .config("openvasd_starts")
        .build()
        .await?;

    t.health_alive().await.snapshot();
    t.health_ready().await.snapshot();
    t.head_scans().await.snapshot();

    Ok(())
}
