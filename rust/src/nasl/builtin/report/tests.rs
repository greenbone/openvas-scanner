// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::Result;

use crate::nasl::test_prelude::*;

async fn get_result(ctx: &ScanCtx<'_>, index: usize) -> Result {
    ctx.storage()
        .retrieve(&(ctx.scan().clone(), index))
        .await
        .unwrap()
        .unwrap()
}

async fn verify(function: &str) {
    let mut t = TestBuilder::default();
    t.run_all(format!(
        r###"
        {function}(data: "test0", port: 12, proto: "udp", uri: "moep");
        {function}(data: "test1", port: 12, proto: "tcp", uri: "moep");
        {function}(data: "test2", port: 12, proto: "nonsense", uri: "moep");
        {function}(data: "test3");
        "###
    ));
    t.check_no_errors();
    {
        let ctx = t.ctx();
        for index in 0..4 {
            let result = get_result(&ctx, index).await;
            insta::assert_ron_snapshot!(format!("result_{}_{}", function, index), result);
        }
    }
    t.async_verify().await;
}

#[tokio::test]
async fn log_message() {
    verify("log_message").await
}

#[tokio::test]
async fn security_message() {
    verify("security_message").await
}

#[tokio::test]
async fn error_message() {
    verify("error_message").await
}

#[tokio::test]
async fn security_notus() {
    let mut t = TestBuilder::default();
    t.run_all(
        r###"
        result["oid"] = "1.2.3.4.5";
        result["message"] = "test message";
        security_notus(result: result);
        "###,
    );
    t.check_no_errors();
    {
        let ctx = t.ctx();
        let result = get_result(&ctx, 0).await;
        insta::assert_ron_snapshot!(result);
    }
    t.async_verify().await;
}
