// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use http_body_util::BodyExt;

#[derive(serde::Serialize, Debug)]
pub struct BadRequest {
    line: usize,
    column: usize,
    message: String,
}

pub async fn json_request<T, H>(
    response: &crate::response::Response,
    req: hyper::Request<H>,
) -> Result<T, crate::response::Result>
where
    T: serde::de::DeserializeOwned,
    H: hyper::body::Body,
    <H as hyper::body::Body>::Error: std::error::Error,
{
    let body = req.into_body();
    let bytes = match body.collect().await {
        Ok(x) => x.to_bytes(),
        Err(e) => {
            return Err(response.internal_server_error(&e));
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(json) => Ok(json),
        Err(e) => Err(response.bad_request(&BadRequest {
            line: e.line(),
            column: e.column(),
            message: e.to_string(),
        })),
    }
}
