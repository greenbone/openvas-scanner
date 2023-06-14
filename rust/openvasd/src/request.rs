// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

#[derive(serde::Serialize, Debug)]
pub struct BadRequest {
    line: usize,
    column: usize,
    message: String,
}

pub async fn json_request<T>(
    response: &crate::response::Response,
    req: hyper::Request<hyper::Body>,
) -> Result<T, hyper::Response<hyper::Body>>
where
    T: serde::de::DeserializeOwned,
{
    let body = req.into_body();
    let bytes = hyper::body::to_bytes(body).await.unwrap();
    match serde_json::from_slice(&bytes) {
        Ok(json) => Ok(json),
        Err(e) => Err(response.bad_request(&BadRequest {
            line: e.line(),
            column: e.column(),
            message: e.to_string(),
        })),
    }
}
