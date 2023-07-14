// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::error::Error;

use serde::Serialize;

type Result = hyper::Response<hyper::Body>;

#[derive(Debug, Clone)]
pub struct Response {
    authentication: String,
    version: String,
    feed_version: String,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            authentication: String::new(),
            version: "1".to_string(),
            feed_version: String::new(),
        }
    }
}

impl Response {
    /// Sets the version of the response header.
    pub fn set_feed_version(&mut self, feed_version: &str) {
        self.feed_version = feed_version.to_string();
    }

    /// Appends authentication to the response header.
    pub fn add_authentication(&mut self, authentication: &str) {
        if self.authentication.is_empty() {
            self.authentication = authentication.to_string();
        } else {
            self.authentication = format!("{}, {}", self.authentication, authentication);
        }
    }

    fn default_response_builder(&self) -> hyper::http::response::Builder {
        hyper::Response::builder()
            .header("authentication", &self.authentication)
            .header("version", &self.version)
            .header("feed_version", &self.feed_version)
    }

    #[tracing::instrument]
    fn create<T>(&self, code: hyper::StatusCode, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        match serde_json::to_string(value) {
            Ok(json) => {
                match self
                    .default_response_builder()
                    .header("Content-Type", "application/json")
                    .header("Content-Length", json.len())
                    .status(code)
                    .body(hyper::Body::from(json))
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!("Error creating response: {}", e);
                        hyper::Response::builder()
                            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(hyper::Body::empty())
                            .unwrap()
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error serializing response: {}", e);
                self.default_response_builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(hyper::Body::empty())
                    .unwrap()
            }
        }
    }

    pub fn ok<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::OK, value)
    }

    pub fn created<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::CREATED, value)
    }

    pub fn empty(&self, code: hyper::StatusCode) -> Result {
        self.default_response_builder()
            .status(code)
            .body(hyper::Body::empty())
            .unwrap()
    }
    pub fn no_content(&self) -> Result {
        self.empty(hyper::StatusCode::NO_CONTENT)
    }

    pub fn unauthorized(&self) -> Result {
        self.empty(hyper::StatusCode::UNAUTHORIZED)
    }

    pub fn internal_server_error(&self, err: &dyn Error) -> Result {
        tracing::error!("Unexpected error: {}", err);
        self.empty(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn service_unavailable<'a>(&self, source: &'a str, reason: &'a str) -> Result {
        #[derive(Serialize, Debug)]
        struct Unavailable<'a> {
            source: &'a str,
            reason: &'a str,
        }
        let value = Unavailable { source, reason };
        tracing::error!("Service {} unavailable: {}", source, reason);
        self.create(hyper::StatusCode::SERVICE_UNAVAILABLE, &value)
    }

    pub fn not_found<'a>(&self, class: &'a str, id: &'a str) -> Result {
        #[derive(Serialize, Debug)]
        struct NotFound<'a> {
            class: &'a str,
            id: &'a str,
        }

        let value = NotFound { class, id };
        tracing::trace!("{:?}", value);
        self.create(hyper::StatusCode::NOT_FOUND, &value)
    }

    pub fn bad_request<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::BAD_REQUEST, &value)
    }

    pub fn not_accepted<T>(&self, got: &T, expected: &[T]) -> Result
    where
        T: Serialize + std::fmt::Debug,
    {
        #[derive(Serialize, Debug)]
        struct NotAccepted<'a, T> {
            allowed: &'a [T],
            got: &'a T,
        }
        let value = NotAccepted {
            allowed: expected,
            got,
        };
        self.create(hyper::StatusCode::NOT_ACCEPTABLE, &value)
    }
}
