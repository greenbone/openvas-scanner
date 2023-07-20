// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{convert::Infallible, error::Error};

use futures::Stream;
use hyper::body::Bytes;
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

#[derive(Debug, Clone)]
pub struct JsonArrayStreamer<T> {
    elements: Vec<T>,
    first: bool,
}

impl<T> Unpin for JsonArrayStreamer<T> {}

impl<T> JsonArrayStreamer<T>
where
    T: Serialize + Send,
{
    pub fn new(elements: Vec<T>) -> Self {
        Self {
            elements,
            first: true,
        }
    }
}

impl<T> Stream for JsonArrayStreamer<T>
where
    T: Serialize + Send,
{
    type Item = std::result::Result<String, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let out = {
            if self.first && self.elements.is_empty() {
                self.first = false;
                Some("[]".to_string())
            } else if self.first {
                self.first = false;
                Some("[".to_string())
            } else {
                match self.elements.pop() {
                    Some(e) => {
                        let e = serde_json::to_string(&e).unwrap();
                        if self.elements.is_empty() {
                            Some(format!("{}]", e))
                        } else {
                            Some(format!("{},", e))
                        }
                    }
                    None => None,
                }
            }
        };

        match out {
            Some(e) => std::task::Poll::Ready(Some(Ok(e))),
            None => std::task::Poll::Ready(None),
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
            .header("api-version", &self.version)
            .header("feed-version", &self.feed_version)
    }

    #[tracing::instrument]
    async fn create_stream<S, O, E>(&self, code: hyper::StatusCode, value: S) -> Result
    where
        S: Stream<Item = std::result::Result<O, E>> + Send + std::fmt::Debug + 'static,
        O: Into<Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        match hyper::Response::builder()
            .status(code)
            .header("Content-Type", "application/json")
            .header("authentication", &self.authentication)
            .header("version", &self.version)
            .body(hyper::Body::wrap_stream(value))
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

    pub async fn ok_stream<T>(&self, value: Vec<T>) -> Result
    where
        T: Serialize + Send + std::fmt::Debug + 'static,
    {
        let stream = JsonArrayStreamer::new(value);
        self.create_stream(hyper::StatusCode::OK, stream).await
    }

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
