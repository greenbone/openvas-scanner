// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{convert::Infallible, error::Error, marker::PhantomData};

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

trait Transform<T> {
    fn transform(t: T) -> String;
}

#[derive(Debug, Clone)]
struct JsonTransformer;

impl<T> Transform<T> for JsonTransformer
where
    T: Serialize,
{
    fn transform(t: T) -> String {
        serde_json::to_string(&t).unwrap()
    }
}

#[derive(Debug, Clone)]
struct U8Streamer;

impl Transform<Vec<u8>> for U8Streamer {
    fn transform(t: Vec<u8>) -> String {
        String::from_utf8(t).unwrap()
    }
}

#[derive(Default)]
enum ArrayStreamState {
    #[default]
    First,
    Running,
    Finished,
}

struct ArrayStreamer<E, T> {
    elements: Box<dyn Iterator<Item = E> + Send>,
    transform: PhantomData<T>,
    state: ArrayStreamState,
}

impl<E, T> Unpin for ArrayStreamer<E, T> {}

impl<E> ArrayStreamer<E, JsonTransformer>
where
    E: Serialize,
{
    fn json(elements: Box<dyn Iterator<Item = E> + Send>) -> Self {
        Self {
            elements,
            state: ArrayStreamState::First,
            transform: PhantomData,
        }
    }
}

impl ArrayStreamer<Vec<u8>, U8Streamer> {
    fn u8(elements: Box<dyn Iterator<Item = Vec<u8>> + Send>) -> Self {
        Self {
            elements,
            state: ArrayStreamState::First,
            transform: PhantomData,
        }
    }
}

impl<E, T> Stream for ArrayStreamer<E, T>
where
    T: Transform<E>,
{
    type Item = std::result::Result<String, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let out = {
            match self.state {
                ArrayStreamState::First => {
                    self.state = ArrayStreamState::Running;
                    if let Some(e) = self.elements.next() {
                        Some(format!("[{}", T::transform(e)))
                    } else {
                        Some("[".to_string())
                    }
                }
                ArrayStreamState::Running => match self.elements.next() {
                    Some(e) => Some(format!(",{}", T::transform(e))),
                    None => {
                        self.state = ArrayStreamState::Finished;
                        Some("]".to_string())
                    }
                },

                ArrayStreamState::Finished => None,
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

    pub async fn create_stream<S, O, E>(&self, code: hyper::StatusCode, value: S) -> Result
    where
        S: Stream<Item = std::result::Result<O, E>> + Send + 'static,
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

    pub async fn ok_json_stream<T>(&self, value: Box<dyn Iterator<Item = T> + Send>) -> Result
    where
        T: Serialize + Send + std::fmt::Debug + 'static,
    {
        let stream = ArrayStreamer::json(value);
        self.create_stream(hyper::StatusCode::OK, stream).await
    }
    pub async fn ok_byte_stream(&self, value: Box<dyn Iterator<Item = Vec<u8>> + Send>) -> Result {
        let stream = ArrayStreamer::u8(value);
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
