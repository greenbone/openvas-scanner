// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{convert::Infallible, error::Error, pin::Pin, sync::mpsc::Receiver, task::Poll, thread};

use http_body::Body;
use hyper::body::Bytes;
use serde::Serialize;
pub type Result = hyper::Response<BodyKind>;

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

/// Implements the hyper http body types
pub enum BodyKind {
    /// Nobody likes the records that I play
    Empty,
    /// Binary data
    Binary(Bytes),
    /// Binary stream, we use the receiver to receive chunks.
    ///
    /// To use this method channels have to be created upfront.
    /// ```text
    /// let (tx, rx) = std::sync::mpsc::sync_channel::<SendState>(0);
    /// tokio::spawn(async move {
    ///     tx.send(SendState::Start).unwrap();
    ///     if let Some(v) = value.next() {
    ///         tx.send(SendState::Bytes(true, v)).unwrap();
    ///     }
    ///     for v in value {
    ///         tx.send(SendState::Bytes(false, v)).unwrap();
    ///     }
    ///     tx.send(SendState::End).unwrap();
    ///     drop(tx);
    /// });
    /// self.ok_json_response(BodyKind::BinaryStream(rx))
    /// ```
    BinaryStream(Receiver<SendState>),
}

#[derive(Debug)]
/// Is used to control the BinaryStream output
pub enum SendState {
    /// Triggers [
    Start,
    /// true triggers ...data... false triggers ,...data...
    Bytes(bool, Vec<u8>),
    /// Triggers ]
    End,
}

static JARREND: &[u8] = &[b']'];
static JARRSTART: &[u8] = &[b'['];
impl Body for BodyKind {
    type Data = Bytes;

    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        match self {
            BodyKind::Empty => true,
            BodyKind::BinaryStream(..) | BodyKind::Binary(_) => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            BodyKind::Empty => http_body::SizeHint::with_exact(0),
            BodyKind::Binary(b) => http_body::SizeHint::with_exact(b.len() as u64),
            // we don't know
            BodyKind::BinaryStream(..) => http_body::SizeHint::default(),
        }
    }

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let kind = self.get_mut();

        match kind {
            BodyKind::Empty => Poll::Ready(None),
            BodyKind::Binary(b) => Poll::Ready({
                let res = Some(Ok(http_body::Frame::data(b.clone())));
                *kind = BodyKind::Empty;
                res
            }),
            BodyKind::BinaryStream(rec) => Poll::Ready({
                let r = rec.recv();
                match r {
                    Ok(SendState::Start) => {
                        Some(Ok(http_body::Frame::data(Bytes::from_static(JARRSTART))))
                    }
                    Ok(SendState::End) => {
                        *kind = BodyKind::Empty;
                        Some(Ok(http_body::Frame::data(Bytes::from_static(JARREND))))
                    }

                    Ok(SendState::Bytes(true, b)) => Some(Ok(http_body::Frame::data(b.into()))),
                    Ok(SendState::Bytes(false, mut b)) => {
                        b.reverse();
                        b.push(b',');
                        b.reverse();
                        Some(Ok(http_body::Frame::data(b.into())))
                    }
                    Err(e) => {
                        tracing::warn!("sender did not send SendState::End before drop: {e}");
                        *kind = BodyKind::Empty;
                        Some(Ok(http_body::Frame::data(Bytes::from_static(JARREND))))
                    }
                }
            }),
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

    #[inline]
    fn default_response_builder(&self) -> hyper::http::response::Builder {
        hyper::Response::builder()
            .header("authentication", &self.authentication)
            .header("api-version", &self.version)
            .header("feed-version", &self.feed_version)
    }

    #[inline]
    fn ok_json_response(&self, body: BodyKind) -> Result {
        match self
            .default_response_builder()
            .header("Content-Type", "application/json")
            .status(hyper::StatusCode::OK)
            .body(body)
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error creating response: {}", e);
                hyper::Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(BodyKind::Empty)
                    .unwrap()
            }
        }
    }
    #[inline]
    pub async fn ok_byte_stream<T>(&self, mut value: T) -> Result
    where
        T: Iterator<Item = Vec<u8>> + Send + 'static,
    {
        // buffer one extra for fast clients
        let (tx, rx) = std::sync::mpsc::sync_channel::<SendState>(2);
        // unfortunately we cannot use tokio::spawn as we don't know
        // if we are running in something that uses TokioExecutor (e.g. http2)
        // or not (e.g. tests or http1) this deep down.
        // Therefore we enforce a thread via the OS.
        thread::spawn(move || {
            let send = |s| match tx.send(s) {
                Ok(_) => false,
                Err(e) => {
                    tracing::trace!(%e, "retrieve is not available anymore, ignoring.");
                    true
                }
            };
            let span = tracing::debug_span!("ok_byte_stream");

            let _enter = span.enter();
            tracing::debug!("starting to send values");
            if send(SendState::Start) {
                return;
            }
            if let Some(v) = value.next() {
                if send(SendState::Bytes(true, v)) {
                    return;
                };
            }
            if value.map(|v| send(SendState::Bytes(false, v))).any(|x| x) {
                return;
            }

            send(SendState::End);
            tracing::debug!("end send values");
            drop(tx);
        });
        self.ok_json_response(BodyKind::BinaryStream(rx))
    }

    #[inline]
    pub async fn ok_json_stream<T, S>(&self, value: T) -> Result
    where
        T: Iterator<Item = S> + Send + 'static,
        S: Serialize + Clone + Send + std::fmt::Debug + 'static,
    {
        let value = value.map(|x| serde_json::to_vec(&x).unwrap());
        self.ok_byte_stream(value).await
    }

    fn create<T>(&self, code: hyper::StatusCode, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        match serde_json::to_vec(value) {
            Ok(json) => {
                match self
                    .default_response_builder()
                    .header("Content-Type", "application/json")
                    .header("Content-Length", json.len())
                    .status(code)
                    .body(BodyKind::Binary(json.into()))
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!("Error creating response: {}", e);
                        hyper::Response::builder()
                            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(BodyKind::Empty)
                            .unwrap()
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error serializing response: {}", e);
                self.default_response_builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(BodyKind::Empty)
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

    pub fn ok_static(&self, value: &[u8]) -> Result {
        self.ok_json_response(BodyKind::Binary(value.to_vec().into()))
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
            .body(BodyKind::Empty)
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
        self.create(hyper::StatusCode::NOT_FOUND, &value)
    }

    pub fn bad_request<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::BAD_REQUEST, &value)
    }

    pub fn not_implemented<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::NOT_IMPLEMENTED, &value)
    }

    pub fn service_unavailable<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::SERVICE_UNAVAILABLE, &value)
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
