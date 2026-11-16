//! Streamed API and HTTP response types.
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Bytes,
    http::header,
    response::{IntoResponse, Response},
};
use futures::{Stream, StreamExt, prelude::*};

use crate::api::error::ApiError;

/// An async stream of Results used by the database.
pub type StreamResult<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send>>;

#[derive(Copy, Clone)]
enum JsonFramingState {
    Start,
    Item { is_first: bool },
    Done,
}

/// Encodes a stream of `Results<T,E>`` into a `JSON` encoded list of `T`.
/// Entries containing an errors are logged and then filtered out.
pub struct JsonStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    inner: S,
    state: JsonFramingState,
}

impl<S> JsonStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    fn new(inner: S) -> Self {
        Self {
            inner,
            state: JsonFramingState::Start,
        }
    }
}

/// Transforms a [`StreamResult`] into a [`JsonStream`].
pub async fn into_json_stream<'a, T>(
    mut inner: StreamResult<T, ApiError>,
) -> Result<JsonStream<Pin<Box<dyn Stream<Item = Bytes> + Unpin + Send + 'a>>>, ApiError>
where
    T: serde::Serialize + 'a + Send,
{
    // If a function that returns a stream throws an error it returns a stream with just that
    // error as the first and only element. Because of this the first element has to be treated
    // individually since the error has a different severity.
    //
    // TODO: This behavior will be removed in favor of an outer Result when the database access
    // is reworked.
    match inner.next().await {
        Some(Ok(first)) => {
            // Since we had to inspect the first element it has to be prepended to the stream again
            let inner_stream = stream::once(std::future::ready(Ok(first)))
                .chain(inner)
                // filters errors from the stream source like sqlite or redis
                .filter_map(|x| {
                    future::ready(
                        x.inspect_err(|e| tracing::error!("stream item error: {e}"))
                            .ok(),
                    )
                })
                // serialize to json and filter out serialization errors
                .filter_map(|x| match serde_json::to_vec(&x) {
                    Ok(x) => future::ready(Some(Bytes::from(x))),
                    Err(e) => {
                        tracing::warn!(error = %e, "Unable to serialize mid-stream.");
                        future::ready(None)
                    }
                });

            Ok(JsonStream::new(Box::pin(inner_stream)))
        }
        Some(Err(e)) => {
            // this is most likely an error that occurred trying to create the stream
            tracing::error!("stream error: {e:?}");
            Err(e)
        }
        _ => Ok(JsonStream::new(Box::pin(futures::stream::empty()))),
    }
}

impl<S> Stream for JsonStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.state;
        match state {
            JsonFramingState::Start => {
                self.state = JsonFramingState::Item { is_first: true };
                Poll::Ready(Some(Ok(Bytes::from_static(b"["))))
            }
            JsonFramingState::Item { is_first } => match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(chunk)) => {
                    if is_first {
                        self.state = JsonFramingState::Item { is_first: false };
                        Poll::Ready(Some(Ok(chunk)))
                    } else {
                        let mut data = Vec::with_capacity(1 + chunk.len());
                        data.push(b',');
                        data.extend_from_slice(&chunk);
                        Poll::Ready(Some(Ok(Bytes::from(data))))
                    }
                }
                Poll::Ready(None) => {
                    self.state = JsonFramingState::Done;
                    Poll::Ready(Some(Ok(Bytes::from_static(b"]"))))
                }
                Poll::Pending => Poll::Pending,
            },
            JsonFramingState::Done => Poll::Ready(None),
        }
    }
}

impl<S> IntoResponse for JsonStream<S>
where
    S: Stream<Item = Bytes> + Unpin + Send + 'static,
{
    fn into_response(self) -> Response {
        let mut resp = Response::new(axum::body::Body::from_stream(self));

        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/json"
                .parse()
                .expect("failed to create valid HTTP header value"),
        );

        resp
    }
}

#[cfg(test)]
mod tests {
    use crate::api::error::ApiError;
    use std::convert::Infallible;

    use futures::{StreamExt, stream};

    use axum::body::Bytes;

    #[tokio::test]
    async fn json_serialization() {
        let items = vec![
            Ok("foo".to_owned()),
            Ok("bar".to_owned()),
            Ok("baz".to_owned()),
        ];

        let string_stream = Box::pin(stream::iter(items.into_iter()));
        let framed_stream = super::into_json_stream(string_stream).await.unwrap();

        let vec: Vec<Result<Bytes, Infallible>> = framed_stream.collect().await;
        let vec = vec
            .into_iter()
            .filter_map(|x| x.ok())
            .flat_map(|x| x.to_vec())
            .collect();
        let result: Vec<String> = serde_json::from_str(&String::from_utf8(vec).unwrap()).unwrap();

        assert_eq!(
            result,
            vec!["foo".to_owned(), "bar".to_owned(), "baz".to_owned()]
        );
    }

    #[tokio::test]
    async fn json_serialization_error_filter() {
        let items = vec![
            Ok("foo".to_owned()),
            Err(ApiError::InvalidInput("".to_string())),
            Ok("baz".to_owned()),
        ];

        let string_stream = Box::pin(stream::iter(items.into_iter()));
        let framed_stream = super::into_json_stream(string_stream).await.unwrap();

        let vec: Vec<Result<Bytes, Infallible>> = framed_stream.collect().await;
        let vec = vec
            .into_iter()
            .filter_map(|x| x.ok())
            .flat_map(|x| x.to_vec())
            .collect();
        let result: Vec<String> = serde_json::from_str(&String::from_utf8(vec).unwrap()).unwrap();

        assert_eq!(result, vec!["foo".to_owned(), "baz".to_owned()]);
    }
}
