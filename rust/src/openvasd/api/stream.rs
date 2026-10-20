//! Streamed API and HTTP response types.
use std::pin::Pin;

use axum_streams::{StreamBodyAs, StreamBodyAsOptions};
use futures::{Stream, StreamExt, future, stream};

use crate::api::error::ApiError;

/// An async stream of Results used by the database.
pub type StreamResult<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send>>;

const JSON_CHUNK_SIZE: usize = 16 * 1024;

// TODO: The current storage layer reports any failure with the initial setup
// through an error in the first item. This adapter exists to preserve that
// behavior for now. It also skips any future serialization errors by simply
// dropping the results. This should be fixed, for obvious reasons.
pub async fn into_json_stream<T>(
    mut inner: StreamResult<T, ApiError>,
) -> Result<StreamBodyAs<'static>, ApiError>
where
    T: serde::Serialize + Send + 'static,
{
    let first = inner.next().await.transpose().inspect_err(|error| {
        tracing::error!(%error, "stream setup error");
    })?;
    let items = stream::iter(first.map(Ok))
        .chain(inner)
        .filter_map(|item| {
            future::ready(
                item.inspect_err(|error| tracing::error!(%error, "stream item error"))
                    .ok(),
            )
        })
        .filter_map(|item| {
            future::ready(
                serde_json::value::to_raw_value(&item)
                    .inspect_err(|error| tracing::warn!(%error, "Unable to serialize mid-stream"))
                    .ok(),
            )
        });

    Ok(StreamBodyAsOptions::new()
        .buffering_bytes(JSON_CHUNK_SIZE)
        .json_array(items))
}
