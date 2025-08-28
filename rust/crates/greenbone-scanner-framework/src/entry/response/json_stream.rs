use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use futures_util::stream::StreamExt;

use crate::entry::Bytes;

#[derive(Copy, Clone)]
enum JsonFramingState {
    Start,
    Item { is_first: bool },
    Done,
}

pub struct JsonFramedStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    inner: S,
    state: JsonFramingState,
}

pub fn from_stream<'a, J, T>(
    inner: J,
) -> JsonFramedStream<Pin<Box<dyn Stream<Item = Bytes> + Unpin + Send + 'a>>>
where
    J: Stream<Item = T> + Unpin + Send + 'a,
    T: serde::Serialize + 'a,
{
    let inner_stream = Box::pin(inner.map(|item| {
        let json_bytes = match serde_json::to_vec(&item) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "Unable to serialize mid-stream.");
                vec![]
            }
        };
        Bytes::from(json_bytes)
    }));

    JsonFramedStream::new(inner_stream)
}

impl<S> JsonFramedStream<S>
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

impl<S> Stream for JsonFramedStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.state;
        match state {
            JsonFramingState::Start => {
                self.state = JsonFramingState::Item { is_first: true };
                Poll::Ready(Some(Bytes::from_static(b"[")))
            }
            JsonFramingState::Item { is_first } => match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(chunk)) => {
                    if is_first {
                        self.state = JsonFramingState::Item { is_first: false };
                        Poll::Ready(Some(chunk))
                    } else {
                        let mut data = Vec::with_capacity(1 + chunk.len());
                        data.push(b',');
                        data.extend_from_slice(&chunk);
                        Poll::Ready(Some(Bytes::from(data)))
                    }
                }
                Poll::Ready(None) => {
                    self.state = JsonFramingState::Done;
                    Poll::Ready(Some(Bytes::from_static(b"]")))
                }
                Poll::Pending => Poll::Pending,
            },
            JsonFramingState::Done => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt, stream};

    use crate::entry::Bytes;

    #[tokio::test]
    async fn json_serialization() {
        let items = vec!["Holla".to_owned(), "die".to_owned(), "Waldfee".to_owned()];
        let string_stream = stream::iter(items.clone().into_iter());

        let framed_stream = super::from_stream(string_stream);

        let vec: Vec<Bytes> = framed_stream.collect().await;
        let vec = vec.into_iter().flat_map(|x| x.to_vec()).collect();
        let result = String::from_utf8(vec).unwrap();
        let result: Vec<String> = serde_json::from_str(&result).unwrap();
        assert_eq!(result, items);
    }
}
