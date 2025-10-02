mod json_stream;
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, StreamExt, stream};
use http_body::{Body, Frame, SizeHint};
use hyper::{StatusCode, body::Bytes};

pub struct BodyKind {
    pub status_code: StatusCode,
    pub content: BodyKindContent,
}

/// Implements the hyper http body types
pub enum BodyKindContent {
    /// Empty body
    Empty,
    /// Static binary buffer
    Binary(Bytes),
    /// Generic boxed stream
    BinaryStream(Pin<Box<dyn Stream<Item = Bytes> + Send>>),
}

#[derive(serde::Serialize, Debug)]
pub struct BadRequest {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

#[macro_export]
macro_rules! internal_server_error {
    ($e:expr) => {{
        tracing::warn!(error = %$e, "Unexpected error occurred");
        $crate::entry::response::BodyKind::no_content(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    }};
    () => {{
        $crate::entry::response::BodyKind::no_content(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    }};
}

pub type StreamResult<'a, T, E> = Box<dyn Stream<Item = Result<T, E>> + Unpin + Send + 'a>;

pub trait BodyKindError {
    fn into_body_kind(self) -> BodyKind;
}

impl<T> BodyKindError for T
where
    T: Into<BodyKind>,
{
    fn into_body_kind(self) -> BodyKind {
        self.into()
    }
}

impl BodyKind {
    pub fn no_content(status_code: StatusCode) -> Self {
        Self {
            status_code,
            content: BodyKindContent::Empty,
        }
    }

    pub fn json_content<T>(status_code: StatusCode, v: &T) -> Self
    where
        T: serde::Serialize,
    {
        match serde_json::to_vec(v) {
            Ok(v) => BodyKind {
                status_code,
                content: BodyKindContent::Binary(v.into()),
            },
            Err(e) => internal_server_error!(e),
        }
    }

    fn from_stream<J, T>(status_code: StatusCode, inner: J) -> Self
    where
        //TODO: get rid of static by adding lifetimes to BodyKind
        J: Stream<Item = T> + Unpin + Send + 'static,
        T: serde::Serialize + 'static,
    {
        let inner = json_stream::from_stream(inner);
        let kind = BodyKindContent::BinaryStream(Box::pin(inner));
        Self {
            status_code,
            content: kind,
        }
    }

    /// Transforms a StreamResult into a BodyKind
    ///
    /// Verifies the first result of given StreamResult:
    /// If it is ok then it will create a new stream with the first element and the result
    /// If it is Err then it will return the error bodykind
    /// If it is an empty stgream it will return an BodyKind::Stream with an empty stream
    pub async fn from_result_stream<T, E>(
        status_code: StatusCode,
        mut input: StreamResult<'static, T, E>,
    ) -> Self
    where
        T: Default + serde::Serialize + Send + 'static,
        E: BodyKindError + std::fmt::Debug + 'static,
    {
        if let Some(element) = input.next().await {
            match element {
                Ok(x) => {
                    let result = input.map(|x| match x {
                    Ok(x) => x,
                    Err(err) => {
                        tracing::warn!(error=?err, "Unexpected error mid stream. Using placeholder element.");
                        T::default()
                    },
                });
                    let result = Box::pin(stream::once(async move { x }).chain(result));

                    BodyKind::from_stream(status_code, result)
                }
                Err(e) => e.into_body_kind(),
            }
        } else {
            BodyKind::from_stream(status_code, stream::empty::<T>())
        }
    }
}

impl From<serde_json::Error> for BodyKind {
    fn from(value: serde_json::Error) -> Self {
        let br = BadRequest {
            line: value.line(),
            column: value.column(),
            message: value.to_string(),
        };
        BodyKind::json_content(StatusCode::BAD_REQUEST, &br)
    }
}

impl Body for BodyKindContent {
    type Data = Bytes;
    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        matches!(self, BodyKindContent::Empty)
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            BodyKindContent::Empty => SizeHint::with_exact(0),
            BodyKindContent::Binary(b) => SizeHint::with_exact(b.len() as u64),
            _ => SizeHint::default(),
        }
    }

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this {
            BodyKindContent::Empty => Poll::Ready(None),
            BodyKindContent::Binary(b) => {
                let data = b.clone();
                *this = BodyKindContent::Empty;
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            BodyKindContent::BinaryStream(s) => match s.as_mut().poll_next(cx) {
                Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Poll::Ready(None) => {
                    *this = BodyKindContent::Empty;
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
