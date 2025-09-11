use std::sync::Arc;
use std::{marker::PhantomData, pin::Pin};

use futures::Stream;
use http_body_util::BodyExt;
use hyper::StatusCode;

use crate::entry::response::BodyKind;
use crate::entry::{self, Bytes, Method};
use crate::{ClientIdentifier, internal_server_error};

pub struct InputData<'a> {
    pub client_id: Arc<entry::ClientIdentifier>,
    pub uri: &'a entry::Uri,
    pub bytes: Bytes,
}

pub trait Endpoint: Sync + Send + 'static {
    type In: Send + 'static;
    type Out: Send + 'static;

    fn needs_authentication() -> bool;
    fn path_segments() -> &'static [&'static str];
    fn http_method() -> Method;

    fn data_to_input(data: InputData) -> Self::In;

    fn output_to_data(out: Self::Out) -> BodyKind;

    fn output_to_data_async(out: Self::Out) -> impl Future<Output = BodyKind> + Send {
        async move { Self::output_to_data(out) }
    }
}

pub trait Handler<E: Endpoint>: Sync + Send + 'static {
    fn prefix() -> &'static str {
        ""
    }

    fn call(
        &self,
        input: <E as Endpoint>::In,
    ) -> Pin<Box<dyn std::future::Future<Output = <E as Endpoint>::Out> + Send>>;
}

impl<T: Handler<E>, E: Endpoint> Handler<E> for Arc<T> {
    fn call(
        &self,
        input: <E as Endpoint>::In,
    ) -> Pin<Box<dyn std::future::Future<Output = <E as Endpoint>::Out> + Send>> {
        <T as Handler<E>>::call(self, input)
    }
}

trait RequestHandler {
    fn call(&self, data: InputData) -> Pin<Box<dyn Future<Output = BodyKind> + Send + '_>>;
    fn prefix(&self) -> &'static str;
    fn needs_authentication(&self) -> bool;
    fn path_segments(&self) -> &'static [&'static str];
    fn http_method(&self) -> Method;
}

struct TypeErasedRequestHandler<T, E> {
    handler: T,
    marker: PhantomData<E>,
}

impl<T: Handler<E>, E: Endpoint> RequestHandler for TypeErasedRequestHandler<T, E>
where
    TypeErasedRequestHandler<T, E>: Sync,
    <E as Endpoint>::In: Send,
    <E as Endpoint>::Out: Send,
{
    fn call(&self, data: InputData) -> Pin<Box<dyn Future<Output = BodyKind> + Send + '_>> {
        let input = E::data_to_input(data);
        Box::pin(async move {
            let output = self.handler.call(input).await;
            E::output_to_data_async(output).await
        })
    }

    fn prefix(&self) -> &'static str {
        <T as Handler<E>>::prefix()
    }

    fn needs_authentication(&self) -> bool {
        <E as Endpoint>::needs_authentication()
    }

    fn path_segments(&self) -> &'static [&'static str] {
        <E as Endpoint>::path_segments()
    }

    fn http_method(&self) -> Method {
        <E as Endpoint>::http_method()
    }
}

#[derive(Default)]
pub struct Handlers {
    inner: Vec<Arc<Box<dyn RequestHandler + Send + Sync>>>,
}

impl Handlers {
    // We take the ZST _endpoint as an argument so we don't
    // need turbofish syntax for this method
    pub fn add<E: Endpoint, T: Handler<E>>(&mut self, _endpoint: E, handler: T)
    where
        T: Send + Sync + 'static,
        E: Send + Sync + 'static,
        <E as Endpoint>::In: Send,
        <E as Endpoint>::Out: Send,
    {
        self.inner.push(Arc::new(Box::new(TypeErasedRequestHandler {
            handler,
            marker: PhantomData,
        })));
    }

    // We take the ZST _endpoint as an argument so we don't
    // need turbofish syntax for this method
    pub fn single<E: Endpoint, T: Handler<E>>(endpoint: E, handler: T) -> Self
    where
        T: Send + Sync + 'static,
        E: Send + Sync + 'static,
        <E as Endpoint>::In: Send,
        <E as Endpoint>::Out: Send,
    {
        let mut s = Self::default();
        s.add::<E, T>(endpoint, handler);
        s
    }

    pub fn call<R>(
        &self,
        client_id: Arc<ClientIdentifier>,
        req: hyper::Request<R>,
    ) -> BodyKindFuture
    where
        R: hyper::body::Body + Send + 'static,
        <R as hyper::body::Body>::Error: std::error::Error,
        <R as hyper::body::Body>::Data: Send,
    {
        let callbacks = self.inner.clone();

        Box::pin(async move {
            let segments = req
                .uri()
                .path()
                .split('/')
                // handles double slashes e.g. /scans/ or /scans//id////results
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>();
            for rh in callbacks {
                if segments_match(rh.prefix(), rh.path_segments(), &segments) {
                    let needs_authentication = rh.needs_authentication();
                    let is_authenticated = matches!(&*client_id, &ClientIdentifier::Known(_));
                    if !needs_authentication || is_authenticated {
                        if req.method() == Method::HEAD {
                            return BodyKind::no_content(StatusCode::OK);
                        }
                        if req.method() == rh.http_method() {
                            let uri = req.uri().clone();
                            let body = req.into_body();
                            let bytes = match body.collect().await {
                                Ok(x) => x.to_bytes(),
                                Err(e) => {
                                    return internal_server_error!(e);
                                }
                            };

                            return rh
                                .call(InputData {
                                    client_id,
                                    uri: &uri,
                                    bytes,
                                })
                                .await;
                        }
                    } else {
                        return BodyKind::no_content(StatusCode::UNAUTHORIZED);
                    }
                }
            }

            BodyKind::no_content(StatusCode::NOT_FOUND)
        })
    }
}

type BodyKindFuture = Pin<Box<dyn futures_util::Future<Output = BodyKind> + Send>>;

fn segments_match(prefix: &str, handler_parts: &[&str], request_parts: &[&str]) -> bool {
    let offset = if !prefix.is_empty() {
        if handler_parts.len() != request_parts.len() - 1 || prefix != request_parts[0] {
            return false;
        }
        1
    } else {
        if handler_parts.len() != request_parts.len() {
            return false;
        }
        0
    };

    for (i, p) in handler_parts.iter().enumerate() {
        if p == &"*" {
            continue;
        }

        if p != &request_parts[i + offset] {
            return false;
        }
    }
    true
}
