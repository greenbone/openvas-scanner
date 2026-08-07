// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    greenbone_scanner_framework::entry::{
        self, Bytes, Method, Prefixed, RequestHandler, response::BodyKind,
    },
    metrics::scanner_metrics,
};

/// Prometheus content type for the text format.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Trait for a type that can provide Prometheus metrics.
///
/// The default implementation renders the process-wide [`ScannerMetrics`].
pub trait GetMetrics: Prefixed + Send + Sync {
    fn metrics(&self) -> Pin<Box<dyn std::future::Future<Output = String> + Send>>;
}

/// Default metrics provider that renders the global [`ScannerMetrics`].
#[derive(Default)]
pub struct DefaultMetrics;

impl Prefixed for DefaultMetrics {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl GetMetrics for DefaultMetrics {
    fn metrics(&self) -> Pin<Box<dyn std::future::Future<Output = String> + Send>> {
        Box::pin(async move { scanner_metrics().render() })
    }
}

/// Handler for `GET /metrics`.
///
/// When `needs_authentication` returns `true`, the request must be authenticated
/// (API key or mTLS). The authentication requirement is configurable via
/// `endpoints.metrics_auth`.
pub struct GetMetricsHandler<T> {
    metrics: Arc<T>,
    authenticated: bool,
}

impl GetMetricsHandler<DefaultMetrics> {
    /// Creates a handler with the default global metrics provider.
    ///
    /// `authenticated` controls whether `/metrics` requires API key / mTLS.
    pub fn new(authenticated: bool) -> Self {
        Self {
            metrics: Arc::new(DefaultMetrics),
            authenticated,
        }
    }
}

impl<T> GetMetricsHandler<T>
where
    T: GetMetrics + 'static,
{
    /// Creates a handler with a custom metrics provider.
    pub fn with_provider(provider: T, authenticated: bool) -> Self {
        Self {
            metrics: Arc::new(provider),
            authenticated,
        }
    }
}

impl<T> Prefixed for GetMetricsHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.metrics.prefix()
    }
}

impl<S> RequestHandler for GetMetricsHandler<S>
where
    S: GetMetrics + Prefixed + 'static,
{
    fn needs_authentication(&self) -> bool {
        self.authenticated
    }

    fn path_segments(&self) -> &'static [&'static str] {
        &["metrics"]
    }

    fn http_method(&self) -> Method {
        Method::GET
    }

    fn call<'a, 'b>(
        &'b self,
        _client_id: Arc<entry::ClientIdentifier>,
        _uri: &'a entry::Uri,
        _body: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let m = self.metrics.clone();
        Box::pin(async move {
            let rendered = m.metrics().await;
            if rendered.is_empty() {
                BodyKind::no_content(StatusCode::INTERNAL_SERVER_ERROR)
            } else {
                BodyKind::text_content(
                    StatusCode::OK,
                    PROMETHEUS_CONTENT_TYPE,
                    rendered,
                )
            }
        })
    }
}

impl<T> From<T> for GetMetricsHandler<T>
where
    T: GetMetrics + 'static,
{
    fn from(value: T) -> Self {
        GetMetricsHandler {
            metrics: Arc::new(value),
            authenticated: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::greenbone_scanner_framework::{Authentication, entry::ClientHash};
    use entry::test_utilities;

    #[tokio::test]
    async fn get_metrics_unauthenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::Disabled,
            create_single_handler!(GetMetricsHandler::new(false)),
            None,
        );

        let req = test_utilities::empty_request(Method::GET, "/metrics");
        let resp = hyper::service::Service::call(&entry_point, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            PROMETHEUS_CONTENT_TYPE
        );
    }

    #[tokio::test]
    async fn get_metrics_requires_auth() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(GetMetricsHandler::new(true)),
            None,
        );

        let req = test_utilities::empty_request(Method::GET, "/metrics");
        let resp = hyper::service::Service::call(&entry_point, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_metrics_authenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::ApiKey(vec!["test".to_owned()]),
            create_single_handler!(GetMetricsHandler::new(true)),
            Some(ClientHash::from("test")),
        );

        let req = test_utilities::empty_request(Method::GET, "/metrics");
        let resp = hyper::service::Service::call(&entry_point, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
