//! [`axum`] [`Layer`] and [`Service`] for route access authorization.
//!
//! Performs authentication and authorization for a given authentication method, either `Mtls`, `ApiKey` or `Disabled`.
//!
//! # Example
//! ```rust
//! Router::new()
//!     .nest(
//!         "/unprotected",
//!            Router::new()
//!                .route("/foo", get("foo"))
//!                .route("/bar", get("bar")))
//!     .nest(
//!         "/unprotected",
//!         Router::new()
//!             .route("/", get("lorem"))
//!             .route("/", get("ipsum"))
//!             // enable authentication for all routes in this router: /unprotected/lorem and /unprotected/ipsum
//!             .layer(crate::auth::AuthLayer::new(Authentication::ApiKey, Arc::new(vec!["api-keys"]))))
//! ```
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use std::fmt::Display;
use std::pin::Pin;
use std::sync::Arc;
use std::task;
use tower::{Layer, Service};

/// Type for [`axum`] extension extraction
pub type ClientId = String;

/// Enabled authentication method.
#[derive(Copy, Clone, Debug)]
#[allow(unused)]
pub enum Authentication {
    Mtls,
    ApiKey,
    Disabled,
}

impl Display for Authentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mtls => write!(f, "mTLS"),
            Self::ApiKey => write!(f, "apikey"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Enforces authentication for the affected routes.
#[derive(Clone)]
pub struct AuthLayer {
    /// authentication method to use
    auth_method: Authentication,
    /// valid api-keys if the ApiKey method is set
    api_keys: Arc<Vec<String>>,
}

impl AuthLayer {
    /// Creates a new authentication layer for a given authentication method and key set.
    pub fn new(auth_method: Authentication, api_keys: Arc<Vec<String>>) -> AuthLayer {
        AuthLayer {
            auth_method,
            api_keys,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            auth_method: self.auth_method,
            api_keys: self.api_keys.clone(),
        }
    }
}

/// Route authentication [`Service`].
///
/// Supports authentication via either `mTLS` or `api keys`. In case of the former the actual authentication
/// occurs within the [`MtlsAcceptor`](super::mtls::MtlsAcceptor). According to the `mTLS` [rfc](https://datatracker.ietf.org/doc/html/rfc8705)
/// a connection has to be terminated if the given client certificates is *invalid*. This happens on the `session layer`
/// before any `HTTP` communication can happen, meaning that it would never reach the [`AuthService`].
///
/// An otherwise failed authentication results in a 401 Unauthorized response with an empty body.
///
/// The service can only react to two `mTLS` cases:
/// * The given client certificates were valid
/// * No client certificates were given (which doesn't require a connection termination)
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    /// authentication method to use
    auth_method: Authentication,
    /// valid api-keys if the ApiKey method is set
    api_keys: Arc<Vec<String>>,
}

impl<S, B> Service<Request<B>> for AuthService<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, ctx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(ctx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();

        let client_id: Option<ClientId> = match self.auth_method {
            // the actual authentication happens in the MtlsAcceptor
            Authentication::Mtls => req
                .extensions()
                .get::<super::mtls::MtlsCertHash>()
                .map(|x| x.to_string()),
            // fetch the given api-key from the HTTP headers and compare against all valid keys
            Authentication::ApiKey => req.headers().get("X-API-KEY").and_then(|key| {
                key.to_str()
                    .ok()
                    .and_then(|key| self.api_keys.iter().find(|x| x == &key))
                    .cloned()
            }),
            Authentication::Disabled => Some("unknown".to_string()),
        };

        if let Some(client_id) = client_id {
            // insert the client_id which can be a hexadecimal string of the client certificate hash,
            // the used api-key or "unknown" if authentication is disabled
            req.extensions_mut().insert(client_id);

            Box::pin(inner.call(req))
        } else {
            let response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(""))
                .expect("static unauthorized response");
            Box::pin(async { Ok(response) })
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{HeaderValue, Request, StatusCode},
        response::Response,
    };
    use std::{convert::Infallible, sync::Arc};
    use tower::service_fn;

    use super::{AuthService, Authentication};
    use crate::api::{auth::ClientId, tests::send_request};

    /// Tests that "unknown" is set as the client id if authentication is set to disabled.
    #[tokio::test]
    async fn auth_disabled_anon_id() -> anyhow::Result<()> {
        // simulates a route handler
        let inner = service_fn(|req: Request<Body>| async move {
            let client_id = req.extensions().get::<ClientId>();
            assert_eq!(client_id, Some(&"unknown".to_string()));
            Ok::<Response, Infallible>(Response::new(Body::empty()))
        });

        let mut service = AuthService {
            inner,
            auth_method: Authentication::Disabled,
            api_keys: Arc::new(vec![]),
        };

        let req = Request::new(Body::empty());
        let resp = send_request(&mut service, req).await;
        assert!(resp.status().is_success());

        Ok(())
    }

    /// Tests that the used api-key is set as the client id.
    #[tokio::test]
    async fn auth_api_key_id() -> anyhow::Result<()> {
        // simulates a route handler
        let inner = service_fn(|req: Request<Body>| async move {
            let client_id = req.extensions().get::<ClientId>();
            assert_eq!(client_id, Some(&"secret2".to_string()));
            Ok::<Response, Infallible>(Response::new(Body::empty()))
        });

        let mut service = AuthService {
            inner,
            auth_method: Authentication::ApiKey,
            api_keys: Arc::new(vec![
                "secret1".to_string(),
                "secret2".to_string(),
                "secret3".to_string(),
            ]),
        };

        let req = Request::builder().body(Body::empty())?;
        let resp = send_request(&mut service, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::builder()
            .header("X-Api-Key", HeaderValue::from_static("secret2"))
            .body(Body::empty())
            .expect("valid HTTP request");
        let resp = send_request(&mut service, req).await;
        assert!(resp.status().is_success());

        Ok(())
    }

    /// Tests that only MTLS is enabled if both mtls and api keys are configured and no fallback occurs.
    #[tokio::test]
    async fn auth_no_fallback() -> anyhow::Result<()> {
        // simulates a route handler
        let inner = service_fn(|_: Request<Body>| async move {
            Ok::<Response, Infallible>(Response::new(Body::empty()))
        });

        let mut service = AuthService {
            inner,
            auth_method: Authentication::Mtls,
            api_keys: Arc::new(vec!["secret1".to_string()]),
        };

        let req = Request::builder()
            .header("X-Api-Key", HeaderValue::from_static("secret1"))
            .body(Body::empty())?;
        let resp = send_request(&mut service, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
