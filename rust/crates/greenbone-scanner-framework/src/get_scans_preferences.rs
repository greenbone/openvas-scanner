use std::sync::Arc;

use hyper::StatusCode;

use crate::{
    define_authentication_paths,
    entry::{self, Bytes, Method, OnRequest, Prefixed, response::BodyKind},
    models,
};

pub trait GetScansPreferences: Send + Sync {
    fn get_scans_preferences(
        &self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>>;
}

pub struct GetScansPreferencesIncomingRequest<T> {
    get_scans_preferences: Arc<T>,
}

#[derive(Default)]
pub struct NoPreferences;
impl Prefixed for NoPreferences {
    fn prefix(&self) -> &'static str {
        ""
    }
}

impl GetScansPreferences for NoPreferences {
    fn get_scans_preferences<'b>(
        &self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>>
    {
        Box::pin(async move { vec![] })
    }
}
impl Default for GetScansPreferencesIncomingRequest<NoPreferences> {
    fn default() -> Self {
        Self {
            get_scans_preferences: Arc::new(NoPreferences {}),
        }
    }
}

impl<T> Prefixed for GetScansPreferencesIncomingRequest<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans_preferences.prefix()
    }
}

impl<S> OnRequest for GetScansPreferencesIncomingRequest<S>
where
    S: GetScansPreferences + Prefixed + 'static,
{
    define_authentication_paths!(
        authenticated: true,
        Method::GET,
        "scans", "preferences"
    );

    fn call<'a, 'b>(
        &'b self,
        _: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        _: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans_preferences.clone();
        Box::pin(async move {
            BodyKind::json_content(StatusCode::OK, &gsp.get_scans_preferences().await)
        })
    }
}

impl<T> From<T> for GetScansPreferencesIncomingRequest<T>
where
    T: GetScansPreferences + 'static,
{
    fn from(value: T) -> Self {
        GetScansPreferencesIncomingRequest {
            get_scans_preferences: Arc::new(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use crate::{Authentication, ClientHash, incoming_request};

    use super::*;

    struct Test {}

    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl GetScansPreferences for Test {
        fn get_scans_preferences(
            &self,
        ) -> std::pin::Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>>
        {
            Box::pin(async move { vec![] })
        }
    }

    #[tokio::test]
    async fn get_scans_preferences_unauthenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansPreferencesIncomingRequest::from(Test {})),
            None,
        );

        let req = Request::builder()
            .uri("/scans/preferences")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_scans_preferences() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(GetScansPreferencesIncomingRequest::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/preferences")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8_lossy(bytes.as_ref());
        insta::assert_snapshot!(resp);
    }
}
