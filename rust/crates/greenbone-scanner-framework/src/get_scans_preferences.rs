use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    auth_method_segments,
    entry::{self, Bytes, Method, Prefixed, RequestHandler, response::BodyKind},
    models,
};

pub trait GetScansPreferences: Send + Sync {
    fn get_scans_preferences(
        &self,
    ) -> Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>>;
}

pub struct GetScansPreferencesHandler<T> {
    get_scans_preferences: Arc<T>,
}

impl<T> Prefixed for GetScansPreferencesHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans_preferences.prefix()
    }
}

impl<S> RequestHandler for GetScansPreferencesHandler<S>
where
    S: GetScansPreferences + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::GET,
        "scans", "preferences"
    );

    fn call<'a, 'b>(
        &'b self,
        _: Arc<entry::ClientIdentifier>,
        _: &'a entry::Uri,
        _: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans_preferences.clone();
        Box::pin(async move {
            BodyKind::json_content(StatusCode::OK, &gsp.get_scans_preferences().await)
        })
    }
}

impl<T> From<T> for GetScansPreferencesHandler<T>
where
    T: GetScansPreferences + 'static,
{
    fn from(value: T) -> Self {
        GetScansPreferencesHandler {
            get_scans_preferences: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansPreferencesHandler<T>
where
    T: GetScansPreferences + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansPreferencesHandler {
            get_scans_preferences: value,
        }
    }
}

#[cfg(test)]
mod tests {
    use entry::test_utilities;
    use http_body_util::{BodyExt, Empty};
    use hyper::{Request, service::Service};

    use super::*;
    use crate::{Authentication, ClientHash, create_single_handler};

    struct Test {}

    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl GetScansPreferences for Test {
        fn get_scans_preferences(
            &self,
        ) -> Pin<Box<dyn Future<Output = Vec<models::ScanPreferenceInformation>> + Send>> {
            Box::pin(async move { vec![] })
        }
    }

    #[tokio::test]
    async fn get_scans_preferences_unauthenticated() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansPreferencesHandler::from(Test {})),
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
            create_single_handler!(GetScansPreferencesHandler::from(Test {})),
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
