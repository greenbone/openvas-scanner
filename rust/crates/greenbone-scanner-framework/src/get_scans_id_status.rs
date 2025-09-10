use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    GetScansError, MapScanID, auth_method_segments,
    entry::{
        self, Bytes, Method, Prefixed, RequestHandler, enforce_client_id_and_scan_id,
        response::BodyKind,
    },
    models,
};

pub trait GetScansIdStatus: MapScanID {
    fn get_scans_id_status(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>>;
}

pub struct GetScansIdStatusHandler<T> {
    get_scans: Arc<T>,
}

impl<T> Prefixed for GetScansIdStatusHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}

impl<S> RequestHandler for GetScansIdStatusHandler<S>
where
    S: GetScansIdStatus + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::GET,
        "scans", "*", "status"
    );

    fn call<'a, 'b>(
        &'b self,
        client_id: Arc<entry::ClientIdentifier>,
        uri: &'a entry::Uri,
        _: Bytes,
    ) -> Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let gsp = self.get_scans.clone();
        let id = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect ID, this is a toolkit error");
        Box::pin(async move {
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                match gsp.get_scans_id_status(id).await {
                    Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for GetScansIdStatusHandler<T>
where
    T: GetScansIdStatus + 'static,
{
    fn from(value: T) -> Self {
        GetScansIdStatusHandler {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansIdStatusHandler<T>
where
    T: GetScansIdStatus + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansIdStatusHandler { get_scans: value }
    }
}

pub type GetScansIDStatusError = GetScansError;

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

    impl MapScanID for Test {
        fn contains_scan_id<'a>(
            &'a self,
            client_id: &'a str,
            scan_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async move {
                if scan_id == "id" {
                    Some(client_id.to_string())
                } else {
                    None
                }
            })
        }
    }

    impl GetScansIdStatus for Test {
        fn get_scans_id_status(
            &self,
            client_id: String,
        ) -> Pin<Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send>>
        {
            let result = models::Status {
                ..Default::default()
            };
            test_utilities::on_client_id_return(client_id, result, GetScansError::NotFound)
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdStatusHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id/status")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn not_found() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdStatusHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans/not_found/status")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_status() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdStatusHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/status")
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
