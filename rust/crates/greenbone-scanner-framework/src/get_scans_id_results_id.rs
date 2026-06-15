use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    ExternalError, MapScanID, auth_method_segments,
    entry::{
        self, Bytes, Method, Prefixed, RequestHandler, enforce_client_id_and_scan_id,
        response::BodyKind,
    },
    internal_server_error, models,
};

pub trait GetScansIdResultsId: MapScanID {
    fn get_scans_id_results_id(
        &self,
        id: String,
        result_id: usize,
    ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>>;
}

pub struct GetScansIdResultsIdHandler<T> {
    get_scans: Arc<T>,
}

impl<T> Prefixed for GetScansIdResultsIdHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}
impl<S> RequestHandler for GetScansIdResultsIdHandler<S>
where
    S: GetScansIdResultsId + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::GET,
        "scans", "*", "results", "*"
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
        let mut ids = self.ids(uri).into_iter();

        let id = ids.next().expect("expect ID, this is a toolkit error");
        let rid = ids
            .next()
            .expect("expected result id, this is a toolkit error");
        Box::pin(async move {
            let rid = match rid.parse() {
                Ok(x) => x,
                Err(_) => return GetScansIDResultsIDError::InvalidID.into(),
            };

            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                match gsp.get_scans_id_results_id(id, rid).await {
                    Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for GetScansIdResultsIdHandler<T>
where
    T: GetScansIdResultsId + 'static,
{
    fn from(value: T) -> Self {
        GetScansIdResultsIdHandler {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansIdResultsIdHandler<T>
where
    T: GetScansIdResultsId + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansIdResultsIdHandler { get_scans: value }
    }
}

#[derive(Debug)]
pub enum GetScansIDResultsIDError {
    NotFound,
    InvalidID,
    External(Box<dyn ExternalError + Sync + Send + 'static>),
}

impl<T> From<T> for GetScansIDResultsIDError
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn from(value: T) -> Self {
        Self::External(Box::new(value))
    }
}

impl From<GetScansIDResultsIDError> for BodyKind {
    fn from(e: GetScansIDResultsIDError) -> Self {
        use GetScansIDResultsIDError::*;
        match e {
            NotFound => BodyKind::no_content(StatusCode::NOT_FOUND),
            External(external_error) => internal_server_error!(external_error),
            InvalidID => BodyKind::json_content(
                StatusCode::BAD_REQUEST,
                &entry::response::BadRequest {
                    line: 0,
                    column: 0,
                    message: "result_id must be a positive number".to_owned(),
                },
            ),
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

    impl GetScansIdResultsId for Test {
        fn get_scans_id_results_id(
            &self,
            client_id: String,
            result_id: usize,
        ) -> Pin<Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send>>
        {
            let result = models::Result {
                id: result_id,
                ..Default::default()
            };

            test_utilities::on_client_id_return(
                client_id,
                result,
                GetScansIDResultsIDError::NotFound,
            )
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsIdHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id/results/42")
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
            create_single_handler!(GetScansIdResultsIdHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans/id/results/42")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_rid() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsIdHandler::from(Test {})),
            Some(ClientHash::from("not_found")),
        );

        let req = Request::builder()
            .uri("/scans/id/results/fourtytwo")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_status() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsIdHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/results/42")
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
