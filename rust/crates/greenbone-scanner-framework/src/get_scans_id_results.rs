use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    GetScansError, MapScanID, StreamResult, auth_method_segments,
    entry::{
        self, Bytes, Method, Prefixed, RequestHandler, enforce_client_id_and_scan_id,
        response::BodyKind,
    },
    models,
};

pub trait GetScansIdResults: MapScanID {
    fn get_scans_id_results(
        &self,
        id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> StreamResult<'static, models::Result, GetScansIDResultsError>;
}

pub struct GetScansIdResultsHandler<T> {
    get_scans: Arc<T>,
}

impl<T> Prefixed for GetScansIdResultsHandler<T>
where
    T: Prefixed,
{
    fn prefix(&self) -> &'static str {
        self.get_scans.prefix()
    }
}
impl<S> RequestHandler for GetScansIdResultsHandler<S>
where
    S: GetScansIdResults + Prefixed + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::GET,
        "scans", "*", "results"
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
        let query = uri.query().map(|x| x.to_owned());
        Box::pin(async move {
            let (from, to) = match query {
                Some(x) => x
                    .split('&')
                    .filter_map(|pair| {
                        let mut kv = pair.splitn(2, '=');
                        match kv.next() {
                            Some("range") => kv.next(),
                            Some(_) | None => None,
                        }
                    })
                    .map(|range| {
                        let mut rs = range.splitn(2, '-');
                        (rs.next(), rs.next())
                    })
                    .map(|(from, to)| {
                        let from = match from {
                            Some(x) => x.parse().ok(),
                            None => None,
                        };

                        let to = match to {
                            Some(x) => x.parse().ok(),
                            None => None,
                        };
                        (from, to)
                    })
                    .next()
                    .unwrap_or_default(),
                None => (None, None),
            };
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                let input = gsp.get_scans_id_results(id, from, to);
                BodyKind::from_result_stream(StatusCode::OK, input).await
            })
            .await
        })
    }
}

impl<T> From<T> for GetScansIdResultsHandler<T>
where
    T: GetScansIdResults + 'static,
{
    fn from(value: T) -> Self {
        GetScansIdResultsHandler {
            get_scans: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for GetScansIdResultsHandler<T>
where
    T: GetScansIdResults + 'static,
{
    fn from(value: Arc<T>) -> Self {
        GetScansIdResultsHandler { get_scans: value }
    }
}

pub type GetScansIDResultsError = GetScansError;

#[cfg(test)]
mod tests {

    use std::io;

    use entry::test_utilities;
    use futures::stream;
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

    impl GetScansIdResults for Test {
        fn get_scans_id_results(
            &self,
            client_id: String,
            from: Option<usize>,
            to: Option<usize>,
        ) -> StreamResult<'static, models::Result, GetScansIDResultsError> {
            let ise = ClientHash::from("internal_server_error").to_string();
            if ise == client_id {
                return Box::new(stream::iter(vec![Err(GetScansError::External(Box::new(
                    io::Error::other("oh no"),
                )))]));
            }
            let to = if from.is_some() {
                // for the test case ?range=99
                to.unwrap_or(101)
            } else {
                to.unwrap_or_default()
            };
            let from = from.unwrap_or_default();
            let result: Vec<Result<models::Result, _>> = (from..to)
                .map(|id| {
                    Ok(models::Result {
                        id,
                        ..Default::default()
                    })
                })
                .collect();

            Box::new(stream::iter(result))
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id/results")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn scan_results() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/results")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp = String::from_utf8_lossy(bytes.as_ref());
        insta::assert_snapshot!(resp);
    }

    #[tokio::test]
    async fn scan_results_from_to() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/results?range=10-100")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp: Vec<models::Result> = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(resp.len(), 90);
        insta::assert_ron_snapshot!(resp);
    }

    #[tokio::test]
    async fn scan_results_from() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/results?range=99")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp: Vec<models::Result> = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(resp.len(), 2);
        insta::assert_ron_snapshot!(resp);
    }

    #[tokio::test]
    async fn ignores_invalid_query() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(GetScansIdResultsHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id/results?range=zero-ten&from=1&to=10")
            .method(Method::GET)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp: Vec<models::Result> = serde_json::from_slice(bytes.as_ref()).unwrap();
        assert_eq!(resp.len(), 0);
    }
}
