use std::{pin::Pin, sync::Arc};

use hyper::StatusCode;

use crate::{
    MapScanID, auth_method_segments,
    entry::{
        self, Bytes, Method, Prefixed, RequestHandler, enforce_client_id_and_scan_id,
        response::BodyKind,
    },
    post_scans_id::PostScansIDError,
};

pub trait DeleteScansId: MapScanID + Prefixed {
    fn delete_scans_id(
        &self,
        id: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>>;
}

pub struct DeleteScansIdHandler<T> {
    handler: Arc<T>,
}

impl<S> Prefixed for DeleteScansIdHandler<S>
where
    S: Prefixed + 'static,
{
    fn prefix(&self) -> &'static str {
        self.handler.prefix()
    }
}

impl<S> RequestHandler for DeleteScansIdHandler<S>
where
    S: DeleteScansId + 'static,
{
    auth_method_segments!(
        authenticated: true,
        Method::DELETE,
        "scans", "*"
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
        let gsp = self.handler.clone();
        let id = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect ID, this is a toolkit error");
        Box::pin(async move {
            enforce_client_id_and_scan_id(&client_id, id, gsp.as_ref(), async |id| {
                match gsp.delete_scans_id(id).await {
                    Ok(()) => BodyKind::no_content(StatusCode::NO_CONTENT),
                    Err(e) => e.into(),
                }
            })
            .await
        })
    }
}

impl<T> From<T> for DeleteScansIdHandler<T>
where
    T: DeleteScansId + 'static,
{
    fn from(value: T) -> Self {
        DeleteScansIdHandler {
            handler: Arc::new(value),
        }
    }
}

impl<T> From<Arc<T>> for DeleteScansIdHandler<T>
where
    T: DeleteScansId + 'static,
{
    fn from(value: Arc<T>) -> Self {
        DeleteScansIdHandler { handler: value }
    }
}

pub type DeleteScansIDError = PostScansIDError;

#[cfg(test)]
mod tests {
    use entry::test_utilities::{self};
    use http_body_util::Empty;
    use hyper::{Method, Request, service::Service};

    use super::*;
    use crate::{Authentication, ClientHash, create_single_handler};

    struct Test {}

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

    impl Prefixed for Test {
        fn prefix(&self) -> &'static str {
            ""
        }
    }

    impl DeleteScansId for Test {
        fn delete_scans_id(
            &self,
            id: String,
        ) -> Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send>> {
            let client_id = id.clone();
            let ok = ClientHash::from("ok").to_string();
            let already_running = ClientHash::from("already_running").to_string();
            Box::pin(async move {
                if client_id == ok {
                    return Ok(());
                }
                if client_id == already_running {
                    return Err(DeleteScansIDError::Running);
                }

                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "").into())
            })
        }
    }

    #[tokio::test]
    async fn internal_server_error() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(DeleteScansIdHandler::from(Test {})),
            Some(ClientHash::from("internal_server_error")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn missing_scan() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(DeleteScansIdHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/not_found")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn already_running() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(DeleteScansIdHandler::from(Test {})),
            Some(ClientHash::from("already_running")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn ok() {
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            create_single_handler!(DeleteScansIdHandler::from(Test {})),
            Some(ClientHash::from("ok")),
        );

        let req = Request::builder()
            .uri("/scans/id")
            .method(Method::DELETE)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = entry_point.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
