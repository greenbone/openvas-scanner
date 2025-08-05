use std::sync::Arc;

use greenbone_scanner_framework::{
    ClientIdentifier, OnRequest,
    entry::{Bytes, Method, Uri, response::BodyKind},
};
use http::StatusCode;
use scannerlib::{
    nasl::FSPluginLoader,
    notus::{HashsumProductLoader, Notus, NotusError},
};
use tokio::sync::RwLock;

use crate::config::Config;

type Oz = Notus<HashsumProductLoader>;

pub struct GetOSIcnomingRequest(Arc<RwLock<Oz>>);

impl OnRequest for GetOSIcnomingRequest {
    fn needs_authentication(&self) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async move { false })
    }

    fn on_parts(&self) -> &'static [&'static str] {
        &["notus"]
    }

    fn on_method(&self) -> &'static Method {
        &Method::GET
    }

    fn call<'a, 'b>(
        &'b self,
        _: Arc<ClientIdentifier>,
        _: &'a Uri,
        _: Bytes,
        // req: Request<Body>,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let products = self.0.clone();
        Box::pin(async move {
            let p = products.read_owned().await;
            match tokio::task::spawn_blocking(move || p.get_available_os())
                .await
                .expect("Tokio runtime must be available")
            {
                Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                Err(error) => {
                    tracing::warn!(%error, "Unable to get available products.");
                    BodyKind::no_content(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        })
    }
}

pub struct PostOSIcnomingRequest(Arc<RwLock<Oz>>);

impl OnRequest for PostOSIcnomingRequest {
    fn needs_authentication(&self) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async move { false })
    }

    fn on_parts(&self) -> &'static [&'static str] {
        &["notus", "*"]
    }

    fn on_method(&self) -> &'static Method {
        &Method::POST
    }

    fn call<'a, 'b>(
        &'b self,
        _: Arc<ClientIdentifier>,
        uri: &'a Uri,
        body: Bytes,
    ) -> std::pin::Pin<Box<dyn Future<Output = BodyKind> + Send>>
    where
        'b: 'a,
    {
        let products = self.0.clone();

        let os = self
            .ids(uri)
            .into_iter()
            .next()
            .expect("expect OS, this is a toolkit error");

        Box::pin(async move {
            let mut p = products.write_owned().await;
            match tokio::task::spawn_blocking(move || {
                let packages: Vec<String> = serde_json::from_slice(&body)
                    .map_err(|e| scannerlib::notus::NotusError::PackageParseError(e.to_string()))?;
                p.scan(&os, &packages)
            })
            .await
            .expect("Tokio runtime must be available")
            {
                Ok(x) => BodyKind::json_content(StatusCode::OK, &x),
                Err(NotusError::UnknownProduct(_)) => BodyKind::no_content(StatusCode::NOT_FOUND),
                Err(error) => {
                    tracing::warn!(%error, "Unable to get available products.");
                    BodyKind::no_content(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        })
    }
}

pub fn init(config: &Config) -> (GetOSIcnomingRequest, PostOSIcnomingRequest) {
    let loader = FSPluginLoader::new(config.notus.products_path.to_string_lossy().to_string());
    let loader = HashsumProductLoader::new(loader);
    let notus = Arc::new(RwLock::new(Notus::new(loader, config.feed.signature_check)));
    (
        GetOSIcnomingRequest(notus.clone()),
        PostOSIcnomingRequest(notus),
    )
}

#[cfg(test)]
mod tests {
    use greenbone_scanner_framework::{
        Authentication, ClientHash,
        entry::{Method, test_utilities},
        incoming_request,
    };
    use http::StatusCode;
    use hyper::service::Service;

    use crate::config::Config;
    fn config() -> Config {
        let nasl = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/nasl").into();
        let advisories_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/feed/notus/advisories"
        )
        .into();
        let products_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/feed/notus/products").into();

        let feed = crate::config::Feed {
            path: nasl,
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path,
            products_path,
        };

        Config {
            feed,
            notus,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn get_notus() -> crate::Result<()> {
        let config = config();
        let (undertest, _) = super::init(&config);
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(undertest),
            Some(ClientHash::default()),
        );
        let req = test_utilities::empty_request(Method::GET, "/notus");
        let resp = entry_point.call(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn post_notus_os() -> crate::Result<()> {
        let config = config();
        let (_, undertest) = super::init(&config);
        let entry_point = test_utilities::entry_point(
            Authentication::MTLS,
            incoming_request!(undertest),
            Some(ClientHash::default()),
        );
        let req = test_utilities::json_request(
            Method::POST,
            "/notus/not_found",
            &vec!["aha".to_string()],
        );
        let resp = entry_point.call(req).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = test_utilities::json_request(
            Method::POST,
            "/notus/test",
            &vec!["man-db-1.1.1".to_string()],
        );
        let resp = entry_point.call(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);

        Ok(())
    }
}
