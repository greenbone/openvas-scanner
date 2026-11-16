use std::sync::Arc;

use scannerlib::notus::{Notus, products_loader};
use tokio::sync::RwLock;

use crate::config::Config;

pub fn config_to_products(config: &Config) -> Arc<RwLock<Notus>> {
    products_loader(&config.notus.products_path, config.feed.signature_check)
}

#[cfg(test)]
mod tests {
    use crate::api::{routes, tests::json_request};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

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
            signature_check: false,
            ..Default::default()
        };
        let notus = crate::config::Notus {
            advisories_path,
            products_path,
            url: None,
        };

        Config {
            feed,
            notus,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn get_notus() -> anyhow::Result<()> {
        let config = config();
        let products = super::config_to_products(&config);
        let router = routes::notus::router(products);

        let req = Request::get("/").body(Body::empty())?;
        let resp = router.oneshot(req).await?;

        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn post_notus_os() -> anyhow::Result<()> {
        let config = config();
        let products = super::config_to_products(&config);
        let router = routes::notus::router(products);

        let req = json_request("POST", "/not_found", &["aha".to_string()]);
        let resp = router.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
