use std::{
    error::Error,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, StreamExt};
use tokio::sync::mpsc::Receiver;

use super::{PackedLayer, Setting};
use crate::container_image_scanner::{ExternalError, Streamer, image::Image};

struct BlobStream {
    receiver: Receiver<Result<PackedLayer, Box<dyn Error + Send + Sync>>>,
}

impl Stream for BlobStream {
    type Item = Result<PackedLayer, Box<dyn Error + Send + Sync>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = Pin::new(&mut self.get_mut().receiver);
        inner.poll_recv(cx)
    }
}

type ArchitectureLayer = (String, Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Registry {
    username: Option<String>,
    password: Option<String>,
    insecure: bool,
    accept_invalid_certs: bool,
}

impl Registry {
    async fn authenticated_client(
        &self,
        scope: &str,
        registry: &str,
    ) -> Result<docker_registry::v2::Client, ExternalError> {
        tracing::trace!(scope, registry, "trying to login");
        docker_registry::v2::Client::configure()
            .insecure_registry(self.insecure)
            .accept_invalid_certs(self.accept_invalid_certs)
            .username(self.username.clone())
            .password(self.password.clone())
            .registry(registry)
            .build()?
            // TODO: change library to automatically use the scope given by the server header
            // information:
            // `www-authenticate: Bearer realm="https://localhost:5001/auth",service="localhost:5000",scope="registry:catalog:*"`
            .authenticate(&[scope])
            .await
            .map_err(|x| x.into())
    }

    async fn catalog_client(
        &self,
        registry: &str,
    ) -> Result<docker_registry::v2::Client, ExternalError> {
        let scope = "registry:catalog:*";
        let client = self.authenticated_client(scope, registry).await?;
        tracing::trace!("authenticated");
        Ok(client)
    }

    async fn pull_client(
        &self,
        registry: &str,
        repository: &str,
    ) -> Result<docker_registry::v2::Client, ExternalError> {
        let scope = format!("repository:{repository}:pull",);
        let client = self.authenticated_client(&scope, registry).await?;
        tracing::trace!("authenticated");
        Ok(client)
    }

    async fn resolve_repository(
        &self,
        registry: &str,
        repository: &str,
    ) -> Vec<Result<Image, ExternalError>> {
        let client = match self.pull_client(registry, repository).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, "unable to pull");
                return vec![Err(e)];
            }
        };
        let repos: Vec<Result<Image, ExternalError>> = client
            .get_tags(repository, None)
            .map(|x| match x {
                Ok(x) => Ok(Image {
                    registry: registry.to_owned(),
                    image: Some(repository.to_owned()),
                    tag: Some(x),
                }),
                Err(x) => {
                    tracing::warn!(error=%x, "unable to resolve_repository");
                    Err(x.into())
                }
            })
            .collect()
            .await;

        repos
    }

    async fn resolve_catalog(&self, registry: &str) -> Vec<Result<Image, ExternalError>> {
        let client = match self.catalog_client(registry).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, "unable to resolve catalog");
                return vec![Err(e)];
            }
        };
        //FIXME: would be better if we don't need to collect here
        let repos: Vec<Result<String, ExternalError>> = client
            .get_catalog(None)
            .map(|x| match x {
                Ok(x) => Ok(x),
                Err(x) => Err(x.into()),
            })
            .collect()
            .await;
        tracing::trace!(repos = repos.len(), "Repositories");

        let mut results: Vec<Result<Image, ExternalError>> = Vec::with_capacity(repos.len());
        for r in repos {
            match r {
                Ok(x) => results.extend(self.resolve_repository(registry, &x).await),
                Err(e) => {
                    tracing::warn!(error=%e, "unable to get_catalog");
                    results.push(Err(e))
                }
            }
        }
        tracing::trace!(results = results.len(), "Results");

        results
    }

    async fn fetch_digest_layer(
        &self,
        image: &Image,
    ) -> Result<
        (
            docker_registry::v2::Client,
            Vec<Result<ArchitectureLayer, ExternalError>>,
        ),
        ExternalError,
    > {
        let repository = match &image.image {
            None => {
                return Err(
                    io::Error::new(io::ErrorKind::NotFound, "missing repository/image.").into(),
                );
            }
            Some(x) => x,
        };
        let tag = match &image.tag {
            None => {
                return Err(io::Error::new(io::ErrorKind::NotFound, "missing image tag.").into());
            }
            Some(x) => x,
        };

        let registry = &image.registry;
        let client = self.pull_client(registry, repository).await?;
        let manifest = client.get_manifest(repository, tag).await?;
        let architectures = manifest.architectures()?;
        tracing::debug!(?architectures, ?image, "Supported architectures");
        Ok((
            client,
            architectures
                .iter()
                .map(|x| {
                    manifest
                        .layers_digests(Some(x))
                        .map(|l| (x.to_owned(), l))
                        .map_err(|x| x.into())
                })
                .collect(),
        ))
    }
}

impl super::Registry for Registry {
    fn initialize(
        credential: Option<super::Credential>,
        settings: Vec<Setting>,
    ) -> Result<Registry, ExternalError> {
        let insecure = settings.iter().any(|x| matches!(x, Setting::Insecure));
        let accept_invalid_certs = settings
            .iter()
            .any(|x| matches!(x, Setting::AcceptInvalidCerts));

        Ok(Self {
            username: credential.clone().map(|x| x.username),
            password: credential.clone().map(|x| x.password),
            insecure,
            accept_invalid_certs,
        })
    }

    fn resolve_image(
        &self,
        image: super::Image,
    ) -> Pin<
        Box<
            dyn Future<Output = Vec<Result<super::Image, super::ExternalError>>> + Send + Sync + '_,
        >,
    > {
        Box::pin(async move {
            match image {
                Image {
                    registry,
                    image: None,
                    tag: _,
                } => self.resolve_catalog(&registry).await,
                Image {
                    registry,
                    image: Some(image),
                    tag: None,
                } => self.resolve_repository(&registry, &image).await,
                image => vec![Ok(image)],
            }
        })
    }

    fn pull_image(
        &self,
        image: super::Image,
    ) -> Streamer<Result<PackedLayer, super::ExternalError>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(5);
        let result = BlobStream { receiver };
        let that = self.clone();
        tokio::spawn(async move {
            let send_log = async |e| match sender.send(Err(e)).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(error=%e, "Receiver closed.")
                }
            };
            tracing::debug!(image = %image, "Downloading digest");

            let (client, og) = match that.fetch_digest_layer(&image).await {
                Ok((client, layer)) => (client, layer),
                Err(e) => {
                    send_log(e).await;
                    return;
                }
            };
            // TODO calculate sum should be better
            let mut digest = Vec::with_capacity(og.len() * 2);
            for r in og {
                match r {
                    Ok((arch, digests)) => {
                        for d in digests {
                            digest.push((arch.to_owned(), d));
                        }
                    }
                    Err(e) => send_log(e).await,
                }
            }

            let futures = digest
                .iter()
                .enumerate()
                .map(|(i, (architecture, digest))| {
                    (
                        i,
                        architecture,
                        client.get_blob(
                            image
                                .image
                                .as_ref()
                                .expect("already verified in fetch_digest_layer"),
                            digest,
                        ),
                    )
                });
            tracing::debug!(image = %image, layer_amount = futures.len(), "Downloading layers");
            for f in futures {
                let (index, arch, fdata) = f;
                let result = fdata
                    .await
                    .map(|data| PackedLayer {
                        data,
                        arch: arch.to_owned(),
                        index,
                    })
                    .map_err(|x| x.into());

                tracing::debug!(image = %image, layer= index, "Downloaded layer");
                if let Err(e) = sender.send(result).await {
                    tracing::debug!(error=%e, "receiver dropped");
                    break;
                }
            }
            drop(sender);
        });

        Box::pin(result)
    }
}

#[cfg(test)]
pub mod fake {
    use std::collections::{HashMap, HashSet};

    use mockito::Matcher;
    use sha2::{Digest, Sha256};

    use crate::container_image_scanner::image::Image;

    pub struct RegistryMock {
        pub server: mockito::ServerGuard,
        // the mocks must be stored otherwise the Server will return 501
        mocks: Vec<mockito::Mock>,
    }

    impl RegistryMock {
        fn authentication_mock(server: &mut mockito::ServerGuard) -> Vec<mockito::Mock> {
            vec![
                server
                    .mock("GET", "/v2/")
                    .with_status(401)
                    .with_header(
                        "WWW-Authenticate",
                        &format!(r#"Bearer realm="http://{}/token""#, server.host_with_port()),
                    )
                    .create(),
                server
                    .mock("GET", "/token")
                    .match_query(Matcher::Any)
                    .with_status(200)
                    .with_header("Content-Type", "application/json")
                    .with_body(r#"{"token": "waldfee"}"#)
                    .create(),
            ]
        }

        fn catalog_mocks(
            server: &mut mockito::ServerGuard,
            repos: Vec<String>,
        ) -> Vec<mockito::Mock> {
            let repos = format!(
                "{{\"repositories\": [{}]}}",
                repos
                    .iter()
                    .map(|x| format!("\"{x}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            );

            vec![
                server
                    .mock("GET", "/v2/_catalog")
                    .with_status(200)
                    .with_header("Content-Type", "application/json")
                    .with_body(repos)
                    .create(),
            ]
        }

        fn tag_list_mocks(
            server: &mut mockito::ServerGuard,
            image: String,
            tags: Vec<String>,
        ) -> Vec<mockito::Mock> {
            let tags = format!(
                r#"{{"name": "{}", "tags": [ {} ]}}"#,
                image,
                tags.iter()
                    .map(|x| format!("\"{x}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let uri = format!("/v2/{image}/tags/list");
            //let addr = server.host_with_port();
            vec![
                server
                    .mock("GET", &uri as &str)
                    .with_status(200)
                    .with_body(tags)
                    .with_header("Content-Type", "application/json")
                    //.with_header(
                    //    "Link",
                    //    &format!(r#"<{}/v2/_tags?n=1&next_page=t1>; rel="next""#, addr),
                    //)
                    .create(),
            ]
        }

        fn hash_hex(input: &[u8]) -> String {
            let mut hasher = Sha256::new();
            hasher.update(input);
            let result = hasher.finalize();
            hex::encode(result)
        }

        fn pull_mocks(server: &mut mockito::ServerGuard) -> Vec<mockito::Mock> {
            const NICHTSFREI_VICTIM_LAYER: &[u8] = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/layers/victim.tar.gz"
            ));
            let size = NICHTSFREI_VICTIM_LAYER.len();
            let hash_victim_layer = Self::hash_hex(NICHTSFREI_VICTIM_LAYER);
            let hash_blob_config = Self::hash_hex("4242".as_bytes());

            let nichtsfrei_victim_latest = format!(
                r#"
       {{
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": {size},
         "digest": "sha256:{hash_victim_layer}"
      }}
      "#
            );

            let manifest_json = format!(
                r#"
{{ 
  "schemaVersion": 2,
  "config": {{
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": {size},
      "digest": "sha256:{hash_blob_config}"
   }},
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "layers": [
    {nichtsfrei_victim_latest}
  ]
}}

            "#
            );

            vec![
                server
                    .mock("GET", "/v2/nichtsfrei/victim/manifests/v1")
                    .with_status(200)
                    .with_header(
                        "Content-Type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .with_header(
                        "docker-content-digest",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .with_body(manifest_json.clone())
                    .create(),
                server
                    .mock("GET", "/v2/nichtsfrei/victim/manifests/latest")
                    .with_status(200)
                    .with_header(
                        "Content-Type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .with_header(
                        "docker-content-digest",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .with_body(manifest_json)
                    .create(),
                server
                    .mock(
                        "GET",
                        &format!("/v2/nichtsfrei/victim/blobs/sha256:{hash_blob_config}") as &str,
                    )
                    .with_status(200)
                    .with_body("{\"architecture\": \"amd64\"}")
                    .create(),
                server
                    .mock(
                        "GET",
                        &format!("/v2/nichtsfrei/victim/blobs/sha256:{hash_victim_layer}") as &str,
                    )
                    .with_status(200)
                    .with_body(NICHTSFREI_VICTIM_LAYER)
                    .create(),
            ]
        }

        pub fn supported_images() -> Vec<Image> {
            vec![
                Image {
                    // registry will always be the addr of the mock
                    registry: Default::default(),
                    image: Some("nichtsfrei/victim".to_owned()),
                    tag: "latest".to_owned().into(),
                },
                Image {
                    registry: Default::default(),
                    image: Some("nichtsfrei/victim".to_owned()),
                    tag: "v1".to_owned().into(),
                },
            ]
        }

        async fn authenticated() -> Self {
            let mut server = mockito::Server::new_async().await;
            let mocks = Self::authentication_mock(&mut server);
            RegistryMock { server, mocks }
        }

        /// Creates a registry v2 mock that can be used for testing
        ///
        /// Creates caralog and image list for each given image, but manifest as well as bloc
        /// download only for nichtsfrei/victim:latest. This is because there is just one binary
        /// layer available at the moment.
        ///
        /// If new entries are added to the build.rs and inside `test-data/;layers` those
        /// manifest_mocks needs to be extended.
        pub async fn serve_images(images: Vec<Image>) -> Self {
            let mut result = Self::authenticated().await;
            let lookup_table: HashMap<String, HashSet<String>> = images
                .into_iter()
                .filter_map(|entry| entry.image.map(|image| (image, entry.tag)))
                .fold(HashMap::new(), |mut table, (image, tag)| {
                    let entry = table.entry(image).or_default();
                    if let Some(tag) = tag {
                        entry.insert(tag);
                    }
                    table
                });

            let server = &mut result.server;
            let mocks = &mut result.mocks;

            let repos = lookup_table.keys().cloned().collect();
            mocks.extend(Self::catalog_mocks(server, repos));

            for (image, tags) in lookup_table {
                let tags = tags.into_iter().collect();
                mocks.extend(Self::tag_list_mocks(server, image, tags));
            }
            mocks.extend(Self::pull_mocks(server));

            result
        }

        pub fn address(&self) -> String {
            self.server.host_with_port()
        }
    }
}

#[cfg(test)]
mod tests {

    use futures::StreamExt;

    use super::fake::RegistryMock;
    use crate::container_image_scanner::image::{Credential, Image, Registry, RegistrySetting};

    #[tokio::test]
    async fn resolve_images() {
        let images = vec![
            Image {
                // registry will always be the addr of the mock
                registry: Default::default(),
                image: Some("nichtsfrei/victim".to_owned()),
                tag: "latest".to_owned().into(),
            },
            Image {
                registry: Default::default(),
                image: Some("nichtsfrei/victim".to_owned()),
                tag: "v1".to_owned().into(),
            },
            Image {
                registry: Default::default(),
                image: Some("nichtsfrei/victim".to_owned()),
                tag: "v2".to_owned().into(),
            },
            Image {
                // registry will always be the addr of the mock
                registry: Default::default(),
                image: Some("greenbone/gvmd".to_owned()),
                tag: "latest".to_owned().into(),
            },
            Image {
                registry: Default::default(),
                image: Some("greenbone/gvmd".to_owned()),
                tag: "v1".to_owned().into(),
            },
            Image {
                registry: Default::default(),
                image: Some("greenbone/gvmd".to_owned()),
                tag: "v2".to_owned().into(),
            },
        ];

        let server = RegistryMock::serve_images(images.clone()).await;

        let addr = server.server.host_with_port();

        let credential = Credential {
            username: "user".to_owned(),
            password: "password".to_owned(),
        };

        let aha = super::Registry::initialize(Some(credential), vec![RegistrySetting::Insecure])
            .expect("Registry cannot fail to initialize");
        let image = Image {
            registry: addr,
            image: None,
            tag: None,
        };
        let client = aha.resolve_image(image).await;
        let count_images = client.iter().filter(|x| x.is_ok()).count();
        assert_eq!(count_images, images.len());
    }

    #[tokio::test]
    async fn pull_image() {
        let mut image = Image {
            // registry will always be the addr of the mock
            registry: Default::default(),
            image: Some("nichtsfrei/victim".to_owned()),
            tag: "latest".to_owned().into(),
        };

        //use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
        //let filter = tracing_subscriber::filter::Targets::new()
        //    .with_default(tracing::Level::TRACE)
        //    .with_target("hyper_util", tracing::Level::INFO);
        //tracing_subscriber::registry()
        //    .with(tracing_subscriber::fmt::layer())
        //    .with(filter)
        //    .init();

        let server = RegistryMock::serve_images(vec![image.clone()]).await;

        image.registry = server.server.host_with_port();

        let credential = Credential {
            username: "user".to_owned(),
            password: "password".to_owned(),
        };

        let aha = super::Registry::initialize(Some(credential), vec![RegistrySetting::Insecure])
            .expect("Registry cannot fail to initialize");
        let mut layer = aha.pull_image(image);
        let mut count = 0;
        while let Some(r) = layer.next().await {
            let _ = r.unwrap();
            count += 1;
        }
        assert_eq!(count, 1);
    }
}
