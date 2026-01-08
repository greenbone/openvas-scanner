use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use docker_registry::v2::manifest::Manifest;
use futures::{Stream, StreamExt, TryStreamExt};
use tokio::sync::mpsc::Receiver;

use super::{PackedLayer, Setting};
use crate::container_image_scanner::{
    Streamer,
    benchy::{self, Measured},
    image::{
        Image,
        registry::{RegistryError, RegistryErrorKind},
    },
};

struct BlobStream {
    receiver: Receiver<Result<PackedLayer, RegistryError>>,
}

impl Stream for BlobStream {
    type Item = Result<PackedLayer, RegistryError>;

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

#[derive(Debug, Clone)]
enum Filter {
    StartsWith(String),
}

impl Filter {
    pub fn matches(&self, other: &str) -> bool {
        tracing::debug!(?self, other, "Matches");
        match self {
            Filter::StartsWith(value) => other.starts_with(value),
        }
    }
}

struct ClientBuilder {
    username: Option<String>,
    password: Option<String>,
    insecure: bool,
    accept_invalid_certs: bool,
    scope: String,
    registry: String,
}

impl ClientBuilder {
    fn error_kind(
        &self,
        kind: RegistryErrorKind,
        source: docker_registry::errors::Error,
    ) -> RegistryError {
        tracing::warn!(?source, %kind, self.registry, self.scope);
        RegistryError {
            registry: Some(self.registry.to_owned()),
            kind,
            status_code: match source {
                docker_registry::errors::Error::UnexpectedHttpStatus(status)
                | docker_registry::errors::Error::Server { status } => Some(status.as_u16()),
                _ => None,
            },
        }
    }
    fn catalog_error(&self, source: docker_registry::errors::Error) -> RegistryError {
        self.error_kind(RegistryErrorKind::Catalog, source)
    }

    fn authenticatation_error(&self, source: docker_registry::errors::Error) -> RegistryError {
        self.error_kind(
            RegistryErrorKind::Authentication {
                scope: self.scope.to_owned(),
            },
            source,
        )
    }

    fn tag_error(&self, source: docker_registry::errors::Error) -> RegistryError {
        self.error_kind(RegistryErrorKind::Tag, source)
    }

    fn manifest_error(&self, source: docker_registry::errors::Error) -> RegistryError {
        self.error_kind(RegistryErrorKind::Manifest, source)
    }

    fn blob_error(&self, source: docker_registry::errors::Error) -> RegistryError {
        self.error_kind(RegistryErrorKind::Blob, source)
    }
}

impl ClientBuilder {
    pub async fn authenticated(&self) -> Result<docker_registry::v2::Client, RegistryError> {
        let scope = &self.scope;
        let registry = &self.registry;
        tracing::trace!(scope, registry, "trying to login");
        let as_ce = |error| self.authenticatation_error(error);
        docker_registry::v2::Client::configure()
            .insecure_registry(self.insecure)
            .accept_invalid_certs(self.accept_invalid_certs)
            .username(self.username.clone())
            .password(self.password.clone())
            .registry(registry)
            .build()
            .map_err(as_ce)?
            // TODO: change library to automatically use the scope given by the server header
            // information:
            // `www-authenticate: Bearer realm="https://localhost:5001/auth",service="localhost:5000",scope="registry:catalog:*"`
            .authenticate(&[scope])
            .await
            .map_err(as_ce)
    }
}

struct Client {
    builder: ClientBuilder,
    client: docker_registry::v2::Client,
    max_retries: usize,
}

impl Client {
    pub async fn authenticated(
        username: Option<String>,
        password: Option<String>,
        insecure: bool,
        accept_invalid_certs: bool,
        scope: String,
        registry: String,
    ) -> Result<Client, RegistryError> {
        let builder = ClientBuilder {
            username,
            password,
            insecure,
            accept_invalid_certs,
            scope,
            registry,
        };
        let client = builder.authenticated().await?;
        Ok(Self {
            builder,
            client,
            max_retries: 3,
        })
    }

    pub fn get_catalog<'a>(
        &'a mut self,
        paginate: Option<u32>,
    ) -> impl Stream<Item = Result<String, RegistryError>> + 'a {
        self.client
            .get_catalog(paginate)
            .map_err(|x| self.builder.catalog_error(x))
    }

    pub fn get_tags<'a>(
        &'a mut self,
        name: &'a str,
        paginate: Option<u32>,
    ) -> impl Stream<Item = Result<String, RegistryError>> + 'a {
        self.client
            .get_tags(name, paginate)
            .map_err(|x| self.builder.tag_error(x))
    }

    pub async fn get_manifest(
        &mut self,
        name: &str,
        reference: &str,
    ) -> Result<(Manifest, Option<String>), RegistryError> {
        loop {
            match self
                .client
                .get_manifest_and_ref(name, reference)
                .await
                .map_err(|source| self.builder.manifest_error(source))
            {
                Err(error) if self.max_retries > 0 && error.can_retry() => {
                    self.max_retries -= 1;
                    tracing::warn!(%error, retries=self.max_retries, "Unable to get manifest. Retrying.");
                    if error.needs_reauthentication() {
                        self.client = self.builder.authenticated().await?;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok(x) => return Ok(x),
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn get_blob(&mut self, name: &str, digest: &str) -> Result<Vec<u8>, RegistryError> {
        // Remove retry and just pull the image again from scratch on error
        loop {
            match self
                .client
                .get_blob(name, digest)
                .await
                .map_err(|source| self.builder.blob_error(source))
            {
                Err(error) if self.max_retries > 0 && error.can_retry() => {
                    self.max_retries -= 1;
                    tracing::warn!(name, digest, %error, retries=self.max_retries, "Unable to get blob. Retrying.");

                    if error.needs_reauthentication() {
                        self.client = self.builder.authenticated().await?;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok(x) => return Ok(x),
                Err(error) => return Err(error),
            }
        }
    }
}

impl Registry {
    async fn catalog_client(&self, registry: &str) -> Result<Client, RegistryError> {
        let scope = "registry:catalog:*";
        Client::authenticated(
            self.username.clone(),
            self.password.clone(),
            self.insecure,
            self.accept_invalid_certs,
            scope.to_owned(),
            registry.to_owned(),
        )
        .await
    }

    async fn pull_client(&self, registry: &str, repository: &str) -> Result<Client, RegistryError> {
        let scope = format!("repository:{repository}:pull",);
        Client::authenticated(
            self.username.clone(),
            self.password.clone(),
            self.insecure,
            self.accept_invalid_certs,
            scope.to_owned(),
            registry.to_owned(),
        )
        .await
    }

    async fn resolve_or_search_repository(
        &self,
        registry: &str,
        repository: &str,
    ) -> Vec<Result<Image, RegistryError>> {
        tracing::debug!(registry, repository, "resolve_or_search_repository");
        let mut client = match self.pull_client(registry, repository).await {
            Ok(x) => x,
            Err(e) => {
                tracing::info!(registry, repository, error=%e, "Trying to find owner through catalog and filtering.");
                return self
                    .resolve_catalog(registry, Some(Filter::StartsWith(repository.to_owned())))
                    .await;
            }
        };
        let repos: Vec<Result<Image, RegistryError>> = client
            .get_tags(repository, None)
            .map(|x| match x {
                Ok(x) => Ok(Image {
                    registry: registry.to_owned(),
                    image: Some(repository.to_owned()),
                    tag: Some(x),
                }),
                Err(x) => {
                    tracing::warn!(error=%x, "unable to resolve_repository");
                    Err(x)
                }
            })
            .collect()
            .await;

        repos
    }

    async fn resolve_repository(
        &self,
        registry: &str,
        repository: &str,
    ) -> Vec<Result<Image, RegistryError>> {
        let mut client = match self.pull_client(registry, repository).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(registry, repository, error=%e, "Unable to resolve repository");
                return vec![Err(e)];
            }
        };
        let repos: Vec<Result<Image, RegistryError>> = client
            .get_tags(repository, None)
            .map(|x| match x {
                Ok(x) => {
                    let image = Image {
                        registry: registry.to_owned(),
                        image: Some(repository.to_owned()),
                        tag: Some(x),
                    };
                    tracing::trace!(%image, "Found");
                    Ok(image)
                }
                Err(x) => {
                    tracing::warn!(error=%x, "unable to resolve_repository");
                    Err(x)
                }
            })
            .collect()
            .await;

        tracing::debug!(registry, repository, images = repos.len(), "resolved");

        repos
    }

    async fn resolve_catalog(
        &self,
        registry: &str,
        filter: Option<Filter>,
    ) -> Vec<Result<Image, RegistryError>> {
        tracing::debug!(registry, ?filter, "resolve_catalog");
        let mut client = match self.catalog_client(registry).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error=%e, "unable to resolve catalog");
                return vec![Err(e)];
            }
        };
        let results: Vec<_> = client
            .get_catalog(None)
            .filter_map(|catalog| {
                let filter = filter.clone();
                let that = self.to_owned();
                let registry = registry.to_owned();
                async move {
                    match catalog {
                        Ok(repository) => {
                            if filter
                                .as_ref()
                                .map(|y| y.matches(&repository))
                                .unwrap_or(true)
                            {
                                Some(that.resolve_repository(&registry, &repository).await)
                            } else {
                                tracing::debug!(registry, repository, "Ignoring");
                                None
                            }
                        }
                        Err(error) => Some(vec![Err(error)]),
                    }
                }
            })
            .flat_map(futures::stream::iter)
            .collect()
            .await;

        tracing::debug!(results = results.len(), "Found images.");

        results
    }

    async fn fetch_digest_layer(
        &self,
        image: &Image,
    ) -> Result<(Client, Vec<Result<ArchitectureLayer, RegistryError>>), RegistryError> {
        let repository = match image.image() {
            None => {
                return Err(RegistryError::no_repository());
            }
            Some(x) => x,
        };
        let tag = match image.tag() {
            None => return Err(RegistryError::no_tag()),
            Some(x) => x,
        };

        let registry = &image.registry;
        let mut client = self.pull_client(registry, repository).await?;

        // _digest will be needed for start_host message
        let (manifest, _digest) = client.get_manifest(repository, tag).await?;
        let architectures = manifest.architectures().unwrap_or_default();
        tracing::trace!(?architectures, ?image, "Supported architectures");
        Ok((
            client,
            architectures
                .iter()
                .map(|x| {
                    manifest
                        .layers_digests(Some(x))
                        .map(|l| (x.to_owned(), l))
                        .map_err(|x| {
                            let kind = RegistryErrorKind::Manifest;
                            tracing::warn!(%kind, registry, source=%x);
                            RegistryError {
                                registry: Some(registry.to_owned()),
                                kind,
                                status_code: None,
                            }
                        })
                })
                .collect(),
        ))
    }
}

impl super::Registry for Registry {
    fn initialize(
        credential: Option<super::Credential>,
        settings: Vec<Setting>,
    ) -> Result<Registry, RegistryError> {
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
    ) -> Pin<Box<dyn Future<Output = Vec<Result<super::Image, RegistryError>>> + Send + Sync + '_>>
    {
        Box::pin(async move {
            match image {
                Image {
                    registry,
                    image: None,
                    tag: _,
                } => self.resolve_catalog(&registry, None).await,
                Image {
                    registry,
                    image: Some(image),
                    tag: None,
                } => self.resolve_or_search_repository(&registry, &image).await,
                image => vec![Ok(image)],
            }
        })
    }

    fn pull_image(&self, image: super::Image) -> Streamer<Result<PackedLayer, RegistryError>> {
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
            tracing::trace!(image = %image, "Downloading digest");

            // TODO: refavtor
            let (mut client, og) = match that.fetch_digest_layer(&image).await {
                Ok((client, layer)) => (client, layer),
                Err(e) => {
                    send_log(e).await;
                    return;
                }
            };

            let mut digest = Vec::with_capacity(og.len() * 2);
            for r in og {
                match r {
                    Ok((arch, digests)) => {
                        for d in digests {
                            digest.push((arch.to_owned(), d));
                        }
                    }
                    Err(e) => {
                        send_log(e).await;
                        return;
                    }
                }
            }

            for (index, (arch, digest)) in digest.iter().enumerate() {
                let blob = client.get_blob(
                    image
                        .image()
                        .as_ref()
                        .expect("already verified in fetch_digest_layer"),
                    digest,
                );

                // TODO: I don't think we should continue on error
                let result = benchy::measure(blob)
                    .await
                    .into_packed_layer(arch.to_owned(), index);

                tracing::trace!(image = %image, layer= index, "Downloaded layer");
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

impl Measured<Result<Vec<u8>, RegistryError>> {
    fn into_packed_layer(self, arch: String, index: usize) -> Result<PackedLayer, RegistryError> {
        let (download_time, result) = self.unpack();

        result.map(|data| PackedLayer {
            data,
            arch: arch.to_owned(),
            index,
            download_time,
        })
    }
}

#[cfg(test)]
pub mod fake {
    use std::collections::{HashMap, HashSet};

    use itertools::Itertools;
    use mockito::Matcher;
    use sha2::{Digest, Sha256};

    use crate::container_image_scanner::image::Image;

    fn hash_hex(input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn digest(input: &[u8]) -> String {
        format!("sha256:{}", hash_hex(input))
    }

    #[derive(Debug, Clone)]
    struct Layer<'a> {
        data: &'a [u8],
    }

    impl<'a> From<&'a [u8]> for Layer<'a> {
        fn from(value: &'a [u8]) -> Self {
            Self { data: value }
        }
    }

    impl<'a> Layer<'a> {
        fn size(&self) -> usize {
            self.data.len()
        }

        fn digest(&self) -> String {
            digest(self.data)
        }

        fn json(&self) -> String {
            format!(
                r#" {{ "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": {}, "digest": "{}" }}"#,
                self.size(),
                self.digest()
            )
        }

        pub fn mock(
            &self,
            server: &mut mockito::ServerGuard,
            image: &Image,
            status_code: usize,
        ) -> mockito::Mock {
            let url = format!("/v2/{}/blobs/{}", image.image().unwrap(), self.digest());
            server
                .mock("GET", &url as &str)
                .with_status(status_code)
                .with_body(self.data)
                .create()
        }
    }

    struct BlobConfig<'a> {
        image: &'a Image,
        digest: String,
        architecture: String,
        layer: Vec<Layer<'a>>,
    }

    impl<'a> BlobConfig<'a> {
        pub fn new(image: &'a Image, architecture: String, layer: Vec<Layer<'a>>) -> Self {
            let digest = digest(image.to_string().as_bytes());
            Self {
                image,
                digest,
                architecture,
                layer,
            }
        }

        pub fn size(&self) -> usize {
            self.layer.iter().map(|x| x.size()).sum()
        }

        pub fn json(&self) -> String {
            format!(
                r#"{{"architecture": "{}", "config": {{ "Labels": null}}}}"#,
                self.architecture
            )
        }

        pub fn mock(&self, server: &mut mockito::ServerGuard, status_code: usize) -> mockito::Mock {
            let bobconfig_url =
                format!("/v2/{}/blobs/{}", self.image.image().unwrap(), self.digest);

            server
                .mock("GET", &bobconfig_url as &str)
                .with_status(status_code)
                .with_body(self.json())
                .create()
        }
    }

    pub struct Catalog<'a> {
        images: &'a [Image],
    }

    impl<'a> Catalog<'a> {
        pub fn json(&self) -> String {
            let repos = self
                .images
                .iter()
                .filter_map(|x| x.image.as_ref())
                .map(|x| format!(r#""{x}""#))
                .unique()
                .join(",");
            format!("{{\"repositories\": [{}]}}", repos)
        }

        fn mock(&self, server: &mut mockito::ServerGuard, status_code: usize) -> mockito::Mock {
            server
                .mock("GET", "/v2/_catalog")
                .with_status(status_code)
                .with_header("Content-Type", "application/json")
                .with_body(self.json())
                .create()
        }
    }

    pub struct Manifest<'a> {
        blobconfig: BlobConfig<'a>,
    }

    impl<'a> Manifest<'a> {
        pub fn json(&self) -> String {
            let blob_size = self.blobconfig.size();
            let blob_digest = &self.blobconfig.digest;
            let layers = self.blobconfig.layer.iter().map(|x| x.json()).join(",");
            format!(
                r#"{{ 
  "schemaVersion": 2,
  "config": {{
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": {blob_size},
      "digest": "{blob_digest}"
   }},
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "layers": [
    {layers}
  ]
}}"#
            )
        }

        fn mock(&self, server: &mut mockito::ServerGuard, status_code: usize) -> mockito::Mock {
            let path = format!(
                "/v2/{}/manifests/{}",
                self.blobconfig.image.image().unwrap(),
                self.blobconfig.image.tag().unwrap()
            );
            server
                .mock("GET", &path as &str)
                .with_status(status_code)
                .with_header(
                    "Content-Type",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .with_header(
                    "docker-content-digest",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .with_body(self.json())
                .create()
        }
    }

    pub struct Pull<'a> {
        images: &'a [Image],
    }

    impl<'a> Pull<'a> {
        fn mocks(
            &self,
            server: &mut mockito::ServerGuard,
            status_codes: Vec<usize>,
        ) -> Vec<mockito::Mock> {
            const NICHTSFREI_VICTIM_LAYER: &[u8] = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/layers/victim.tar.gz"
            ));

            // we currently just have one layer example and are repeating it for each image.
            let layer = vec![Layer::from(NICHTSFREI_VICTIM_LAYER)];

            let manifests = self.images.iter().map(|image| {
                let manifest = Manifest {
                    blobconfig: BlobConfig::new(image, "amd64".to_owned(), layer.clone()),
                };
                FakeResponses::Manifest(manifest)
            });

            manifests
                .flat_map(|x| x.mocks(server, status_codes.clone()))
                .collect()
        }
    }

    pub struct Tags<'a> {
        images: &'a [Image],
    }

    impl<'a> Tags<'a> {
        pub fn mocks(
            &self,
            server: &mut mockito::ServerGuard,
            mut status_codes: Vec<usize>,
        ) -> Vec<mockito::Mock> {
            let lookup_table: HashMap<String, HashSet<String>> = self
                .images
                .iter()
                .cloned()
                .filter_map(|entry| entry.image.map(|image| (image, entry.tag)))
                .fold(HashMap::new(), |mut table, (image, tag)| {
                    let entry = table.entry(image).or_default();
                    if let Some(tag) = tag {
                        entry.insert(tag);
                    }
                    table
                });
            let mut mocks = Vec::with_capacity(self.images.len());
            for (image, tags) in lookup_table {
                let tags = format!(
                    r#"{{"name": "{}", "tags": [ {} ]}}"#,
                    image,
                    tags.iter()
                        .map(|x| format!("\"{x}\""))
                        .collect::<Vec<_>>()
                        .join(",")
                );

                let uri = format!("/v2/{image}/tags/list");
                mocks.push(
                    server
                        .mock("GET", &uri as &str)
                        .with_status(status_codes.pop().unwrap_or(200))
                        .with_body(tags)
                        .with_header("Content-Type", "application/json")
                        //.with_header(
                        //    "Link",
                        //    &format!(r#"<{}/v2/_tags?n=1&next_page=t1>; rel="next""#, addr),
                        //)
                        .create(),
                );
            }
            mocks
        }
    }

    pub enum FakeResponses<'a> {
        Authenticated,
        Catalog(Catalog<'a>),
        Tags(Tags<'a>),
        Manifest(Manifest<'a>),
        Pull(Pull<'a>),
    }

    impl<'a> FakeResponses<'a> {
        fn mock_count(&self) -> usize {
            match self {
                FakeResponses::Manifest(manifest) => 1 + 1 + manifest.blobconfig.layer.len(),
                FakeResponses::Catalog(_) => 1,
                FakeResponses::Pull(pull) => pull.images.len() * 3,
                FakeResponses::Authenticated => 2,
                FakeResponses::Tags(tags) => tags.images.len(),
            }
        }

        fn mocks(
            &self,
            server: &mut mockito::ServerGuard,
            mut status_codes: Vec<usize>,
        ) -> Vec<mockito::Mock> {
            let mut next_sc = || status_codes.pop().unwrap_or(200);

            match self {
                FakeResponses::Manifest(manifest) => {
                    let mut results = Vec::with_capacity(self.mock_count());
                    results.push(manifest.mock(server, next_sc()));
                    results.push(manifest.blobconfig.mock(server, next_sc()));
                    for l in manifest.blobconfig.layer.iter() {
                        results.push(l.mock(server, manifest.blobconfig.image, next_sc()));
                    }
                    results
                }
                FakeResponses::Catalog(catalog) => vec![catalog.mock(server, next_sc())],
                FakeResponses::Pull(pull) => pull.mocks(server, status_codes),
                FakeResponses::Authenticated => {
                    vec![
                        server
                            .mock("GET", "/v2/")
                            .with_status(401)
                            .with_header(
                                "WWW-Authenticate",
                                &format!(
                                    r#"Bearer realm="http://{}/token""#,
                                    server.host_with_port()
                                ),
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
                FakeResponses::Tags(tags) => tags.mocks(server, status_codes),
            }
        }
    }

    pub struct RegistryMock {
        pub server: mockito::ServerGuard,
        // the mocks must be stored otherwise the Server will return 501
        _mocks: Vec<mockito::Mock>,
    }

    struct PortExpander {
        ports: Vec<usize>,
    }

    impl From<&[usize]> for PortExpander {
        fn from(value: &[usize]) -> Self {
            let mut ports = value.to_owned();
            ports.reverse();
            Self { ports }
        }
    }

    impl PortExpander {
        fn expand(&mut self, fr: &FakeResponses) -> Vec<usize> {
            let mut result = Vec::with_capacity(fr.mock_count());
            for _ in 0..fr.mock_count() {
                result.push(self.ports.pop().unwrap_or(200));
            }
            result
        }
    }

    impl RegistryMock {
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

        /// Creates a registry v2 mock that can be used for testing
        ///
        /// Creates caralog and image list for each given image, but manifest as well as bloc
        /// download only for nichtsfrei/victim:latest. This is because there is just one binary
        /// layer available at the moment.
        ///
        /// If new entries are added to the build.rs and inside `test-data/;layers` those
        /// manifest_mocks needs to be extended within FakeResponses::Pull.
        pub async fn serve_images(images: &[Image], status_codes: &[usize]) -> Self {
            let mut port_expander: PortExpander = status_codes.into();
            let mut server = mockito::Server::new_async().await;
            let mocks = [
                FakeResponses::Authenticated,
                FakeResponses::Catalog(Catalog { images }),
                FakeResponses::Tags(Tags { images }),
                FakeResponses::Pull(Pull { images }),
            ]
            .iter()
            .flat_map(|x| x.mocks(&mut server, port_expander.expand(x)))
            .collect();

            Self {
                server,
                _mocks: mocks,
            }
        }

        pub async fn from_images(value: &[Image]) -> Self {
            Self::serve_images(value, &[]).await
        }

        pub async fn serve_default() -> Self {
            Self::from_images(&Self::supported_images()).await
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

        let server = RegistryMock::from_images(&images).await;

        let addr = server.server.host_with_port();

        let credential = Credential {
            username: "user".to_owned(),
            password: "password".to_owned(),
        };

        let aha = super::Registry::initialize(Some(credential), vec![RegistrySetting::Insecure])
            .expect("Registry cannot fail to initialize");
        let image = Image {
            registry: addr.clone(),
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

        let server = RegistryMock::from_images(&[image.clone()]).await;

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
