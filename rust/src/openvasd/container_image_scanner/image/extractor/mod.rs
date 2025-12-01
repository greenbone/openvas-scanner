use std::{path::PathBuf, sync::Arc};

use thiserror::Error;
use tokio::{fs::File, io::BufReader};

use super::{ImageID, PackedLayer};
use crate::container_image_scanner::{PinBoxFut, PinBoxFutRef, config::Config};

pub mod filtered_image;

#[derive(Debug, thiserror::Error)]
pub enum ExtractorError {
    #[error("io error {0}")]
    Io(#[from] std::io::Error),
    #[error("Wrong target path {0}: must be absolute path to existing directory.")]
    WrongTargetDir(PathBuf),
}

pub struct Location(PathBuf);

impl Location {
    /// Opens the underlying PathBuf
    ///
    /// As the Locator must ensure that the file exists it MUST not fail therefore we don't need to
    /// pass an error around and can panic instead as it is a logic error.
    pub async fn open(self) -> impl tokio::io::AsyncBufRead + Unpin {
        BufReader::new(File::open(&self.0).await.unwrap())
    }

    pub fn into_inner(self) -> PathBuf {
        self.0
    }
}

impl From<PathBuf> for Location {
    fn from(value: PathBuf) -> Self {
        Location(value)
    }
}

pub trait Extractor
where
    Self::Item: Locator + Send + Sync,
{
    type Item;
    fn initialize(config: Arc<Config>, image: ImageID) -> PinBoxFut<Result<Self, ExtractorError>>
    where
        Self: Sized + Send + Sync;

    fn push(&mut self, layer: PackedLayer) -> PinBoxFut<Result<(), ExtractorError>>;

    /// Returns an Locator per architecture
    fn extract(self) -> PinBoxFut<Vec<Self::Item>>;
}

pub trait Locator {
    fn architecture(&self) -> &str;
    /// Locates the given name
    ///
    /// It MUST ensure that the returned Location is available and readable.
    fn locate(&self, name: &str) -> PinBoxFutRef<'_, Result<Location, LocatorError>>;
}

#[derive(Error, Debug)]
pub enum LocatorError {
    #[error("Failed to read: `{0}`")]
    ReadError(#[from] std::io::Error),
    #[error("`{0}` not found.")]
    NotFound(String),
}
