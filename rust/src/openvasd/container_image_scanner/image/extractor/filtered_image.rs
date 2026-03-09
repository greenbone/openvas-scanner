use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bzip2::read::BzDecoder;
use docker_registry::render;
use flate2::read::{GzDecoder, ZlibDecoder};
use tokio::fs::File;
use zstd::stream::read::Decoder as ZstdDecoder;

use super::{ExtractorError, LocatorError};
use crate::container_image_scanner::{
    self, benchy, detection,
    image::{Image, ImageID, PackedLayer, packages},
};

pub struct Extractor {
    base: PathBuf,
    architecture: Vec<String>,
    // is used for warnings when an layer was missing that it won't repeat the warning.
    offset: usize,
    last_index: usize,
}

impl From<docker_registry::render::RenderError> for ExtractorError {
    fn from(value: docker_registry::render::RenderError) -> Self {
        match value {
            render::RenderError::WrongTargetPath(path_buf) => {
                ExtractorError::Io(std::io::Error::other(format!(
                    "Wrong target path {}: must be absolute path to existing directory.",
                    path_buf.display()
                )))
            }
            render::RenderError::Io(error) => ExtractorError::Io(error),
        }
    }
}

impl From<tokio::task::JoinError> for ExtractorError {
    fn from(value: tokio::task::JoinError) -> Self {
        tracing::warn!(error=?value, "Tokio is unable to join the task.");
        ExtractorError::Io(std::io::Error::other("Unable to joining task."))
    }
}

impl super::Extractor for Extractor {
    type Item = FileSystemLocator;

    fn initialize(
        config: Arc<container_image_scanner::config::Config>,
        image: ImageID,
    ) -> super::Promise<Result<Self, ExtractorError>>
    where
        Self: Sized + Send + Sync,
    {
        Box::pin(async move {
            let base = config.image_extraction_location();
            let scan_id = image.id();
            //TODO: remove unnecessary parsing
            let image: Image = image.image.parse().unwrap();
            let base = base
                .join("images")
                .join(scan_id)
                .join(&image.registry)
                .join(image.image.as_ref().map(|x| x as &str).unwrap_or_default())
                .join(image.tag.as_ref().map(|x| x as &str).unwrap_or_default());

            if !base.exists() {
                tokio::fs::create_dir_all(&base).await?;
            }

            Ok(Self {
                base,
                offset: 0,
                last_index: 0,
                architecture: vec![],
            })
        })
    }

    fn locator(self) -> super::Promise<Vec<Self::Item>> {
        Box::pin(async move {
            self.architecture
                .clone()
                .into_iter()
                .map(|arch| FileSystemLocator {
                    base: self.base.join(&arch),
                    arch,
                })
                .collect()
        })
    }

    fn extract(&mut self, layer: PackedLayer) -> super::Promise<Result<Duration, ExtractorError>> {
        if !(layer.index == 0 && self.last_index == 0)
            && layer.index != self.last_index + 1 + self.offset
        {
            tracing::warn!(
                layer = layer.index,
                assumed_layer = self.last_index + 1 + self.offset,
                "Expected a different layer index."
            );
            self.offset += 1;
        }

        self.last_index = layer.index;
        let base = self.base.clone().join(&layer.arch);
        if !self.architecture.contains(&layer.arch) {
            self.architecture.push(layer.arch);
        }
        Box::pin(async move {
            if !base.exists() {
                tokio::fs::create_dir_all(&base).await?;
            }

            let (duration, result) = benchy::measure(tokio::task::spawn_blocking(move || {
                unpack_layer(&layer.data, &base, |p| {
                    let result = detection::OS_FILES
                        .iter()
                        .chain(packages::PACKAGE_FILES.iter())
                        .filter(|x| !x.is_empty())
                        .any(|x| p.ends_with(x));

                    tracing::trace!(
                        base=?base,
                        path = ?p,
                        result,
                        "Checked for white listing"
                    );

                    result
                })
            }))
            .await
            .unpack();
            result??;
            Ok(duration)
        })
    }
}

pub struct FileSystemLocator {
    base: PathBuf,
    arch: String,
}

impl Drop for FileSystemLocator {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(&self.base);
        match result {
            Ok(_) => tracing::trace!(dir = ?&self.base, "Removed dir"),
            Err(e) => {
                tracing::warn!(
                    dir = ?self.base,
                    error = %e,
                    "Failed to remove directory. It will remain on the filesystem but does not affect functionality."
                );
            }
        }
    }
}

impl super::Locator for FileSystemLocator {
    fn locate(&self, name: &str) -> super::PromiseRef<'_, Result<super::Location, LocatorError>> {
        let base = self.base.clone();
        let name = name.to_owned();

        Box::pin(async move {
            let element = name.split('/').fold(base, |a, b| a.join(b));
            if !element.exists() {
                return Err(LocatorError::NotFound(name.to_owned()));
            }
            File::open(&element)
                .await
                .map(|_| super::Location(element))
                .map_err(LocatorError::ReadError)
        })
    }

    fn architecture(&self) -> &str {
        &self.arch
    }
}

// This is based on `unpack_filtered` and `_unpack` from the
// `docker-registry` crate
fn unpack_layer(
    layer: &[u8],
    target_dir: &Path,
    predicate: impl Fn(&Path) -> bool,
) -> Result<(), ExtractorError> {
    if !target_dir.is_absolute() || !target_dir.exists() || !target_dir.is_dir() {
        return Err(ExtractorError::WrongTargetDir(target_dir.to_path_buf()));
    }
    tracing::trace!(layer_size = layer.len(), "layer_size");
    let dec = create_decoder(layer)?;

    match unpack(target_dir, &predicate, dec) {
        Ok(x) => Ok(x),
        Err(error) => {
            tracing::trace!(%error, "We try one more time with cursor as the first file name may start with a magic header");
            unpack(target_dir, predicate, std::io::Cursor::new(layer)).map_err(|_| error)
        }
    }
}

fn create_decoder<'a>(bytes: &'a [u8]) -> Result<Box<dyn std::io::Read + 'a>, ExtractorError> {
    // https://en.wikipedia.org/wiki/List_of_file_signatures
    const GZIP_ID: [u8; 2] = [0x1f, 0x8b];
    const ZLIB_NO_ID: [u8; 2] = [0x78, 0x01];
    const ZLIB_FAST_ID: [u8; 2] = [0x78, 0x5e];
    const ZLIB_DEFAULT_ID: [u8; 2] = [0x78, 0x9c];
    const ZLIB_BEST_ID: [u8; 2] = [0x78, 0xDA]; // ignoring preset
    const BZIP2_ID: [u8; 3] = [0x42, 0x5a, 0x68];
    // https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
    const ZSTD_ID: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

    Ok(if bytes[0..2] == GZIP_ID {
        tracing::trace!("GZIP");
        Box::new(GzDecoder::new(bytes))
    } else if bytes[0..2] == ZLIB_NO_ID
        || bytes[0..2] == ZLIB_FAST_ID
        || bytes[0..2] == ZLIB_DEFAULT_ID
        || bytes[0..2] == ZLIB_BEST_ID
    {
        tracing::trace!("ZLIB");
        Box::new(ZlibDecoder::new(bytes))
    } else if bytes[0..3] == BZIP2_ID {
        tracing::trace!("BZIP2");
        Box::new(BzDecoder::new(bytes))
    } else if bytes[0..4] == ZSTD_ID {
        tracing::trace!("ZSTD");
        let dec = ZstdDecoder::new(bytes)?;
        Box::new(dec)
    } else {
        tracing::trace!("Missing header information.");
        Box::new(std::io::Cursor::new(bytes))
    })
}

fn unpack<R>(
    target_dir: &Path,
    predicate: impl Fn(&Path) -> bool,
    dec: R,
) -> Result<(), ExtractorError>
where
    R: std::io::Read,
{
    let mut archive = tar::Archive::new(dec);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if predicate(&path) {
            entry.unpack_in(target_dir)?;
        }
    }
    Ok(())
}
