use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use docker_registry::render;
use libflate::gzip;
use tokio::fs::File;

use super::{ExtractorError, LocatorError};
use crate::container_image_scanner::{
    self, detection,
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
    ) -> super::PinBoxFut<Result<Self, ExtractorError>>
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

    fn extract(self) -> super::PinBoxFut<Vec<Self::Item>> {
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

    fn push(&mut self, layer: PackedLayer) -> super::PinBoxFut<Result<(), ExtractorError>> {
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

            tokio::task::spawn_blocking(move || {
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
            })
            .await??;
            Ok(())
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
    fn locate(&self, name: &str) -> super::PinBoxFutRef<'_, Result<super::Location, LocatorError>> {
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
    let gz_dec = gzip::Decoder::new(layer)?;
    let mut archive = tar::Archive::new(gz_dec);
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
