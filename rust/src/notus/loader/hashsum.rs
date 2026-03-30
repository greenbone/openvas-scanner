// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::path::Path;

use greenbone_scanner_framework::models::Product;

use crate::nasl::syntax::Loader;

use crate::feed::{HashSumFileItem, HashSumNameLoader, SignatureChecker, VerifyError};
use crate::feed::{NoVerifier, check_signature};
use crate::notus::advisories::ProductsAdvisories;
use crate::notus::error::{Error, LoadProductErrorKind};

use super::{FeedStamp, ProductLoader};

#[derive(Clone)]
pub struct HashsumProductLoader {
    loader: Loader,
}

impl SignatureChecker for HashsumProductLoader {}

impl HashsumProductLoader {
    pub fn new(loader: Loader) -> Self {
        Self { loader }
    }
}

impl ProductLoader for HashsumProductLoader {
    fn get_products(&self) -> Result<Vec<String>, Error> {
        let mut ret = vec![];
        let loader = HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;

        for entry in loader {
            let item = entry.map_err(Error::HashsumLoadError)?;
            if let Some(name) = item.get_filename().strip_suffix(".notus") {
                ret.push(name.to_string())
            }
        }
        Ok(ret)
    }

    fn load_product(&self, os: &str) -> Result<(Product, FeedStamp), Error> {
        let mut loader =
            HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;
        let file_item = loader
            .find(|entry| {
                if let Ok(item) = entry {
                    return item.get_filename() == format!("{os}.notus");
                }
                false
            })
            .ok_or_else(|| Error::UnknownProduct(os.to_string()))?
            .map_err(Error::HashsumLoadError)?;

        file_item.verify().map_err(Error::HashsumLoadError)?;

        let file = self
            .loader
            .load(file_item.get_filename().as_str())
            .map_err(|e| {
                Error::LoadProductError(os.to_string(), LoadProductErrorKind::LoadError(e))
            })?;

        match serde_json::from_str(&file) {
            Ok(adv) => Ok((adv, FeedStamp::Hashsum(file_item.get_hashsum()))),
            Err(err) => Err(Error::JSONParseError(os.to_string(), err)),
        }
    }

    fn has_changed(&self, os: &str, stamp: &FeedStamp) -> bool {
        if let Ok(mut loader) = HashSumNameLoader::sha256(&self.loader)
            && let Some(Ok(file_item)) = loader.find(|entry| {
                if let Ok(item) = entry {
                    return item.get_filename() == format!("{os}.notus");
                }
                false
            })
        {
            return *stamp != FeedStamp::Hashsum(file_item.get_hashsum());
        }
        false
    }

    /// Perform a signature check of the sha256sums file
    fn verify_signature(&self) -> Result<(), VerifyError> {
        let path = self.loader.root_path();
        check_signature(&path)
    }

    fn root_path(&self) -> &Path {
        self.loader.root_path()
    }
}

pub struct ProductsAdvisoriesContainer {
    pub filename: String,
    pub advisories: ProductsAdvisories,
}

enum LoaderType<'a> {
    NoVerifier(HashsumAdvisoryLoader<NoVerifier<'a>>),
    Verifier(HashsumAdvisoryLoader<HashSumNameLoader<'a>>),
}

impl<'a> Iterator for LoaderType<'a> {
    type Item = Result<ProductsAdvisoriesContainer, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            LoaderType::NoVerifier(x) => x.next(),
            LoaderType::Verifier(x) => x.next(),
        }
    }
}

#[derive(Clone)]
pub struct HashsumAdvisoryLoader<T> {
    first: bool,
    end: bool,
    loader: T,
}

pub fn advisory_loader<'a>(
    check_feed_integrity: bool,
    loader: &'a Loader,
) -> Result<impl Iterator<Item = Result<ProductsAdvisoriesContainer, Error>>, Error> {
    Ok(if check_feed_integrity {
        LoaderType::Verifier(HashsumAdvisoryLoader::<HashSumNameLoader<'a>>::new(loader)?)
    } else {
        LoaderType::NoVerifier(HashsumAdvisoryLoader::<NoVerifier<'a>>::new(loader)?)
    })
}

impl<'a> HashsumAdvisoryLoader<HashSumNameLoader<'a>> {
    fn new(loader: &'a Loader) -> Result<Self, Error> {
        Ok(Self {
            first: true,
            end: false,
            loader: HashSumNameLoader::sha256(loader).map_err(Error::SignatureCheckError)?,
        })
    }
}

impl<'a> HashsumAdvisoryLoader<NoVerifier<'a>> {
    fn new(loader: &'a Loader) -> Result<Self, Error> {
        Ok(Self {
            first: true,
            end: false,
            loader: NoVerifier::notus(loader),
        })
    }
}

impl<'a> HashsumAdvisoryLoader<NoVerifier<'a>> {
    fn load_from_entry(
        &self,
        entry: Result<HashSumFileItem<'a>, VerifyError>,
    ) -> Result<ProductsAdvisoriesContainer, Error> {
        let entry = entry.map_err(Error::HashsumLoadError)?;
        let filename = entry.get_filename();
        let file = self.loader.load(&filename).map_err(|e| {
            Error::LoadProductError(filename.clone(), LoadProductErrorKind::LoadError(e))
        })?;
        match serde_json::from_str(&file) {
            Ok(advisories) => Ok(ProductsAdvisoriesContainer {
                filename,
                advisories,
            }),
            Err(err) => Err(Error::JSONParseError(filename, err)),
        }
    }
}

impl<'a> Iterator for HashsumAdvisoryLoader<NoVerifier<'a>> {
    type Item = Result<ProductsAdvisoriesContainer, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.loader.next()?;
        Some(self.load_from_entry(entry))
    }
}

impl<'a> HashsumAdvisoryLoader<HashSumNameLoader<'a>> {
    fn load_from_entry(
        &self,
        entry: Result<HashSumFileItem<'a>, VerifyError>,
    ) -> Result<ProductsAdvisoriesContainer, Error> {
        let entry = entry.map_err(Error::HashsumLoadError)?;
        entry.verify().map_err(Error::HashsumLoadError)?;
        let filename = entry.get_filename();
        let file = self.loader.load(&filename).map_err(|e| {
            Error::LoadProductError(filename.clone(), LoadProductErrorKind::LoadError(e))
        })?;
        match serde_json::from_str(&file) {
            Ok(advisories) => Ok(ProductsAdvisoriesContainer {
                filename,
                advisories,
            }),
            Err(err) => Err(Error::JSONParseError(filename, err)),
        }
    }
}

impl<'a> Iterator for HashsumAdvisoryLoader<HashSumNameLoader<'a>> {
    type Item = Result<ProductsAdvisoriesContainer, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            if let Err(error) = check_signature(&self.loader.root_path()) {
                self.end = true;
                tracing::warn!(%error, "Unable to check advisories signature");
                return Some(Err(Error::SignatureCheckError(error)));
            }
        }
        if self.end {
            return None;
        }
        let entry = self.loader.next()?;
        Some(self.load_from_entry(entry))
    }
}
