// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

// Maybe move products to notus so they are the same as advisories

use greenbone_scanner_framework::models::Product;

use crate::nasl::syntax::{LoadError, Loader};

use crate::feed::{HashSumFileItem, HashSumNameLoader, SignatureChecker, VerifyError};
use crate::feed::{NoVerifier, check_signature};
use crate::notus::advisories::ProductsAdvisories;
use crate::notus::error::{Error, LoadProductErrorKind};

#[derive(Clone)]
pub struct ProductLoader {
    loader: Loader,
    feed_integrity_check: bool,
}

impl SignatureChecker for ProductLoader {}

impl ProductLoader {
    pub fn new(feed_integrity_check: bool, loader: Loader) -> Self {
        Self {
            loader,
            feed_integrity_check,
        }
    }
}

impl ProductLoader {
    pub fn get_products(&self) -> Result<Vec<String>, Error> {
        let fmap = |entry: Result<HashSumFileItem<'_>, VerifyError>| match entry {
            Ok(x) => x
                .get_filename()
                .strip_suffix(".notus")
                .map(|x| x.to_string()),
            Err(error) => {
                tracing::warn!(%error, "Unable to load product");
                None
            }
        };
        let ret = if self.feed_integrity_check {
            HashSumNameLoader::sha256(&self.loader)
                .map_err(Error::HashsumLoadError)?
                .filter_map(fmap)
                .collect()
        } else {
            NoVerifier::notus(&self.loader).filter_map(fmap).collect()
        };
        Ok(ret)
    }

    pub fn load_product(&self, os: &str) -> Result<Product, Error> {
        tracing::debug!(
            root=?self.loader.root_path(),
            os =?os,
            "Loading notus product",
        );
        let file_name = format!("{os}.notus");
        if self.feed_integrity_check {
            let mut loader =
                HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;
            let file_item = loader
                .find(|entry| {
                    if let Ok(item) = entry {
                        return item.get_filename() == file_name;
                    }
                    false
                })
                .ok_or_else(|| Error::UnknownProduct(os.to_string()))?
                .map_err(Error::HashsumLoadError)?;

            file_item.verify().map_err(Error::HashsumLoadError)?;
        }

        let file = self.loader.load(&file_name).map_err(|e| {
            if let LoadError::NotFound(_) = e {
                Error::UnknownProduct(os.to_string())
            } else {
                Error::LoadProductError(os.to_string(), LoadProductErrorKind::LoadError(e))
            }
        })?;

        match serde_json::from_str(&file) {
            Ok(adv) => Ok(adv),
            Err(err) => Err(Error::JSONParseError(os.to_string(), err)),
        }
    }
}

#[derive(Debug)]
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
struct HashsumAdvisoryLoader<T> {
    first: bool,
    end: bool,
    loader: T,
}

pub fn advisory_loader<'a>(
    check_feed_integrity: bool,
    loader: &'a Loader,
) -> Result<impl Iterator<Item = Result<ProductsAdvisoriesContainer, Error>>, Error> {
    tracing::debug!(check_feed_integrity, "creating advisory_loader");
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
