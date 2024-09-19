// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Product, ProductsAdivisories};
use crate::nasl::syntax::{FSPluginLoader, Loader};

use crate::feed::check_signature;
use crate::feed::{HashSumNameLoader, SignatureChecker, VerifyError};
use crate::notus::error::{Error, LoadProductErrorKind};

use super::{AdvisoryLoader, FeedStamp, ProductLoader};

#[derive(Debug, Clone)]
pub struct HashsumProductLoader {
    loader: FSPluginLoader,
}

impl SignatureChecker for HashsumProductLoader {}

impl HashsumProductLoader {
    pub fn new(loader: FSPluginLoader) -> Result<Self, Error> {
        Ok(Self { loader })
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
        if let Ok(mut loader) = HashSumNameLoader::sha256(&self.loader) {
            if let Some(Ok(file_item)) = loader.find(|entry| {
                if let Ok(item) = entry {
                    return item.get_filename() == format!("{os}.notus");
                }
                false
            }) {
                return *stamp != FeedStamp::Hashsum(file_item.get_hashsum());
            }
        }
        false
    }

    /// Perform a signature check of the sha256sums file
    fn verify_signature(&self) -> Result<(), VerifyError> {
        let path = self.loader.root_path().unwrap();
        check_signature(&path)
    }
    fn get_root_dir(&self) -> Result<String, Error> {
        let p = self.loader.root_path().unwrap();
        Ok(p)
    }
}

#[derive(Debug, Clone)]
pub struct HashsumAdvisoryLoader {
    loader: FSPluginLoader,
}

impl SignatureChecker for HashsumAdvisoryLoader {}

impl HashsumAdvisoryLoader {
    pub fn new(loader: FSPluginLoader) -> Result<Self, Error> {
        Ok(Self { loader })
    }
}

impl AdvisoryLoader for HashsumAdvisoryLoader {
    fn get_advisories(&self) -> Result<Vec<String>, Error> {
        let mut ret = vec![];
        let loader = HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;

        for entry in loader {
            let item = entry.map_err(Error::HashsumLoadError)?;
            ret.push(item.get_filename())
        }
        Ok(ret)
    }

    fn load_advisory(&self, os: &str) -> Result<ProductsAdivisories, Error> {
        let mut loader =
            HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;
        let file_item = loader
            .find(|entry| {
                if let Ok(item) = entry {
                    return item.get_filename() == *os;
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
            Ok(adv) => Ok(adv),
            Err(err) => Err(Error::JSONParseError(os.to_string(), err)),
        }
    }

    /// Perform a signature check of the sha256sums file
    fn verify_signature(&self) -> Result<(), VerifyError> {
        let path = self.loader.root_path().unwrap();
        check_signature(&path)
    }
    fn get_root_dir(&self) -> Result<String, Error> {
        let p = self.loader.root_path().unwrap();
        Ok(p)
    }
}
