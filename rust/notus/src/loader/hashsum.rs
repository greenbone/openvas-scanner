// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{io::Read, marker::PhantomData};

use feed::{HashSumNameLoader, SignatureChecker};
use models::ProductsAdivisories;
use nasl_syntax::{AsBufReader, Loader};

use crate::error::Error;

use super::{AdvisoryLoader, FeedStamp, ProductLoader};

#[derive(Debug, Clone)]
pub struct HashsumProductLoader<R, L> {
    loader: L,
    read_type: PhantomData<R>,
}

impl<R, L> SignatureChecker for HashsumProductLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
}

impl<R, L> HashsumProductLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
    pub fn new(reader: L) -> Result<Self, Error> {
        Ok(Self {
            loader: reader,
            read_type: PhantomData,
        })
    }
}

impl<R, L> ProductLoader for HashsumProductLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
    fn get_products(&self) -> Result<Vec<String>, crate::error::Error> {
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

    fn load_product(&self, os: &str) -> Result<(models::Product, FeedStamp), Error> {
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
                Error::LoadProductError(
                    os.to_string(),
                    crate::error::LoadProductErrorKind::LoadError(e),
                )
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
    fn verify_signature(&self) -> Result<(), feed::VerifyError> {
        let path = self.loader.root_path().unwrap();
        feed::verify::check_signature(&path)
    }
    fn get_root_dir(&self) -> Result<String, Error> {
        let p = self.loader.root_path().unwrap();
        Ok(p)
    }
}

#[derive(Debug, Clone)]
pub struct HashsumAdvisoryLoader<R, L> {
    loader: L,
    read_type: PhantomData<R>,
}

impl<R, L> SignatureChecker for HashsumAdvisoryLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
}

impl<R, L> HashsumAdvisoryLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
    pub fn new(reader: L) -> Result<Self, Error> {
        Ok(Self {
            loader: reader,
            read_type: PhantomData,
        })
    }
}

impl<R, L> AdvisoryLoader for HashsumAdvisoryLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
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
                Error::LoadProductError(
                    os.to_string(),
                    crate::error::LoadProductErrorKind::LoadError(e),
                )
            })?;

        match serde_json::from_str(&file) {
            Ok(adv) => Ok(adv),
            Err(err) => Err(Error::JSONParseError(os.to_string(), err)),
        }
    }

    /// Perform a signature check of the sha256sums file
    fn verify_signature(&self) -> Result<(), feed::VerifyError> {
        let path = self.loader.root_path().unwrap();
        feed::verify::check_signature(&path)
    }
    fn get_root_dir(&self) -> Result<String, Error> {
        let p = self.loader.root_path().unwrap();
        Ok(p)
    }
}
