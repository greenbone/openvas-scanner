// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{io::Read, marker::PhantomData};

use feed::HashSumNameLoader;
use nasl_syntax::{AsBufReader, Loader};

use crate::error::Error;

use super::AdvisoriesLoader;

#[derive(Debug, Clone)]
pub struct HashsumAdvisoryLoader<R, L> {
    loader: L,
    read_type: PhantomData<R>,
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

impl<R, L> AdvisoriesLoader for HashsumAdvisoryLoader<R, L>
where
    L: Loader + AsBufReader<R>,
    R: Read,
{
    fn get_available_os(&self) -> Result<Vec<String>, crate::error::Error> {
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

    fn load_package_advisories(&self, os: &str) -> Result<models::Advisories, crate::error::Error> {
        let mut loader =
            HashSumNameLoader::sha256(&self.loader).map_err(Error::HashsumLoadError)?;
        let file_item = loader
            .find(|entry| {
                if let Ok(item) = entry {
                    return item.get_filename() == format!("{os}.notus");
                }
                false
            })
            .ok_or_else(|| Error::UnknownOs(os.to_string()))?
            .map_err(Error::HashsumLoadError)?;

        file_item.verify().map_err(Error::HashsumLoadError)?;

        let file = self
            .loader
            .load(file_item.get_filename().as_str())
            .map_err(|e| {
                Error::LoadAdvisoryError(
                    os.to_string(),
                    crate::error::LoadAdvisoryErrorKind::LoadError(e),
                )
            })?;

        match serde_json::from_str(&file) {
            Ok(adv) => Ok(adv),
            Err(err) => Err(Error::JSONParseError(os.to_string(), err)),
        }
    }
}
