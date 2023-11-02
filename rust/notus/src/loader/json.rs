// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs::File,
    io::{Error, ErrorKind, Read},
    path::Path,
};

use models::Advisories;

use super::AdvisoriesLoader;

pub struct JSONAdvisoriesLoader<P>
where
    P: AsRef<Path>,
{
    path: P,
}

impl<P> JSONAdvisoriesLoader<P>
where
    P: AsRef<Path>,
{
    pub fn new(path: P) -> Result<Self, Error> {
        if !path.as_ref().exists() || !path.as_ref().is_dir() {
            return Err(ErrorKind::NotFound.into());
        }

        Ok(Self { path })
    }
}

impl<P> AdvisoriesLoader for JSONAdvisoriesLoader<P>
where
    P: AsRef<Path>,
{
    fn load_package_advisories(&self, os: &str) -> Result<Advisories, Error> {
        let notus_file = self.path.as_ref().join(os);
        let mut file = File::open(notus_file)?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        match serde_json::from_str(&buf) {
            Ok(json) => Ok(json),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::loader::AdvisoriesLoader;

    use super::JSONAdvisoriesLoader;

    #[test]
    fn test_load_advisories() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = JSONAdvisoriesLoader::new(path).unwrap();
        let _ = loader.load_package_advisories("debian_10.notus").unwrap();
    }
}
