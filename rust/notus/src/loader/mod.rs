// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::time::SystemTime;

use models::Advisories;

use crate::error::Error;

pub mod fs;
pub mod hashsum;

#[derive(PartialEq, PartialOrd, Clone, Debug)]
pub enum FeedStamp {
    Time(SystemTime),
    Hashsum(String),
}

/// Trait for and AdvisoryLoader
pub trait AdvisoriesLoader {
    /// Depending on the given os string, the corresponding Advisories are loaded
    fn load_package_advisories(&self, os: &str) -> Result<(Advisories, FeedStamp), Error>;
    fn get_available_os(&self) -> Result<Vec<String>, Error>;
    fn has_changed(&self, os: &str, stamp: &FeedStamp) -> bool;
    fn verify_signature(&self) -> Result<(), feed::VerifyError>;
    fn get_root_dir(&self) -> Result<String, Error>;
}
