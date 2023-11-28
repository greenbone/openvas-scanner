// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use models::Advisories;

use crate::error::Error;

pub mod fs;
pub mod hashsum;

/// Trait for and AdvisoryLoader
pub trait AdvisoriesLoader {
    /// Depending on the given os string, the corresponding Advisories are loaded
    fn load_package_advisories(&self, os: &str) -> Result<Advisories, Error>;
    fn get_available_os(&self) -> Result<Vec<String>, Error>;
}
