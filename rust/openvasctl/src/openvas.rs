use async_trait::async_trait;
use models::{
    scanner::{
        Error as ScanError, ScanDeleter, ScanResultFetcher, ScanResults, ScanStarter, ScanStopper,
    },
    Scan,
};
use std::{collections::HashMap, process::Child, sync::Mutex};

use crate::{cmd, error::OpenvasError};

#[derive(Debug)]
pub struct Scanner {
    running: Mutex<HashMap<String, Child>>,
    sudo: bool,
}

impl From<OpenvasError> for ScanError {
    fn from(value: OpenvasError) -> Self {
        ScanError::Unexpected(value.to_string())
    }
}

impl Scanner {
    pub fn with_sudo_enabled() -> Self {
        Self {
            running: Default::default(),
            sudo: true,
        }
    }

    pub fn with_sudo_disabled() -> Self {
        Self {
            running: Default::default(),
            sudo: false,
        }
    }
    /// Removes a scan from init and add it to the list of running scans
    fn add_running(&self, id: String) -> Result<bool, OpenvasError> {
        let openvas = cmd::start(&id, self.sudo, None).map_err(OpenvasError::CmdError)?;
        self.running.lock().unwrap().insert(id, openvas);
        Ok(true)
    }

    /// Remove a scan from the list of running scans and returns the process to able to tidy up
    fn remove_running(&self, id: &str) -> Option<Child> {
        self.running.lock().unwrap().remove(id)
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            running: Default::default(),
            sudo: cmd::check_sudo(),
        }
    }
}
#[async_trait]
impl ScanStarter for Scanner {
    async fn start_scan(&self, scan: Scan) -> Result<(), ScanError> {
        // TODO: Create new DB for Scan
        // TODO: Add Scan ID to DB
        // TODO: Prepare Target (hosts, ports, credentials)
        // TODO: Prepare Plugins
        // TODO: Prepare main kbindex
        // TODO: Prepare host options
        // TODO: Prepare scan params
        // TODO: Prepare reverse lookup option (maybe part of target)
        // TODO: Prepare alive test option (maybe part of target)
        self.add_running(scan.scan_id)?;

        return Ok(());
    }
}

/// Stops a scan
#[async_trait]
impl ScanStopper for Scanner {
    /// Stops a scan
    async fn stop_scan<I>(&self, id: I) -> Result<(), ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        let scan_id = id.as_ref();

        // TODO: Set stop scan flag in redis?

        let mut scan = match self.remove_running(scan_id) {
            Some(scan) => scan,
            None => return Err(OpenvasError::ScanNotFound(scan_id.to_string()).into()),
        };

        cmd::stop(scan_id, self.sudo)
            .map_err(OpenvasError::CmdError)?
            .wait()
            .map_err(OpenvasError::CmdError)?;

        scan.wait().map_err(OpenvasError::CmdError)?;
        // TODO: Clean redis DB
        Ok(())
    }
}

/// Deletes a scan
#[async_trait]
impl ScanDeleter for Scanner {
    async fn delete_scan<I>(&self, _id: I) -> Result<(), ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        // already deleted on stop?
        Ok(())
    }
}

#[async_trait]
impl ScanResultFetcher for Scanner {
    /// Fetches the results of a scan and combines the results with response
    async fn fetch_results<I>(&self, _id: I) -> Result<ScanResults, ScanError>
    where
        I: AsRef<str> + Send + 'static,
    {
        todo!()
    }
}
