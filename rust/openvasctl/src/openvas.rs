use std::{collections::HashMap, process::Child, sync::Mutex};

use crate::{cmd, ctl::ScanController, error::OpenvasError};

pub struct OpenvasControl {
    init: Mutex<HashMap<String, ()>>,
    running: Mutex<HashMap<String, Child>>,
    sudo: bool,
}

impl OpenvasControl {
    pub fn new() -> Self {
        Self {
            init: Default::default(),
            running: Default::default(),
            sudo: cmd::check_sudo(),
        }
    }

    /// Removes a scan from init and add it to the list of running scans
    fn add_running(&self, id: String) -> Result<bool, OpenvasError> {
        if self.init.lock().unwrap().remove(&id).is_none() {
            return Ok(false);
        }
        let openvas = cmd::start(&id, self.sudo, None).map_err(OpenvasError::CmdError)?;
        self.running.lock().unwrap().insert(id, openvas);
        Ok(true)
    }

    /// Remove a scan from the init phase
    fn remove_init(&self, id: &str) -> bool {
        self.init.lock().unwrap().remove(id).is_some()
    }

    /// Remove a scan from the list of running scans and returns the process to able to tidy up
    fn remove_running(&self, id: &str) -> Option<Child> {
        self.running.lock().unwrap().remove(id)
    }
}

impl Default for OpenvasControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanController for OpenvasControl {
    /// Stops a scan with given ID. This will set a key in redis and indirectly
    /// sends SIGUSR1 to the running scan process by running openvas with the
    /// --stop-scan option.
    fn stop_scan(&self, id: &str) -> Result<(), OpenvasError> {
        let scan_id = id.to_string();

        // TODO: Set stop scan flag in redis?

        if self.remove_init(&scan_id) {
            return Ok(());
        }

        let mut scan = match self.remove_running(&scan_id) {
            Some(scan) => scan,
            None => return Err(OpenvasError::ScanNotFound),
        };

        cmd::stop(&scan_id, self.sudo)
            .map_err(OpenvasError::CmdError)?
            .wait()
            .map_err(OpenvasError::CmdError)?;

        scan.wait().map_err(OpenvasError::CmdError)?;
        Ok(())

        // TODO: Clean redis DB
    }

    fn start_scan(&self, scan: models::Scan) -> Result<(), OpenvasError> {
        // TODO: Create new DB for Scan
        // TODO: Add Scan ID to DB
        // TODO: Prepare Target (hosts, ports, credentials)
        // TODO: Prepare Plugins
        // TODO: Prepare main kbindex
        // TODO: Prepare host options
        // TODO: Prepare scan params
        // TODO: Prepare reverse lookup option (maybe part of target)
        // TODO: Prepare alive test option (maybe part of target)

        if !self.add_running(scan.scan_id)? {
            return Ok(());
        }

        // TODO: Control loop (check for status and results)?
        todo!();
    }

    fn num_running(&self) -> usize {
        self.init.lock().unwrap().len() + self.running.lock().unwrap().len()
    }

    fn num_init(&self) -> usize {
        self.init.lock().unwrap().len()
    }

    fn set_init(&self, id: &str) {
        self.init.lock().unwrap().insert(id.to_string(), ());
    }

    fn exists(&self, id: &str) -> bool {
        self.init.lock().unwrap().contains_key(id) || self.running.lock().unwrap().contains_key(id)
    }
}
