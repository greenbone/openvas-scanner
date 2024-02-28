
use std::{collections::HashMap, sync::{Arc, Mutex}, process::Child};

use crate::{
    cmd::{self, check_sudo},
    error::OpenvasError,
};

#[derive(Default)]
pub struct ScanContainer {
    init: HashMap<String, ()>,
    running: HashMap<String, Child>,
}

pub struct OpenvasController {
    scans: Arc<Mutex<ScanContainer>>,
    sudo: bool,
}

impl OpenvasController {
    /// Create a new OpenvasController
    pub fn new() -> Result<Self, OpenvasError> {
        if !cmd::check() {
            return Err(OpenvasError::MissingExec);
        }

        Ok(Self {
            scans: Default::default(),
            sudo: check_sudo(),
        })
    }

    /// Add a scan into the init phase
    fn add_init(&mut self, id: String) -> bool {
        self.scans.lock().unwrap().init.insert(id, ()).is_none()
    }

    /// Remove a scan from the init phase
    fn remove_init(&mut self, id: &String) -> bool {
        self.scans.lock().unwrap().init.remove(id).is_some()
    }

    /// Removes a scan from init and add it to the list of running scans
    fn add_running(&mut self, id: String) -> Result<bool, OpenvasError> {
        let mut container = self.scans.lock().unwrap();
        if container.init.remove(&id).is_none() {
            return Ok(false);
        }
        let openvas =
            cmd::start(&id, self.sudo, None).map_err(|_| OpenvasError::UnableToRunExec)?;
        container.running.insert(id, openvas);
        Ok(true)
    }

    /// Remove a scan from the list of running scans and returns the Child process
    fn remove_running(&mut self, id: &String) -> Option<Child> {
        self.scans.lock().unwrap().running.remove(id)
    }

    /// Stops a scan with given ID. This will set a key in redis and indirectly
    /// sends SIGUSR1 to the running scan process by running openvas with the
    /// --stop-scan option.
    pub fn stop_scan(&mut self, id: &str) -> Result<(), OpenvasError> {
        let scan_id = id.to_string();

        // TODO: Set stop scan flag in redis?

        if self.remove_init(&scan_id) {
            return Ok(());
        }

        let mut scan = match self.remove_running(&scan_id) {
            Some(scan) => scan,
            None => return Err(OpenvasError::ScanNotFound(scan_id)),
        };

        cmd::stop(&scan_id, self.sudo)
            .map_err(OpenvasError::CmdError)?
            .wait()
            .map_err(OpenvasError::CmdError)?;

        scan.wait().map_err(OpenvasError::CmdError)?;

        // TODO: Clean redis DB

        Ok(())
    }

    /// Prepare scan and start it
    pub fn start_scan(&mut self, scan: models::Scan) -> Result<(), OpenvasError> {
        self.add_init(scan.scan_id.clone());

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
}
/// The ScanController is the core for the scheduler to manage scans.
pub trait ScanController {
    /// Prepares and starts a requested scan.
    fn start_scan(&self, scan: models::Scan) -> Result<(), OpenvasError>;
    /// Stops a scan that is either initializing or running. If the Scan is either unknown or
    /// already finished, an error is returned.
    fn stop_scan(&self, id: &str) -> Result<(), OpenvasError>;
    /// Return the number of currently initializing + active running scans.
    fn num_running(&self) -> usize;
    /// Return the number of currently initializing scans
    fn num_init(&self) -> usize;
    /// Marks a given scan ID as running. This is used for safely transfer scan status between the
    /// scheduler and Controller.
    fn set_init(&self, id: &str);
    /// Returns if a given scan ID is known by the controller by either being initializing,
    /// running or finished.
    fn exists(&self, id: &str) -> bool;
}
