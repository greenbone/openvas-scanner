use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use sysinfo::System;
use tokio::task;

use crate::{config::Config, ctl::ScanController, error::OpenvasError};

/// Estimated memory a scan will use
const SCAN_MEM: u64 = 1024 * 1024 * 512;

pub struct Scheduler<S> {
    queue: Arc<Mutex<VecDeque<models::Scan>>>,
    config: Config,
    controller: Arc<S>,
}

/// The scheduler is the core component for managing scans. Scans can be queued and are
/// automatically scheduled, when enough resources are available. It is also possible
/// to stop registered scans.
impl<S> Scheduler<S>
where
    S: ScanController + std::marker::Send + std::marker::Sync + 'static,
{
    /// Create a new OpenvasController
    pub fn new(config: Option<Config>, controller: S) -> Self {
        Self {
            queue: Default::default(),
            config: config.unwrap_or_default(),
            controller: Arc::new(controller),
        }
    }

    /// Add a new scan to the queue. An error is returned, if the queue is either full or the scan
    /// ID is already registered.
    pub async fn add(&mut self, scan: models::Scan) -> Result<(), OpenvasError> {
        let queue = self.queue.lock().unwrap();
        if let Some(max_queued_scans) = self.config.max_queued_scans {
            if queue.len() == max_queued_scans {
                return Err(OpenvasError::MaxQueuedScans);
            }
        }
        if queue.iter().any(|x| x.scan_id == scan.scan_id) {
            return Err(OpenvasError::DuplicateScanID);
        }
        self.queue.lock().unwrap().push_back(scan);
        Ok(())
    }

    fn remove_queue(&mut self, id: &str) -> bool {
        let mut queue = self.queue.lock().unwrap();
        if let Some(index) = queue.iter().position(|x| x.scan_id == id) {
            queue.remove(index);
            return true;
        }
        false
    }

    /// Stop a registered scan. In case, the scan in still queued, it is just removed from the
    /// queue. In case, it is currently initialized, it is also just removed from this list,
    /// as a scan should not actually start, when it is removed. An error is returned, if
    /// the scan in not registered in the scheduler.
    pub async fn stop(&mut self, id: &str) -> Result<(), OpenvasError> {
        if self.remove_queue(id) {
            return Ok(());
        }

        self.controller.stop_scan(id)
    }

    /// Starts the scheduler, which checks periodically for new scans to start. In order for a scan
    /// to start, it has to meet two conditions: the max number of running scans in not reached and
    /// there must be enough available memory. Both values are configurable.
    pub async fn schedule(self) -> Result<(), OpenvasError> {
        // For checking available memory later
        let mut sys = System::new();
        // Time period to yield after each iteration
        let mut interval = tokio::time::interval(self.config.check_interval);
        loop {
            interval.tick().await;
            // TODO: Check for feed update
            // TODO: Handle interrupted scans
            // TODO: Remove forgotten finished scans

            // Are scans in the queue?
            if self.queue.lock().unwrap().is_empty() {
                continue;
            }

            // Max running scan reached?
            if let Some(max_running_scans) = self.config.max_running_scans {
                if max_running_scans == self.controller.num_running() {
                    continue;
                }
            }

            // Check available resources
            sys.refresh_memory();
            if let Some(min_free_mem) = self.config.min_free_mem {
                if sys.available_memory() - self.controller.num_init() as u64 * SCAN_MEM
                    < min_free_mem
                {
                    continue;
                }
            }

            // Start next scan in queue
            let mut queue = self.queue.lock().unwrap();
            if let Some(scan) = queue.pop_front() {
                let controller = self.controller.clone();
                controller.set_init(&scan.scan_id);
                drop(queue);
                task::spawn(async move { controller.start_scan(scan) });
            }
        }
    }
}
