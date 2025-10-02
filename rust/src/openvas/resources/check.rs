// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::scanner::ObservableResources;

/// Checks for relative resource availability.
///
/// When e.g. min_free_memory is set to 10 then 10% of the memory must be free so that `verify`
/// does not return the memory observation as an unfullfiled check.
#[derive(Debug)]
pub struct Checker {
    /// Memory in bytes that must be free
    pub memory: Option<u64>,
    /// Percentage of CPU until that must be free.
    pub cpu: Option<f32>,
}

impl Checker {
    /// Returns a instance based on given absolute memory values and relative cpu usage.
    pub fn new(memory: Option<u64>, cpu: Option<f32>) -> Self {
        Self { memory, cpu }
    }

    /// Returns a list of resource observables that are not within the threshold.
    fn breakaways(&self) -> Vec<ObservableResources> {
        let mut results = Vec::with_capacity(2);
        let available = super::available();
        if let Some(free) = self.memory
            && available.memory < free
        {
            results.push(ObservableResources::Memory);
        }
        if let Some(workload) = self.cpu
            && available.cpu > workload
        {
            results.push(ObservableResources::CPU);
        }

        results
    }

    /// Returns true when all resources are within the threshold
    pub fn in_boundaries(&self) -> bool {
        self.breakaways().is_empty()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn in_boundaries() {
        let checker = Checker::new(Some(u64::MIN), Some(f32::MAX));
        assert_eq!(checker.breakaways(), vec![]);
        assert!(checker.in_boundaries());
    }
    #[test]
    fn not_in_boundaries() {
        let checker = Checker::new(Some(u64::MAX), Some(f32::MIN));
        use ObservableResources::*;
        assert_eq!(checker.breakaways(), vec![Memory, CPU]);
        assert!(!checker.in_boundaries());
    }
}
