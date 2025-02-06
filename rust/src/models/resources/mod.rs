// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

pub mod check;

#[derive(Debug)]
pub struct AvailableResources {
    /// Available memory in bytes
    pub memory: u64,
    /// Percentage of CPU usage
    pub cpu: f32,
}

/// Returns available resources
pub fn available() -> AvailableResources {
    let system = sysinfo::System::new_all();
    let cpu = system.global_cpu_info().cpu_usage();
    let memory = system.available_memory();
    AvailableResources { memory, cpu }
}

#[cfg(test)]
mod tests {

    #[test]
    fn available() {
        let result = super::available();
        assert!(result.memory > 0);
        assert!(result.cpu > 0.0);
    }
}
