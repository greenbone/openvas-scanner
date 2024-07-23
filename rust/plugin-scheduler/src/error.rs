// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use thiserror::Error;

#[derive(Clone, Debug, Error)]
/// Errors, that occur during creation of the PluginScheduler
pub enum SchedulerError {
    /// A dependency cycle within the dependency chain of a plugin.
    #[error("Dependency cycle: ({})", .0.join(","))]
    DependencyCycle(Vec<String>),

    /// A plugin is missing in the PluginCollection.
    #[error("{}", format_plugin_not_found(.0, .1))]
    PluginNotFound(Vec<String>, String),
}

fn format_plugin_not_found(deps: &[String], not_found: &str) -> String {
    if deps.is_empty() {
        "NVT not found".to_string()
    } else {
        format!("Dependency {not_found} not found ({})", deps.join(","))
    }
}
