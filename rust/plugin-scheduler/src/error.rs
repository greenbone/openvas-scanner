// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::fmt::Display;

use crate::plugin::Phase;

#[derive(Clone, Debug)]
/// Errors, that occur during creation of the PluginScheduler
pub enum SchedulerError<C>
where
    C: Phase + Clone,
{
    /// A dependency cycle within the dependency chain of a plugin.
    DependencyCycle(Vec<String>),

    /// A plugin is missing in the PluginCollection.
    PluginNotFound(Vec<String>, String),

    /// An error in the plugin execution error. Plugins belong to Categories. These categories
    /// are ran in a specific order, like category 1 runs before category 2. When a plugin of
    /// category 1 has a dependency to a plugin of category 2, it is impossible to run the
    /// dependency plugin before its dependant.
    DependencyOrder(Vec<String>, (String, C), (String, C)),
}

impl<C> Display for SchedulerError<C>
where
    C: Phase + Display + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DependencyCycle(deps) => {
                write!(f, "dependency cycle in ({})", deps.join(","))
            }
            Self::PluginNotFound(deps, not_found) => {
                if deps.is_empty() {
                    write!(f, "NVT not found")
                } else {
                    write!(f, "dependency {not_found} not found ({})", deps.join(","))
                }
            }
            Self::DependencyOrder(deps, dependant, dependency) => {
                write!(
                    f,
                    "dependency {} of category {} would run after dependant {} of category {} ({})",
                    dependency.0,
                    dependency.1,
                    dependant.0,
                    dependant.1,
                    deps.join(",")
                )
            }
        }
    }
}
