// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use generic_array::ArrayLength;

/// The phase is used to differentiate execution phases of Plugins. Different phases might use
/// different setups for execution.
pub trait Phase {
    /// Number of Phases
    type LEN: ArrayLength;
    /// Get the value of a phase for indexing
    fn get(&self) -> usize;
}

/// This Trait defines a Plugin used for the Plugin Scheduler.
pub trait Plugin<C>
where
    C: Phase,
{
    /// Returns an identifier of a Plugin
    fn get_id(&self) -> String;
    /// Returns a list of identifiers corresponding to the plugins dependencies
    fn get_dependencies(&self) -> Vec<String>;
    /// Return the category of a Plugin
    fn get_category(&self) -> C;
}

/// A PluginCollection is a collection of plugins, to look them up
pub trait PluginCollection<P, C>
where
    P: Plugin<C>,
    C: Phase,
{
    /// Search for a Plugin by an identifier
    fn get_plugin(&self, id: &str) -> Option<P>;
}
