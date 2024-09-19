// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Contains the logging abstraction for nasl-interpreter

use std::fmt::Display;

/// Modes that are used by the default logger
#[derive(Eq, PartialEq, PartialOrd, Default)]
pub enum Mode {
    /// Debug Mode, enables all logging
    Debug,
    /// Info Mode, enables Info, Warning and Error Messages
    #[default]
    Info,
    /// Warning Mde, enables Warning and Error Messages
    Warning,
    /// Error Mode, enables only Error Messages
    Error,
}

/// A trait for types that can be logged.
///
/// This trait is automatically implemented for all types that implement
/// `Sync + Send + Display`.
pub trait Logable: Sync + Send + Display {}

impl<T: Sync + Send + Display> Logable for T {}
