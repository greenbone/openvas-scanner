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

/// A interface for a logger for the NASL interpreter
pub trait NaslLogger {
    /// Log a message with a specific level
    fn log(&self, level: Mode, msg: &dyn Logable);

    /// Log a Debug Message
    fn debug(&self, msg: &dyn Logable) {
        self.log(Mode::Debug, msg)
    }
    /// Log a Info Message
    fn info(&self, msg: &dyn Logable) {
        self.log(Mode::Info, msg)
    }
    /// Log a Warning Message
    fn warning(&self, msg: &dyn Logable) {
        self.log(Mode::Warning, msg)
    }
    /// Log a Error Message
    fn error(&self, msg: &dyn Logable) {
        self.log(Mode::Error, msg)
    }
}

/// A default logger that prints to stderr
#[derive(Default)]
pub struct DefaultLogger {
    mode: Mode,
}

impl DefaultLogger {
    /// Create a new DefaultLogger
    pub fn new(mode: Mode) -> Self {
        Self { mode }
    }

    /// Change the mode of the Logger
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }
}

impl NaslLogger for DefaultLogger {
    fn log(&self, level: Mode, msg: &dyn Logable) {
        if self.mode > level {
            return;
        }
        match level {
            Mode::Debug => eprintln!("\x1b[38;5;8mDEBUG: \x1b[0m{}", msg),
            Mode::Info => eprintln!("\x1b[38;5;2mINFO : \x1b[0m{}", msg),
            Mode::Warning => eprintln!("\x1b[38;5;3mWARN : \x1b[0m{}", msg),
            Mode::Error => eprintln!("\x1b[38;5;1mERROR: \x1b[0m{}", msg),
        }
    }
}

impl Default for Box<dyn NaslLogger> {
    fn default() -> Self {
        Box::<DefaultLogger>::default()
    }
}
