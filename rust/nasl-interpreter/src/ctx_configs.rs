// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::logger::{DefaultLogger, NaslLogger};

/// Configurations
///
/// This struct includes all objects that a nasl function requires.
/// New objects must be added here in
pub struct CtxConfigs {
    /// Default logger.
    logger: Box<dyn NaslLogger>,
}

impl CtxConfigs {
    /// Creates an empty configuration
    pub fn new() -> Self {
        Self {
            logger: Box::new(DefaultLogger::new()),
        }
    }
    /// Get the logger to print messages
    pub fn logger(&self) -> &dyn NaslLogger {
        &*self.logger
    }

    /// Set a new logger
    pub fn set_logger(&mut self, logger: Box<dyn NaslLogger>) {
        self.logger = logger;
    }
}

impl Default for CtxConfigs {
    fn default() -> Self {
        Self::new()
    }
}
