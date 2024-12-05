// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Host, Protocol};

use crate::nasl::interpreter::InterpretError;
use crate::scheduling::Stage;

#[derive(thiserror::Error, Debug, Clone)]
/// An error occurred while executing the script
pub enum ExecuteError {
    #[error("storage error occurred: {0}")]
    /// Storage error
    Storage(#[from] crate::storage::StorageError),
    #[error("Scheduling error occurred: {0}")]
    /// An error while scheduling
    Scheduling(#[from] crate::scheduling::VTError),
    #[error("unable to load: {0}")]
    /// Script was not found
    NotFound(#[from] crate::nasl::syntax::LoadError),
    #[error("unable to handle parameter: {0}")]
    /// The parameter could not be processed
    Parameter(crate::models::Parameter),
}

#[derive(Debug)]
/// Contains the result of a executed script
pub enum ScriptResultKind {
    /// Contains the code provided by exit call or 0 when script finished successful without exit
    /// call
    ReturnCode(i64),
    /// Is missing a port
    MissingPort(Protocol, String),
    /// Script did not run because an excluded key is set
    ContainsExcludedKey(String),
    /// Script did not run because of missing required keys
    ///
    /// It contains the first not found key.
    MissingRequiredKey(String),
    /// Script did not run because of missing mandatory keys
    ///
    /// It contains the first not found key.
    MissingMandatoryKey(String),
    /// Contains the error the script returned
    Error(InterpretError),
}

#[derive(Debug)]
/// Contains meta data of the script and its result
pub struct ScriptResult {
    /// Object identifier of the script
    pub oid: String,
    /// relative filename of the script
    pub filename: String,
    /// the stage of the script
    pub stage: Stage,
    /// the result
    pub kind: ScriptResultKind,
    /// The target of the result
    pub target: Host,
}

impl ScriptResult {
    /// Returns true when the return code of the script is 0.
    pub fn has_succeeded(&self) -> bool {
        matches!(&self.kind, ScriptResultKind::ReturnCode(0))
    }

    /// Returns true when the script didn't run
    pub fn has_not_run(&self) -> bool {
        matches!(
            self.kind,
            ScriptResultKind::MissingRequiredKey(_)
                | ScriptResultKind::MissingMandatoryKey(_)
                | ScriptResultKind::ContainsExcludedKey(_)
                | ScriptResultKind::MissingPort(..)
        )
    }
}
