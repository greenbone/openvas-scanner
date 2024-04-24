// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    CloseNodeError(String, &'static str),
    /// The list of dependencies is empty
    EmptyListError,
    IteratorDropped,
    NoAvailableNodeError,
    ResolveGraphError(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CloseNodeError(name, reason) => {
                write!(f, "Failed to close node {}: {}", name, reason)
            }
            Self::EmptyListError => write!(f, "The dependency list is empty"),
            Self::IteratorDropped => write!(
                f,
                "The iterator attached to the coordination thread dropped"
            ),
            Self::NoAvailableNodeError => write!(f, "No node are currently available"),
            Self::ResolveGraphError(reason) => write!(f, "Failed to resolve the graph: {}", reason), // _ => write!(f, "{:?}", self),
        }
    }
}

impl error::Error for Error {}
