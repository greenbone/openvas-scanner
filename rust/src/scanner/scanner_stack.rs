// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{FSPluginLoader, Loader};
use crate::storage::{DefaultDispatcher, Storage};

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

pub trait Schedule: Iterator<Item = ConcurrentVTResult> + Sized {
    fn cache(self) -> Result<Vec<ConcurrentVT>, VTError> {
        self.collect()
    }
}

impl<T> Schedule for T where T: Iterator<Item = ConcurrentVTResult> {}

pub trait ScannerStack {
    type Storage: Storage + Sync + Send + 'static;
    type Loader: Loader + Send + 'static;
}

impl<S, L> ScannerStack for (S, L)
where
    S: Storage + Send + 'static,
    L: Loader + Send + 'static,
{
    type Storage = S;
    type Loader = L;
}

/// The default scanner stack, consisting of `DefaultDispatcher`,
/// `FSPluginLoader` and `NaslFunctionRegister`.
pub type DefaultScannerStack = (DefaultDispatcher, FSPluginLoader);

/// Like `DefaultScannerStack` but with a specific storage type.
pub type ScannerStackWithStorage<S> = (S, FSPluginLoader);
