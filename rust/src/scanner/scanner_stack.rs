// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{FSPluginLoader, Loader};

use crate::nasl::utils::scan_ctx::ContextStorage;
use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, SchedulerStorage, VTError};

pub trait Schedule: Iterator<Item = ConcurrentVTResult> + Sized {
    fn cache(self) -> Result<Vec<ConcurrentVT>, VTError> {
        self.collect()
    }
}

impl<T> Schedule for T where T: Iterator<Item = ConcurrentVTResult> {}

pub trait ScannerStack {
    type Storage: ContextStorage + SchedulerStorage + Clone + 'static;
    type Loader: Loader + Send + 'static;
}

impl<S, L> ScannerStack for (S, L)
where
    S: ContextStorage + SchedulerStorage + Clone + 'static,
    L: Loader + Send + 'static,
{
    type Storage = S;
    type Loader = L;
}

pub type ScannerStackWithStorage<S> = (S, FSPluginLoader);
