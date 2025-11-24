// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::utils::scan_ctx::ContextStorage;
use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, SchedulerStorage, VTError};

pub trait Schedule: Iterator<Item = ConcurrentVTResult> + Sized {
    fn cache(self) -> Result<Vec<ConcurrentVT>, VTError> {
        self.collect()
    }
}

impl<T> Schedule for T where T: Iterator<Item = ConcurrentVTResult> {}

// TODO: Remove this trait, now that it is just one associated type?
pub trait ScannerStack {
    type Storage: ContextStorage + SchedulerStorage + Clone + 'static;
}

impl<S> ScannerStack for S
where
    S: ContextStorage + SchedulerStorage + Clone + 'static,
{
    type Storage = S;
}
