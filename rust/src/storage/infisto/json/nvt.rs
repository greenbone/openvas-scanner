// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::io::Write;

use crate::storage::{
    dispatch::Dispatcher,
    items::nvt::{FileName, Nvt},
};

use super::JsonStorage;

impl<S: Write> Dispatcher<FileName> for JsonStorage<S> {
    type Item = Nvt;
    fn dispatch(
        &self,
        _: FileName,
        item: Self::Item,
    ) -> Result<(), crate::storage::error::StorageError> {
        self.as_json(item)
    }
}
