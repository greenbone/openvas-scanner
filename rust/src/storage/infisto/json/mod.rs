// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

use std::{
    io::{self, Write},
    sync::Mutex,
};

use crate::storage::{
    self, inmemory::kb::InMemoryKbStorage, item::CacheDispatcher, items::nvt::Nvt, StorageError,
};

mod kbs;
mod nvt;

/// Wraps write calls of json elements to be as list.
///
/// This allows to stream elements within an run to be written as an array without having to cache
/// the elements upfront.
/// It is done by using write_all and verify if it is the first call. If it is it will write `[`
/// before the given byte slice otherwise it will print a `,`.
/// The user of this struct must use `write_all` and cannot rely on `write` additionally the user
/// must ensure that `end` is called when the array should be closed.
pub struct ArrayWrapper<W> {
    w: W,
    first: bool,
}

impl<W> ArrayWrapper<W>
where
    W: Write,
{
    /// Creates a new JsonArrayWrapper
    pub fn new(w: W) -> Self {
        Self { first: true, w }
    }
    /// Must be called on the end of the complete run.
    ///
    /// This is to ensure that an enclosed `]` is printed.
    pub fn end(&mut self) -> io::Result<()> {
        self.w.write_all(b"]")
    }
}

impl<W> Write for ArrayWrapper<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.first {
            self.w.write_all(b"[")?;
            self.first = false;
        } else {
            self.w.write_all(b",")?;
        }
        self.w.write_all(buf)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// It will transform a Nvt to json and write it into the given Writer.
pub struct JsonStorage<W: Write> {
    w: Mutex<W>,
    kbs: InMemoryKbStorage,
}
impl<S> JsonStorage<S>
where
    S: Write,
{
    /// Creates a new JsonNvtDispatcher
    ///
    pub fn new(w: S) -> Self {
        Self {
            w: Mutex::new(w),
            kbs: Default::default(),
        }
    }

    /// Returns a new instance as a Dispatcher
    pub fn as_dispatcher(w: S) -> CacheDispatcher<Self> {
        CacheDispatcher::new(Self::new(w))
    }

    fn as_json(&self, nvt: Nvt) -> Result<(), storage::StorageError> {
        let mut context = self.w.lock().map_err(StorageError::from)?;
        serde_json::to_vec(&nvt)
            .map_err(|e| StorageError::Dirty(format!("{e:?}")))
            .and_then(|x| context.write_all(&x).map_err(StorageError::from))
    }
}
