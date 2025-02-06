// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{marker::PhantomData, ops::Index};

use crate::nasl::{FnError, Register};

use super::FromNaslValue;

/// Captures all the positional arguments in a
/// NASL function. Can be used to obtain an iterator
/// over the positional arguments of a given type `T`.
pub struct Positionals<'a, T> {
    register: &'a Register,
    start_position: usize,
    _marker: PhantomData<T>,
}

impl<'a, T: FromNaslValue<'a>> Positionals<'a, T> {
    /// Create a new `Positionals` from the register.
    pub fn new(register: &'a Register, start_position: usize) -> Self {
        Self {
            register,
            start_position,
            _marker: PhantomData,
        }
    }

    /// Returns an iterator over the positional arguments.
    /// The item type is Result<T, FnError>, since
    /// the conversion to T can still fail.
    pub fn iter(&self) -> impl Iterator<Item = Result<T, FnError>> + 'a {
        self.register
            .positional()
            .iter()
            .skip(self.start_position)
            .map(|val| T::from_nasl_value(val))
    }
}

/// Captures all the positional arguments in a
/// NASL function. Can be used to obtain an iterator
/// over the positional arguments of a given type `T`.
/// This type checks all the type conversions from `NaslValue`
/// to `T` upon construction, so that we can assume
/// every argument is of valid type.
pub struct CheckedPositionals<T> {
    data: Vec<T>,
    _marker: PhantomData<T>,
}

impl<'a, T: FromNaslValue<'a>> CheckedPositionals<T> {
    /// Create a new `CheckedPositionals` from the register.
    pub fn new(register: &'a Register, start_position: usize) -> Result<Self, FnError> {
        let data = register
            .positional()
            .iter()
            .skip(start_position)
            .map(T::from_nasl_value)
            .collect::<Result<Vec<_>, FnError>>()?;
        Ok(Self {
            data,
            _marker: PhantomData,
        })
    }

    /// Returns an iterator over the references to the positional arguments
    /// in the target type `T`.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.data.iter()
    }

    /// Returns the number of positional arguments.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no positional arguments.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a, T: FromNaslValue<'a>> IntoIterator for CheckedPositionals<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<T> Index<usize> for CheckedPositionals<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}
