// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Contains helper for serializing and deserializing structs.
use serde::{Deserialize, Serialize};

use crate::base;

#[derive(Debug)]
/// Serializes and deserializes data
pub enum Serialization<T> {
    /// Wrapper for Deserialized T
    Deserialized(T),
    /// Wrapper for Serialized T
    Serialized(Vec<u8>),
}

impl<T> Serialization<T>
where
    T: Serialize,
{
    /// Serializes given data to Vec<u8>
    pub fn serialize(t: T) -> Result<Self, base::Error> {
        match rmp_serde::to_vec(&t) {
            Ok(v) => Ok(Serialization::Serialized(v)),
            Err(_) => Err(base::Error::Serialize),
        }
    }

    /// Deserializes given Serialization to T
    pub fn deserialize(self) -> Result<T, base::Error> {
        match self {
            Serialization::Deserialized(s) => Ok(s),
            Serialization::Serialized(_) => Err(base::Error::Serialize),
        }
    }
}

impl<T> TryFrom<Vec<u8>> for Serialization<T>
where
    T: for<'de> Deserialize<'de>,
{
    type Error = base::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match rmp_serde::from_slice(&value) {
            Ok(t) => Ok(Serialization::Deserialized(t)),
            Err(_) => Err(base::Error::Serialize),
        }
    }
}

impl<T> AsRef<[u8]> for Serialization<T> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Serialization::Deserialized(_) => &[0u8],
            Serialization::Serialized(v) => v.as_ref(),
        }
    }
}

impl<T> From<Serialization<T>> for Vec<u8> {
    fn from(s: Serialization<T>) -> Self {
        match s {
            Serialization::Deserialized(_) => vec![0u8],
            Serialization::Serialized(v) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};

    use crate::base::{CachedIndexFileStorer, IndexedByteStorage, Range};

    const BASE: &str = "/tmp/openvasd/unittest";
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct Test {
        a: u32,
        b: u32,
    }

    #[test]
    fn serialization() {
        let t = Test { a: 1, b: 2 };
        let s = super::Serialization::serialize(t).unwrap();
        let v = Vec::<u8>::from(s);
        let s = super::Serialization::<Test>::try_from(v).unwrap();
        let t = match s {
            super::Serialization::Deserialized(t) => t,
            _ => panic!("Serialization::try_from failed"),
        };
        assert_eq!(t, Test { a: 1, b: 2 });
    }

    #[test]
    fn create_on_append() {
        let key = "create_serde_on_append";
        let test = Test { a: 1, b: 2 };
        let serialized = super::Serialization::serialize(&test).unwrap();
        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        store.append(key, serialized).unwrap();
        let results: Vec<super::Serialization<Test>> = store.by_range(key, Range::All).unwrap();
        assert_eq!(results.len(), 1);
        let test2 = match results.first().unwrap() {
            super::Serialization::Deserialized(t) => t.clone(),
            _ => panic!("Serialization::try_from failed"),
        };

        assert_eq!(test, test2);
        store.remove(key).unwrap();
    }
}
