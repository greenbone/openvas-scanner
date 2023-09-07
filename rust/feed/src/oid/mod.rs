// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Is a module to get oids within a feed

use std::fs::File;

use nasl_interpreter::{AsBufReader, Loader};
use nasl_syntax::{IdentifierType, Statement, TokenCategory};

use crate::{update, verify};
/// Updates runs nasl plugin with description true and uses given storage to store the descriptive
/// information
pub struct Oid<L, V> {
    /// Is used to load nasl plugins by a relative path
    loader: L,
    verifier: V,
}
impl<L, V> Oid<L, V>
where
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<String, verify::Error>>,
{
    /// Creates an oid finder. Returns a tuple of (filename, oid).
    ///
    /// It will iterate through the filenames retrieved by the verifier and execute each found
    /// `.nasl` script in description mode to return the OID set in script_oid.
    ///
    /// It is used to find all oids within a feed.
    pub fn init(
        loader: L,
        verifier: V,
    ) -> impl Iterator<Item = Result<(String, String), update::Error>> {
        Self { loader, verifier }
    }

    fn script_oid(stmt: &Statement) -> Option<String> {
        match stmt {
            Statement::Call(t, stms, _) => match t.category() {
                TokenCategory::Identifier(IdentifierType::Undefined(s)) => match s as &str {
                    "script_oid" => stms.first().map(|x| x.to_string()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    /// Returns the OID string or update::Error::MissingExit.
    fn single(&self, key: String) -> Result<String, update::ErrorKind> {
        let code = self.loader.load(key.as_ref())?;
        for stmt in nasl_syntax::parse(&code) {
            if let Statement::If(_, _, stmts, _, _) = stmt? {
                if let Statement::Block(_, x, _) = &*stmts {
                    for stmt in x {
                        if let Some(oid) = Self::script_oid(stmt) {
                            return Ok(oid);
                        }
                    }
                }
            }
        }
        Err(update::ErrorKind::MissingExit(key))
    }
}

impl<L, V> Iterator for Oid<L, V>
where
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<String, verify::Error>>,
{
    type Item = Result<(String, String), update::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.verifier.find(|x| {
            if let Ok(x) = x {
                x.ends_with(".nasl")
            } else {
                true
            }
        }) {
            Some(Ok(k)) => Some(
                self.single(k.clone())
                    .map(|x| (k.clone(), x))
                    .map_err(|e| update::Error { kind: e, key: k }),
            ),
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        }
    }
}
