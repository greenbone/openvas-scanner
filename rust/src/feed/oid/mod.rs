// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Is a module to get oids within a feed

use std::fs::File;

use crate::nasl::syntax::grammar::{Atom, Expr, Statement};
use crate::nasl::syntax::{AsBufReader, Loader};

use crate::feed::{
    update,
    verify::{self, HashSumFileItem},
};
use crate::nasl::Code;

/// Updates runs nasl plugin with description true and uses given storage to store the descriptive
/// information
pub struct Oid<L, V> {
    /// Is used to load nasl plugins by a relative path
    loader: L,
    verifier: V,
}
impl<'a, L, V> Oid<L, V>
where
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a>, verify::Error>>,
{
    fn script_oid(stmt: &Statement) -> Option<String> {
        if let Statement::ExprStmt(Expr::Atom(Atom::FnCall(call))) = stmt {
            if call.fn_name.to_str() == "script_oid" {
                return call.args.items.first().map(|x| x.to_string());
            }
        }
        None
    }

    /// Returns the OID string or update::Error::MissingExit.
    fn single(&self, key: String) -> Result<String, update::ErrorKind> {
        for stmt in Code::load(&self.loader, &key)?
            .parse()
            .result()
            .map_err(update::ErrorKind::SyntaxError)?
        {
            if let Statement::If(if_) = stmt {
                for stmt in &if_.if_branches[0].1.items {
                    if let Some(oid) = Self::script_oid(stmt) {
                        return Ok(oid);
                    }
                }
            }
        }
        Err(update::ErrorKind::MissingExit(key))
    }
}

impl<'a, L, V> Iterator for Oid<L, V>
where
    L: Sync + Send + Loader + AsBufReader<File>,
    V: Iterator<Item = Result<HashSumFileItem<'a>, verify::Error>>,
{
    type Item = Result<(String, String), update::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.verifier.find(|x| {
            if let Ok(x) = x {
                x.get_filename().ends_with(".nasl")
            } else {
                true
            }
        }) {
            Some(Ok(k)) => {
                if let Err(e) = k.verify() {
                    return Some(Err(e.into()));
                }
                Some(
                    self.single(k.get_filename())
                        .map(|x| (k.get_filename(), x))
                        .map_err(|e| update::Error {
                            kind: e,
                            key: k.get_filename(),
                        }),
                )
            }
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        }
    }
}
