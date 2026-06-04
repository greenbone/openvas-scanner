// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::nasl::syntax::grammar::{Ast, Atom, Expr, FnCall};

pub fn iter_fn_calls(ast: &Ast) -> impl Iterator<Item = &FnCall> {
    ast.iter_exprs().filter_map(|expr| {
        if let Expr::Atom(Atom::FnCall(fn_call)) = expr {
            Some(fn_call)
        } else {
            None
        }
    })
}

pub fn oid_from_ast(ast: &Ast) -> Option<String> {
    iter_fn_calls(ast)
        .find(|call| call.fn_name.to_string() == "script_oid")
        .map(|call| {
            call.args
                .items
                .first()
                .unwrap()
                .to_string()
                .replace('\"', "")
        })
}

// poor mans TQDM
pub fn progress<T>(x: Vec<T>) -> impl Iterator<Item = T> {
    let num = x.len();
    let mut last_whole = 0;
    eprintln!("Reading Scripts...");
    x.into_iter().enumerate().map(move |(i, x)| {
        let completed_fraction = (i + 1) as f64 / num as f64;
        let percentage = (completed_fraction * 100.0) as usize;
        if percentage > last_whole {
            last_whole = percentage;
            if i + 1 == num {
                eprintln!("\rProgress: 100%");
            } else {
                eprint!("\rProgress: {}%", percentage);
            }
        }
        x
    })
}
