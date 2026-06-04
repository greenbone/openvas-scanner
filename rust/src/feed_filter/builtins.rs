// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::nasl::nasl_std_executor;
use scannerlib::nasl::syntax::grammar::Ast;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use crate::utils::iter_fn_calls;

#[derive(Eq, Hash, PartialEq, Clone)]
pub enum BuiltinStatus {
    Used,
    Unused,
    Deprecated,
}

/// This struct holds information about implemented and unimplemented built-in functions
/// based on the documentation files and rust implementation of NASL. It also tracks
/// functions that are present in the rust implementation but not documented.
pub struct BuiltinFunctions {
    /// HashMap<function_name, (category, deprecated)>
    implemented: HashMap<String, (String, bool)>,
    /// HashMap<function_name, (category, deprecated)>
    unimplemented: HashMap<String, (String, bool)>,
    /// Set of undocumented functions
    pub undocumented: HashSet<String>,
}

impl BuiltinFunctions {
    pub fn new(doc_path: PathBuf) -> Self {
        let mut implemented = HashMap::new();
        let mut unimplemented = HashMap::new();

        let exec = nasl_std_executor();
        let mut implemented_funcs = exec.iter().map(|f| f.to_string()).collect::<HashSet<_>>();

        for entry in fs::read_dir(doc_path).unwrap() {
            let entry = entry.unwrap();
            let category_path = entry.path();
            let category = category_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();

            if category_path.is_dir() {
                for func_entry in fs::read_dir(category_path).unwrap() {
                    let func_path = func_entry.unwrap().path();
                    let function = func_path
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();

                    if function == "index" {
                        continue;
                    }

                    let content = fs::read_to_string(func_path.clone())
                        .unwrap()
                        .to_ascii_lowercase();

                    let deprecated = content.contains("## deprecated");

                    if implemented_funcs.take(&function).is_some() {
                        implemented.insert(function, (category.clone(), deprecated));
                    } else {
                        unimplemented.insert(function, (category.clone(), deprecated));
                    }
                }
            }
        }
        Self {
            implemented,
            unimplemented,
            undocumented: implemented_funcs,
        }
    }

    pub fn implemented(&self) -> &HashMap<String, (String, bool)> {
        &self.implemented
    }

    pub fn unimplemented(&self) -> &HashMap<String, (String, bool)> {
        &self.unimplemented
    }

    pub fn script_is_runnable(&self, ast: &Ast) -> bool {
        for call in iter_fn_calls(ast) {
            let function = call.fn_name.to_string();
            if let Some((_, deprecated)) = self.unimplemented().get(&function)
                && !deprecated
            {
                return false;
            }
        }
        true
    }
}
