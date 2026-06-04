// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashMap;
use std::fmt::Display;

use crate::builtins::{BuiltinFunctions, BuiltinStatus};
use crate::script::Scripts;
use crate::utils::iter_fn_calls;

pub struct CategoryStats {
    pub implemented: Vec<(String, usize)>,
    pub unimplemented: HashMap<BuiltinStatus, Vec<(String, usize)>>,
}

pub struct BuiltinStats {
    pub undocumented: Vec<String>,
    pub categories: HashMap<String, CategoryStats>,
}

impl BuiltinStats {
    pub fn new(scripts: &Scripts, builtins: &BuiltinFunctions) -> Self {
        let mut category_stats = HashMap::new();
        let mut function_calls = HashMap::new();

        // Initialize all built-in functions with zero calls
        for (func, _) in builtins.unimplemented().iter() {
            function_calls.entry(func.clone()).or_insert(0);
        }
        for (func, _) in builtins.implemented().iter() {
            function_calls.entry(func.clone()).or_insert(0);
        }

        // Count function calls in all scripts
        for (_, script) in scripts.iter() {
            for call in iter_fn_calls(&script.ast) {
                let function = call.fn_name.to_string();
                *function_calls.entry(function).or_insert(0) += 1;
            }
        }

        for (func, calls) in function_calls.iter() {
            if let Some((category, _)) = builtins.implemented().get(func) {
                let stats = category_stats
                    .entry(category.clone())
                    .or_insert(CategoryStats {
                        implemented: vec![],
                        unimplemented: HashMap::new(),
                    });
                stats.implemented.push((func.clone(), *calls));
            } else if let Some((category, deprecated)) = builtins.unimplemented().get(func) {
                let stats = category_stats
                    .entry(category.clone())
                    .or_insert(CategoryStats {
                        implemented: vec![],
                        unimplemented: HashMap::new(),
                    });
                let status = if *deprecated {
                    BuiltinStatus::Deprecated
                } else if *calls > 0 {
                    BuiltinStatus::Used
                } else {
                    BuiltinStatus::Unused
                };
                stats
                    .unimplemented
                    .entry(status)
                    .or_insert(vec![])
                    .push((func.clone(), *calls));
            }
        }

        Self {
            undocumented: builtins.undocumented.iter().cloned().collect(),
            categories: category_stats,
        }
    }
}

impl Display for BuiltinStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "# Coverage of NASL built-in functions per Category\n")?;
        let mut num_functions = 0;
        let mut num_implemented = 0;
        for (category, stats) in self.categories.iter() {
            let num_unimplemented: usize = stats.unimplemented.values().map(|v| v.len()).sum();
            num_functions += stats.implemented.len() + num_unimplemented;
            num_implemented += stats.implemented.len();
            writeln!(f, "## {}\n", category)?;
            writeln!(f, "<b>")?;
            writeln!(
                f,
                "Functions: {}\n",
                stats.implemented.len() + num_unimplemented
            )?;
            writeln!(f, "Implemented: {}\n", stats.implemented.len())?;
            writeln!(
                f,
                "Percentage implemented: {:.2}%",
                (stats.implemented.len() as f64
                    / (stats.implemented.len() + num_unimplemented) as f64)
                    * 100.0
            )?;
            writeln!(f, "</b>\n")?;
            if !stats.implemented.is_empty() {
                writeln!(f, "### Implemented Functions\n")?;
                let mut funcs = stats.implemented.clone();
                funcs.sort_by_key(|(_, a)| *a);
                funcs.reverse();
                for (func, count) in funcs {
                    writeln!(f, "- {} (used {} times)", func, count)?;
                }
                writeln!(f)?;
            }
            writeln!(f, "### Unimplemented Functions\n")?;
            let statuses = [
                BuiltinStatus::Used,
                BuiltinStatus::Unused,
                BuiltinStatus::Deprecated,
            ];
            for status in statuses {
                if let Some(funcs) = stats.unimplemented.get(&status)
                    && !funcs.is_empty()
                {
                    match status {
                        BuiltinStatus::Used => {
                            writeln!(f, "#### Used\n")?;
                        }
                        BuiltinStatus::Unused => {
                            writeln!(f, "#### Unused\n")?;
                        }
                        BuiltinStatus::Deprecated => {
                            writeln!(f, "#### Deprecated\n")?;
                        }
                    }
                    let mut funcs = funcs.clone();
                    funcs.sort_by_key(|(_, a)| *a);
                    funcs.reverse();
                    for (func, count) in funcs {
                        writeln!(f, "- {} (used {} times)", func, count)?;
                    }
                    writeln!(f)?;
                }
            }
        }
        writeln!(f, "# Overall Coverage\n")?;
        writeln!(f, "<b>")?;
        writeln!(f, "Total Functions: {}\n", num_functions)?;
        writeln!(f, "Total Implemented: {}\n", num_implemented)?;
        writeln!(f, "Total Missing: {}\n", num_functions - num_implemented)?;
        writeln!(
            f,
            "Overall Percentage implemented: {:.2}%",
            (num_implemented as f64 / num_functions as f64) * 100.0
        )?;
        writeln!(f, "</b>\n")?;
        writeln!(f, "## Undocumented Functions (Rust Only)\n")?;
        for func in self.undocumented.iter() {
            writeln!(f, "- {}", func)?;
        }
        Ok(())
    }
}
