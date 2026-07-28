// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use scannerlib::nasl::Code;
use scannerlib::nasl::syntax::Loader;

use crate::script::ScriptPath;
use crate::utils::oid_from_ast;

/// Dependencies of a script.
pub struct ScriptDepsInfo {
    /// include deps
    pub includes: Vec<ScriptPath>,
    /// script_dependencies deps
    pub script_dependencies: Vec<ScriptPath>,
    /// The OID of this script, if present.
    pub oid: Option<String>,
}

impl ScriptDepsInfo {
    pub fn all_deps(&self) -> impl Iterator<Item = &ScriptPath> {
        self.includes.iter().chain(self.script_dependencies.iter())
    }
}

/// Map from every script in the feed to its dependency info.
pub type DepMap = HashMap<ScriptPath, ScriptDepsInfo>;

/// Reads the feed and builds the full dependency map.
pub struct DepReader {
    feed_path: PathBuf,
    loader: Loader,
}

impl DepReader {
    pub fn new(feed_path: PathBuf) -> Self {
        let loader = Loader::from_feed_path(&feed_path);
        Self { feed_path, loader }
    }

    /// Read the given root scripts and all their dependencies recursively.
    ///
    /// Only the files that are actually reachable from `roots` are read from
    /// disk; the rest of the feed is never touched.
    pub fn read_from_roots(&mut self, roots: &[ScriptPath]) -> DepMap {
        let mut map: DepMap = HashMap::default();
        let mut queue: VecDeque<ScriptPath> = roots.iter().cloned().collect();

        while let Some(path) = queue.pop_front() {
            if map.contains_key(&path) {
                continue;
            }
            let full_path = self.feed_path.join(&path.0);
            match self.read_one(&full_path) {
                Some(info) => {
                    for dep in info.all_deps() {
                        if !map.contains_key(dep) {
                            queue.push_back(dep.clone());
                        }
                    }
                    map.insert(path, info);
                }
                None => {
                    eprintln!("Warning: could not read {}", path.0);
                }
            }
        }

        map
    }

    fn read_one(&mut self, path: &Path) -> Option<ScriptDepsInfo> {
        let code = Code::load(&self.loader, path).ok()?;
        let ast = code.parse().emit_errors().ok()?;
        Some(extract_deps(&ast, &self.feed_path))
    }
}

fn extract_deps(ast: &scannerlib::nasl::syntax::grammar::Ast, feed_path: &Path) -> ScriptDepsInfo {
    let sp = search_path::SearchPath::from(feed_path.to_path_buf());

    let includes = ast
        .iter_includes()
        .filter_map(|inc| {
            sp.find_file(&PathBuf::from(&inc.path))
                .map(|p| ScriptPath::new(feed_path, &p))
        })
        .collect();

    let script_dependencies = ast
        .iter_fn_calls()
        .filter(|call| call.fn_name.to_string() == "script_dependencies")
        .flat_map(|call| {
            call.args.items.iter().filter_map(|arg| {
                let s = arg.to_string();
                // Args are double-quoted string literals: `"filename.nasl"`
                let name = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                    s[1..s.len() - 1].to_string()
                } else {
                    return None;
                };
                sp.find_file(&PathBuf::from(&name))
                    .map(|p| ScriptPath::new(feed_path, &p))
            })
        })
        .collect();

    let oid = oid_from_ast(ast);

    ScriptDepsInfo {
        includes,
        script_dependencies,
        oid,
    }
}

pub fn resolve_script(feed_path: &Path, script: &Path) -> Option<ScriptPath> {
    if script.is_absolute() {
        pathdiff::diff_paths(script, feed_path)
            .map(|rel| ScriptPath(rel.to_string_lossy().into_owned()))
    } else {
        let full = feed_path.join(script);
        if full.exists() {
            Some(ScriptPath(script.to_string_lossy().into_owned()))
        } else {
            None
        }
    }
}
