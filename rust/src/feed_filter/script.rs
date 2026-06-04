// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use scannerlib::nasl::Code;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::syntax::grammar::{Ast, Statement};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::builtins::BuiltinFunctions;
use crate::utils::{oid_from_ast, progress};

pub type Scripts = HashMap<ScriptPath, Script>;

#[derive(Clone, Debug)]
pub enum ScriptKind {
    Runnable,
    NotRunnable,
    Dependencies(Vec<ScriptPath>),
}

#[derive(Clone, Debug)]
pub struct Script {
    pub kind: ScriptKind,
    pub ast: Ast,
    pub oid: Option<String>,
}

impl Script {
    fn new(kind: ScriptKind, ast: Ast) -> Self {
        Self {
            kind,
            oid: oid_from_ast(&ast),
            ast,
        }
    }

    pub fn runnable(ast: Ast) -> Self {
        Self::new(ScriptKind::Runnable, ast)
    }

    pub fn not_runnable(ast: Ast) -> Self {
        Self::new(ScriptKind::NotRunnable, ast)
    }

    pub fn dependencies(deps: Vec<ScriptPath>, ast: Ast) -> Self {
        Self::new(ScriptKind::Dependencies(deps), ast)
    }

    pub fn iter_dependencies(&self) -> impl Iterator<Item = &ScriptPath> {
        if let ScriptKind::Dependencies(dependencies) = &self.kind {
            dependencies.iter()
        } else {
            panic!("iter_dependencies() called on non-dependencies variant")
        }
    }

    pub fn is_runnable(&self) -> bool {
        matches!(self.kind, ScriptKind::Runnable)
    }

    pub fn is_not_runnable(&self) -> bool {
        matches!(self.kind, ScriptKind::NotRunnable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScriptPath(pub String);

impl ScriptPath {
    pub fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

pub struct ScriptReader<'a> {
    feed_path: PathBuf,
    loader: Loader,
    builtins: &'a BuiltinFunctions,
}

impl<'a> ScriptReader<'a> {
    pub fn new(feed_path: PathBuf, builtins: &'a BuiltinFunctions) -> Self {
        let loader = Loader::from_feed_path(&feed_path);
        Self {
            feed_path,
            loader,
            builtins,
        }
    }

    pub fn read_scripts(&mut self) -> Scripts {
        let mut scripts = HashMap::default();
        let entries: Vec<_> = WalkDir::new(&self.feed_path).into_iter().collect();
        for entry in progress(entries) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                let path = entry.path();
                if path
                    .extension()
                    .is_none_or(|ext| ext != "nasl" && ext != "inc")
                {
                    continue;
                }
                let script_path = ScriptPath::new(&self.feed_path, path);
                if let Some(script) = self.script_from_path(path) {
                    scripts.insert(script_path, script);
                }
            }
        }
        scripts
    }

    fn script_from_path(&mut self, path: &Path) -> Option<Script> {
        let ast = self.ast_from_path(path)?;
        let script = self.script_from_ast(ast);
        Some(script)
    }

    fn ast_from_path(&mut self, path: &Path) -> Option<Ast> {
        let code = Code::load(&self.loader, path).unwrap();
        let ast = code.parse().emit_errors().unwrap();
        Some(ast)
    }

    fn script_from_ast(&mut self, ast: Ast) -> Script {
        let is_runnable = self.builtins.script_is_runnable(&ast);
        let dependencies = self.get_dependencies(&ast);
        if !is_runnable {
            Script::not_runnable(ast)
        } else if dependencies.is_empty() {
            Script::runnable(ast)
        } else {
            Script::dependencies(dependencies, ast)
        }
    }

    fn get_dependencies(&self, ast: &Ast) -> Vec<ScriptPath> {
        ast.iter_stmts()
            .filter_map(|stmt| {
                if let Statement::Include(include) = stmt {
                    let sp = search_path::SearchPath::from(self.feed_path.clone());
                    sp.find_file(&PathBuf::from(include.path.as_str()))
                        .map(|i| ScriptPath::new(&self.feed_path, &i))
                } else {
                    None
                }
            })
            .collect()
    }
}

pub struct RunnableScripts(pub Scripts);

impl RunnableScripts {
    pub fn new(unresolved: Scripts) -> Self {
        let resolved = Self::resolve(unresolved);
        Self(
            resolved
                .into_iter()
                .filter(|(_, script)| script.is_runnable())
                .collect(),
        )
    }

    pub fn resolve(mut unresolved: Scripts) -> Scripts {
        let mut resolved: Scripts = HashMap::default();
        loop {
            let (newly_resolved, newly_unresolved) = unresolved
                .into_iter()
                .partition::<HashMap<_, _>, _>(|(_, script)| {
                    script.is_runnable() || script.is_not_runnable()
                });
            unresolved = newly_unresolved;
            let new_length = newly_resolved.len();
            resolved.extend(newly_resolved);
            if unresolved.is_empty() {
                return resolved;
            }
            if new_length == 0 {
                for (k, v) in unresolved.iter() {
                    for dep in v.iter_dependencies() {
                        assert!(
                            resolved.keys().any(|k| k.0 == dep.0)
                                || unresolved.keys().any(|k| k.0 == dep.0),
                            "References to non-existent file: {}. dep: {}",
                            k.0,
                            dep.0
                        );
                    }
                }
            }
            for v in unresolved.values_mut() {
                let any_not_runnable = v
                    .iter_dependencies()
                    .any(|dep| resolved.get(dep).is_some_and(|s| s.is_not_runnable()));
                if any_not_runnable {
                    v.kind = ScriptKind::NotRunnable;
                    continue;
                }
                let all_resolved = v.iter_dependencies().all(|dep| resolved.contains_key(dep));
                if !all_resolved {
                    continue;
                }
                v.kind = ScriptKind::Runnable;
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ScriptPath, &Script)> {
        self.0.iter()
    }
}
