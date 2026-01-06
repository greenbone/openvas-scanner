// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod error;

use clap::Parser;
use scannerlib::models::{Scan, VT};
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::syntax::grammar::{Ast, Atom, Expr, FnCall, Statement};
use scannerlib::nasl::{Code, nasl_std_functions};
use std::collections::HashSet;
use std::fmt::Display;
use std::io::{self};
use std::path::PathBuf;
use std::{collections::HashMap, fs, path::Path};
use walkdir::WalkDir;

use crate::error::CliError;

#[derive(clap::Parser)]
#[command(
    name = "feed-filter",
    about = "Filters scripts from the feed which aren't runnable with the current set of builtins in the openvasd implementation.",
    version = env!("CARGO_PKG_VERSION")
)]
struct FilterArgs {
    /// Path to the feed that should be read and filtered.
    feed_path: PathBuf,
    /// Path to the documentation nasl builtin base directory.
    /// The expected path looks something like /path/to/openvas-scanner/doc/manual/nasl/built-in-functions/
    doc_path: PathBuf,
    /// Output path: If present, a copy of the feed containing only
    /// the runnable scripts will be copied to this directory. If
    /// the directory does not exist, it will be created.
    #[clap(long)]
    feed_out: Option<PathBuf>,
    /// Output file: If present, a file containing statistics about
    /// unimplemented built-in function usage will be written to this file.
    #[clap(long)]
    stat_out: Option<PathBuf>,
    /// List all runnable scripts to stdout
    #[clap(short, long)]
    list: bool,
    /// If present, a template scan json containing the OIDs of all
    /// runnable scripts will be written to this path.
    #[clap(short, long)]
    scan_config: Option<PathBuf>,
}

#[derive(Eq, Hash, PartialEq, Clone)]
enum BuiltinStatus {
    Used,
    Unused,
    Deprecated,
}

struct CategoryStats {
    implemented: Vec<(String, usize)>,
    unimplemented: HashMap<BuiltinStatus, Vec<(String, usize)>>,
}

struct BuiltinStats {
    undocumented: Vec<String>,
    categories: HashMap<String, CategoryStats>,
}

impl BuiltinStats {
    fn new(scripts: &Scripts, builtins: &BuiltinFunctions) -> Self {
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
                funcs.sort_by(|(_, a), (_, b)| a.cmp(b));
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
                    funcs.sort_by(|(_, a), (_, b)| a.cmp(b));
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

/// This struct holds information about implemented and unimplemented built-in functions
/// based on the documentation files and rust implementation of NASL. It also tracks
/// functions that are present in the rust implementation but not documented.
struct BuiltinFunctions {
    /// HashMap<function_name, (category, deprecated)>
    implemented: HashMap<String, (String, bool)>,
    /// HashMap<function_name, (category, deprecated)>
    unimplemented: HashMap<String, (String, bool)>,
    /// Set of undocumented functions
    undocumented: HashSet<String>,
}

impl BuiltinFunctions {
    fn new(doc_path: PathBuf) -> Self {
        let mut implemented = HashMap::new();
        let mut unimplemented = HashMap::new();

        let exec = nasl_std_functions();
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

    fn implemented(&self) -> &HashMap<String, (String, bool)> {
        &self.implemented
    }

    fn unimplemented(&self) -> &HashMap<String, (String, bool)> {
        &self.unimplemented
    }

    fn script_is_runnable(&self, ast: &Ast) -> bool {
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

fn iter_fn_calls(ast: &Ast) -> impl Iterator<Item = &FnCall> {
    ast.iter_exprs().filter_map(|expr| {
        if let Expr::Atom(Atom::FnCall(fn_call)) = expr {
            Some(fn_call)
        } else {
            None
        }
    })
}

// poor mans TQDM
fn progress<T>(x: Vec<T>) -> impl Iterator<Item = T> {
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

fn oid_from_ast(ast: &Ast) -> Option<String> {
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

type Scripts = HashMap<ScriptPath, Script>;

#[derive(Clone, Debug)]
enum ScriptKind {
    Runnable,
    NotRunnable,
    Dependencies(Vec<ScriptPath>),
}

#[derive(Clone, Debug)]
struct Script {
    kind: ScriptKind,
    ast: Ast,
    oid: Option<String>,
}

impl Script {
    fn new(kind: ScriptKind, ast: Ast) -> Self {
        Self {
            kind,
            oid: oid_from_ast(&ast),
            ast,
        }
    }

    fn runnable(ast: Ast) -> Self {
        Self::new(ScriptKind::Runnable, ast)
    }

    fn not_runnable(ast: Ast) -> Self {
        Self::new(ScriptKind::NotRunnable, ast)
    }

    fn dependencies(deps: Vec<ScriptPath>, ast: Ast) -> Self {
        Self::new(ScriptKind::Dependencies(deps), ast)
    }

    fn iter_dependencies(&self) -> impl Iterator<Item = &ScriptPath> {
        if let ScriptKind::Dependencies(dependencies) = &self.kind {
            dependencies.iter()
        } else {
            panic!("iter_dependencies() called on non-dependencies variant")
        }
    }

    fn is_runnable(&self) -> bool {
        matches!(self.kind, ScriptKind::Runnable)
    }

    fn is_not_runnable(&self) -> bool {
        matches!(self.kind, ScriptKind::NotRunnable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScriptPath(String);

impl ScriptPath {
    fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

struct ScriptReader<'a> {
    feed_path: PathBuf,
    loader: Loader,
    builtins: &'a BuiltinFunctions,
}

impl<'a> ScriptReader<'a> {
    fn new(feed_path: PathBuf, builtins: &'a BuiltinFunctions) -> Self {
        let loader = Loader::from_feed_path(&feed_path);
        Self {
            feed_path,
            loader,
            builtins,
        }
    }

    fn read_scripts(&mut self) -> Scripts {
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

struct RunnableScripts(Scripts);

impl RunnableScripts {
    fn new(unresolved: Scripts) -> Self {
        let resolved = Self::resolve(unresolved);
        Self(
            resolved
                .into_iter()
                .filter(|(_, script)| script.is_runnable())
                .collect(),
        )
    }

    fn resolve(mut unresolved: Scripts) -> Scripts {
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

    fn iter(&self) -> impl Iterator<Item = (&ScriptPath, &Script)> {
        self.0.iter()
    }
}

fn copy_feed(
    runnable: &RunnableScripts,
    feed_path: &Path,
    output_path: &Path,
) -> Result<(), io::Error> {
    fs::create_dir_all(output_path)?;
    for (path, _) in runnable.iter() {
        let src = feed_path.join(&path.0);
        let dst = output_path.join(&path.0);
        fs::create_dir_all(dst.parent().unwrap())?;
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

fn print_scripts(runnable: &RunnableScripts) {
    for (path, _) in runnable.iter() {
        println!("{path:?}");
    }
}

fn write_scan_config(
    runnable: &RunnableScripts,
    feed_path: &Path,
    scan_config: &PathBuf,
) -> Result<(), io::Error> {
    let scan = get_scan_config(feed_path, runnable);
    fs::write(scan_config, serde_json::to_string(&scan).unwrap())
}

fn get_scan_config(_feed_path: &Path, runnable: &RunnableScripts) -> Scan {
    let vts: Vec<_> = runnable
        .iter()
        .filter_map(|(_, script)| {
            script.oid.as_ref().map(|oid| VT {
                oid: oid.clone(),
                parameters: vec![],
            })
        })
        .collect();
    Scan {
        vts,
        ..Default::default()
    }
}

fn run(args: FilterArgs) -> Result<(), CliError> {
    let builtins = BuiltinFunctions::new(args.doc_path.clone());
    let mut reader = ScriptReader::new(args.feed_path.to_owned(), &builtins);
    let scripts = reader.read_scripts();
    let builtin_stats = BuiltinStats::new(&scripts, &builtins);
    let runnable = RunnableScripts::new(scripts);
    if let Some(ref output_path) = args.feed_out {
        copy_feed(&runnable, &args.feed_path, output_path)?;
    }
    if args.list {
        print_scripts(&runnable);
    }
    if let Some(ref scan_config) = args.scan_config {
        write_scan_config(&runnable, &args.feed_path, scan_config)?;
    }
    if let Some(ref stat_out) = args.stat_out {
        fs::write(stat_out, format!("{}", builtin_stats))?;
    }
    Ok(())
}

fn main() -> Result<(), CliError> {
    let cli = FilterArgs::parse();
    run(cli)
}

#[cfg(test)]
mod tests {
    use scannerlib::nasl::syntax::grammar::Ast;

    use super::{RunnableScripts, ScriptPath};

    use super::{Script, Scripts};

    fn path(path_str: &str) -> ScriptPath {
        ScriptPath(path_str.to_string())
    }

    fn dependencies(paths: &[&str]) -> Script {
        Script::dependencies(paths.iter().map(|p| path(p)).collect(), Ast::new(vec![]))
    }

    fn runnable() -> Script {
        Script::runnable(Ast::new(vec![]))
    }

    fn not_runnable() -> Script {
        Script::not_runnable(Ast::new(vec![]))
    }

    fn make_scripts(scripts: &[(&str, Script)]) -> Scripts {
        scripts
            .iter()
            .map(|(name, script)| (ScriptPath(name.to_string()), script.clone()))
            .collect()
    }

    #[test]
    fn resolution() {
        let scripts = [
            ("a", runnable()),
            ("b", runnable()),
            ("c", not_runnable()),
            ("d", dependencies(&["a", "b", "c"])),
        ];
        let resolved = RunnableScripts::resolve(make_scripts(&scripts));
        assert!(resolved[&path("a")].is_runnable());
        assert!(resolved[&path("b")].is_runnable());
        assert!(resolved[&path("c")].is_not_runnable());
        assert!(resolved[&path("d")].is_not_runnable());
    }

    #[test]
    fn transitive_resolution() {
        let scripts = [
            ("a1", runnable()),
            (
                "b1",
                Script::dependencies(vec![path("a1")], Ast::new(vec![])),
            ),
            (
                "c1",
                Script::dependencies(vec![path("b1")], Ast::new(vec![])),
            ),
            (
                "d1",
                Script::dependencies(vec![path("c1")], Ast::new(vec![])),
            ),
            ("a2", not_runnable()),
            (
                "b2",
                Script::dependencies(vec![path("a2")], Ast::new(vec![])),
            ),
            (
                "c2",
                Script::dependencies(vec![path("b2")], Ast::new(vec![])),
            ),
            (
                "d2",
                Script::dependencies(vec![path("c2")], Ast::new(vec![])),
            ),
        ];
        let resolved = RunnableScripts::resolve(make_scripts(&scripts));
        assert!(resolved[&path("a1")].is_runnable());
        assert!(resolved[&path("b1")].is_runnable());
        assert!(resolved[&path("c1")].is_runnable());
        assert!(resolved[&path("d1")].is_runnable());
        assert!(resolved[&path("a2")].is_not_runnable());
        assert!(resolved[&path("b2")].is_not_runnable());
        assert!(resolved[&path("c2")].is_not_runnable());
        assert!(resolved[&path("d2")].is_not_runnable());
    }
}
