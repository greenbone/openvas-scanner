// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

mod builtins;
mod dep_filter;
mod error;
mod output;
mod script;
mod stats;
mod utils;

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use crate::builtins::BuiltinFunctions;
use crate::dep_filter::{DepReader, resolve_script};
use crate::error::CliError;
use crate::output::{
    copy_dep_feed, copy_feed, print_dep_scripts, print_scripts, write_dep_dot,
    write_dep_scan_config, write_scan_config,
};
use crate::script::{RunnableScripts, ScriptReader};
use crate::stats::BuiltinStats;

#[derive(Parser)]
#[command(
    name = "feed-filter",
    about = "Utilities for filtering and analysing NASL feed scripts.",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Filter feed based on built-in function coverage.
    Builtin(BuiltinArgs),
    /// Filter feed based on given root scripts and their dependencies.
    Dep(DepArgs),
}

#[derive(clap::Args)]
struct BuiltinArgs {
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
    /// List all runnable scripts to stdout.
    #[clap(short, long)]
    list: bool,
    /// If present, a template scan json containing the OIDs of all
    /// runnable scripts will be written to this path.
    #[clap(short, long)]
    scan_config: Option<PathBuf>,
}

fn run_builtin_filter(args: BuiltinArgs) -> Result<(), CliError> {
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

#[derive(clap::Args)]
struct DepArgs {
    /// Path to the feed directory.
    feed_path: PathBuf,
    /// One or more .nasl scripts (paths relative to the feed root) to use as
    /// the starting points. All transitive dependencies are included.
    #[clap(required = true)]
    scripts: Vec<PathBuf>,
    /// Copy the filtered feed (root scripts + all dependencies) to this directory.
    #[clap(long)]
    feed_out: Option<PathBuf>,
    /// List all collected scripts to stdout.
    #[clap(short, long)]
    list: bool,
    /// Write a scan-config JSON with the OIDs of all collected scripts to this path.
    #[clap(short, long)]
    scan_config: Option<PathBuf>,
    /// Write a Graphviz DOT dependency graph to this path.
    /// Include edges are drawn as dashed gray arrows; script_dependencies edges as solid black arrows.
    #[clap(long)]
    dot_graph: Option<PathBuf>,
}

fn run_dep_filter(args: DepArgs) -> Result<(), CliError> {
    // Resolve root scripts before touching the feed.
    let roots: Vec<_> = args
        .scripts
        .iter()
        .filter_map(|s| {
            let resolved = resolve_script(&args.feed_path, s);
            if resolved.is_none() {
                eprintln!("Warning: script not found in feed: {}", s.display());
            }
            resolved
        })
        .collect();

    if roots.is_empty() {
        return Err(CliError::from("No valid root scripts found in the feed."));
    }

    let mut reader = DepReader::new(args.feed_path.clone());
    // Read only the reachable scripts, not the entire feed.
    let dep_map = reader.read_from_roots(&roots);

    // The dep_map already contains exactly the reachable set.
    let collected: std::collections::HashSet<_> = dep_map.keys().cloned().collect();

    if let Some(ref output_path) = args.feed_out {
        copy_dep_feed(&collected, &args.feed_path, output_path)?;
    }
    if args.list {
        print_dep_scripts(&collected);
    }
    if let Some(ref scan_config) = args.scan_config {
        write_dep_scan_config(&collected, &dep_map, scan_config)?;
    }
    if let Some(ref dot_path) = args.dot_graph {
        write_dep_dot(&dep_map, dot_path)?;
    }
    Ok(())
}

fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Builtin(args) => run_builtin_filter(args),
        Command::Dep(args) => run_dep_filter(args),
    }
}

#[cfg(test)]
mod tests {
    use scannerlib::nasl::syntax::grammar::Ast;

    use crate::script::{RunnableScripts, Script, ScriptPath, Scripts};

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
