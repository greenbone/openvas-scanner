mod all_builtins;

use all_builtins::ALL_BUILTINS;
use scannerlib::models::{Scan, VT};
use scannerlib::nasl::syntax::grammar::{Ast, Atom, Expr, FnCall, Statement};
use scannerlib::nasl::{Code, FSPluginLoader, nasl_std_functions};
use std::io::{self};
use std::path::PathBuf;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};
use walkdir::WalkDir;

use crate::CliError;

#[derive(clap::Parser)]
pub struct FilterArgs {
    /// Path to the feed that should be read and filtered.
    feed_path: PathBuf,
    /// Output path: If present, a copy of the feed containing only
    /// the runnable scripts will be copied to this directory. If
    /// the directory does not exist, it will be created.
    #[clap(short, long)]
    output_path: Option<PathBuf>,
    /// If present, a template scan json containing the OIDs of all
    /// runnable scripts will be written to this path.
    #[clap(short, long)]
    scan_config: Option<PathBuf>,
}

struct Builtins {
    builtins: Vec<String>,
    counts: HashMap<String, usize>,
}

impl Builtins {
    fn unimplemented() -> Self {
        let exec = nasl_std_functions();
        let implemented: Vec<_> = exec.iter().collect();
        let mut unimplemented: HashSet<_> = ALL_BUILTINS.iter().map(|x| x.to_string()).collect();
        for f in implemented {
            unimplemented.remove(f);
        }
        let counts = unimplemented.iter().map(|name| (name.clone(), 0)).collect();
        Self {
            builtins: unimplemented.into_iter().collect(),
            counts,
        }
    }

    fn script_is_runnable(&mut self, ast: &Ast) -> bool {
        let mut is_runnable = true;
        let fn_calls: Vec<&FnCall> = iter_fn_calls(ast).collect();
        for builtin in self.builtins.iter() {
            if fn_calls
                .iter()
                .any(|fn_call| fn_call.fn_name.to_string() == *builtin)
            {
                is_runnable = false;
                *self.counts.get_mut(builtin).unwrap() += 1;
            }
        }
        is_runnable
    }

    fn print_counts(&self) {
        let mut sorted: Vec<_> = self.counts.iter().collect();
        sorted.sort_by_key(|(_, count)| **count);
        for (builtin, count) in sorted.iter() {
            println!("{builtin} {count}");
        }
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
    let mut percentages: Vec<_> = (0..100).step_by(5).map(|x| x as f64).collect();
    x.into_iter().enumerate().map(move |(i, x)| {
        let completed_fraction = i as f64 / num as f64;
        let next_percentage = percentages.first().cloned().unwrap_or(100.0);
        if completed_fraction * 100.0 > next_percentage {
            percentages.remove(0);
            println!("{next_percentage}%.");
        }
        x
    })
}

type Scripts = HashMap<ScriptPath, Script>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScriptKind {
    Runnable,
    NotRunnable,
    Dependencies(Vec<ScriptPath>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Script {
    kind: ScriptKind,
    oid: Option<String>,
}

impl Script {
    fn new(kind: ScriptKind, oid: Option<String>) -> Self {
        Self { kind, oid }
    }

    fn runnable(oid: Option<String>) -> Self {
        Self::new(ScriptKind::Runnable, oid)
    }

    fn not_runnable(oid: Option<String>) -> Self {
        Self::new(ScriptKind::NotRunnable, oid)
    }

    fn dependencies(deps: Vec<ScriptPath>, oid: Option<String>) -> Self {
        Self::new(ScriptKind::Dependencies(deps), oid)
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
pub struct ScriptPath(String);

impl ScriptPath {
    fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

struct ScriptReader {
    builtins: Builtins,
    feed_path: PathBuf,
    loader: FSPluginLoader,
}

impl ScriptReader {
    fn read_scripts_from_path(feed_path: PathBuf) -> Scripts {
        let builtins = Builtins::unimplemented();
        let loader = FSPluginLoader::new(&feed_path);
        let mut reader = Self {
            builtins,
            feed_path,
            loader,
        };
        let scripts = reader.read_scripts();
        reader.builtins.print_counts();
        scripts
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
                } else {
                    // If a script cannot be read, we assume
                    // it's not runnable.
                    scripts.insert(script_path, Script::not_runnable(None));
                }
            }
        }
        scripts
    }

    fn script_from_path(&mut self, path: &Path) -> Option<Script> {
        let code = Code::load(&self.loader, path).unwrap();
        let ast = code.parse().emit_errors().unwrap();
        let script = self.script_from_ast(&ast);
        Some(script)
    }

    fn script_from_ast(&mut self, ast: &Ast) -> Script {
        let oid = self.oid_from_ast(&ast);
        let is_runnable = self.builtins.script_is_runnable(ast);
        let dependencies = self.get_dependencies(ast);
        if !is_runnable {
            Script::not_runnable(oid)
        } else if dependencies.is_empty() {
            Script::runnable(oid)
        } else {
            Script::dependencies(dependencies, oid)
        }
    }

    fn oid_from_ast(&self, ast: &Ast) -> Option<String> {
        iter_fn_calls(ast)
            .find(|call| call.fn_name.to_string() == "script_oid")
            .map(|call| call.args.items.first().unwrap().to_string())
    }

    fn get_dependencies(&self, ast: &Ast) -> Vec<ScriptPath> {
        ast.iter_stmts()
            .filter_map(|stmt| {
                if let Statement::Include(include) = stmt {
                    Some(ScriptPath(include.path.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
}

pub struct RunnableScripts(Scripts);

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
                            "Reference to non-existent file: {}",
                            k.0
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

pub fn run(args: FilterArgs) -> Result<(), CliError> {
    let scripts = ScriptReader::read_scripts_from_path(args.feed_path.to_owned());
    let runnable = RunnableScripts::new(scripts);
    if let Some(ref output_path) = args.output_path {
        copy_feed(&runnable, &args.feed_path, output_path)?;
    } else {
        print_scripts(&runnable);
    }
    if let Some(ref scan_config) = args.scan_config {
        write_scan_config(&runnable, &args.feed_path, scan_config)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::feed::filter::{RunnableScripts, ScriptPath};

    use super::{Script, Scripts};

    fn path(path_str: &str) -> ScriptPath {
        ScriptPath(path_str.to_string())
    }

    fn dependencies(paths: &[&str]) -> Script {
        Script::dependencies(paths.into_iter().map(|p| path(p)).collect(), None)
    }

    fn runnable() -> Script {
        Script::runnable(None)
    }

    fn not_runnable() -> Script {
        Script::not_runnable(None)
    }

    fn make_scripts(scripts: &[(&str, Script)]) -> Scripts {
        scripts
            .into_iter()
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
            ("b1", Script::dependencies(vec![path("a1")], None)),
            ("c1", Script::dependencies(vec![path("b1")], None)),
            ("d1", Script::dependencies(vec![path("c1")], None)),
            ("a2", not_runnable()),
            ("b2", Script::dependencies(vec![path("a2")], None)),
            ("c2", Script::dependencies(vec![path("b2")], None)),
            ("d2", Script::dependencies(vec![path("c2")], None)),
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
